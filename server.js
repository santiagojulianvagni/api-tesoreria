// server.js - API Backend (Con Roles Multiusuario)
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;
const SECRET_KEY = 'super_clave_secreta_financiera_2026'; 

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const pool = new Pool({
    connectionString: 'postgresql://neondb_owner:npg_ISxCvM4w6jko@ep-still-river-an6gel8k-pooler.c-6.us-east-1.aws.neon.tech/neondb?sslmode=require',
    ssl: { rejectUnauthorized: false }
});

const enviarCorreo = (destino, asunto, mensaje) => { console.log(`\n📧 [EMAIL A: ${destino}]\nAsunto: ${asunto}\nMensaje: ${mensaje}\n`); };

// NUEVO: Ahora el token extrae también el EMAIL para saber a qué negocios estás invitado
const verificarToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: 'Acceso denegado.' });
    try {
        const decoded = jwt.verify(token.split(' ')[1], SECRET_KEY);
        req.usuario_id = decoded.id; 
        req.usuario_email = decoded.email; 
        next(); 
    } catch (error) { res.status(401).json({ error: 'Token inválido.' }); }
};

// --- AUTH, RECUPERACIÓN Y ADMIN ---
// (Estas rutas quedan intactas para mantener tu registro y panel fundador)
app.post('/api/register', async (req, res) => {
    const { email, password, nombre, apellido, pais, telefono } = req.body;
    try {
        const hash = await bcrypt.hash(password, 10);
        const result = await pool.query('INSERT INTO usuarios (email, password_hash, nombre, apellido, pais, telefono) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, nombre', [email, hash, nombre, apellido, pais, telefono]);
        enviarCorreo(email, "¡Bienvenido a Tesorería SaaS!", `Hola ${nombre}, tu cuenta ha sido creada con éxito.`);
        res.status(201).json(result.rows[0]);
    } catch (error) { res.status(400).json({ error: 'El email ya está registrado' }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [req.body.email]);
        if (result.rows.length === 0 || !(await bcrypt.compare(req.body.password, result.rows[0].password_hash))) return res.status(400).json({ error: 'Credenciales inválidas' });
        const payload = { id: result.rows[0].id, email: result.rows[0].email, nombre: result.rows[0].nombre };
        res.json({ token: jwt.sign(payload, SECRET_KEY, { expiresIn: '8h' }), usuario: payload });
    } catch (error) { res.status(500).json({ error: 'Error en servidor' }); }
});

app.post('/api/recuperar', async (req, res) => {
    const { email } = req.body;
    try {
        const result = await pool.query('SELECT id, nombre FROM usuarios WHERE email = $1', [email]);
        if (result.rows.length > 0) {
            const resetToken = crypto.randomBytes(32).toString('hex');
            await pool.query("UPDATE usuarios SET reset_token = $1, reset_expires = NOW() + INTERVAL '1 hour' WHERE email = $2", [resetToken, email]);
            enviarCorreo(email, "Recuperación de Contraseña", `Hola ${result.rows[0].nombre},\nUsa este código: ${resetToken}`);
        }
        res.json({ mensaje: 'Si el correo existe, enviamos las instrucciones.' });
    } catch (error) { res.status(500).json({ error: 'Error procesando solicitud' }); }
});

app.put('/api/usuarios/password', verificarToken, async (req, res) => {
    const { passwordActual, passwordNueva } = req.body;
    try {
        const result = await pool.query('SELECT password_hash FROM usuarios WHERE id = $1', [req.usuario_id]);
        if (!(await bcrypt.compare(passwordActual, result.rows[0].password_hash))) return res.status(400).json({ error: 'Contraseña actual incorrecta' });
        const nuevoHash = await bcrypt.hash(passwordNueva, 10);
        await pool.query('UPDATE usuarios SET password_hash = $1 WHERE id = $2', [nuevoHash, req.usuario_id]);
        res.json({ mensaje: 'Contraseña actualizada' });
    } catch (error) { res.status(500).json({ error: 'Error al cambiar' }); }
});

app.delete('/api/usuarios', verificarToken, async (req, res) => {
    try { await pool.query('DELETE FROM usuarios WHERE id = $1', [req.usuario_id]); res.json({ mensaje: 'Cuenta eliminada' }); } 
    catch (error) { res.status(500).json({ error: 'Error al eliminar' }); }
});

app.get('/api/admin/stats', verificarToken, async (req, res) => {
    if (req.usuario_id !== 1) return res.status(403).json({ error: 'Solo fundador.' });
    try {
        const users = await pool.query('SELECT COUNT(*) FROM usuarios');
        const negocios = await pool.query('SELECT COUNT(*) FROM negocios');
        const movs = await pool.query('SELECT COUNT(*) FROM movimientos_tesoreria');
        res.json({ total_usuarios: users.rows[0].count, total_negocios: negocios.rows[0].count, total_movimientos: movs.rows[0].count });
    } catch (error) { res.status(500).json({ error: 'Error métricas' }); }
});

// --- NUEVO: SISTEMA DE COLABORADORES ---
app.post('/api/colaboradores', verificarToken, async (req, res) => {
    const { negocio_id, email_invitado } = req.body;
    try {
        // Ciberseguridad: Solo el dueño real de la marca puede invitar gente
        const check = await pool.query('SELECT id FROM negocios WHERE id = $1 AND usuario_id = $2', [negocio_id, req.usuario_id]);
        if (check.rows.length === 0) return res.status(403).json({ error: 'Solo el dueño puede invitar colaboradores.' });

        await pool.query('INSERT INTO colaboradores (negocio_id, email_colaborador) VALUES ($1, $2)', [negocio_id, email_invitado]);
        
        // Simulamos envío de email al invitado
        enviarCorreo(email_invitado, "¡Te han invitado a colaborar!", `Hola, te han dado acceso a la tesorería de un negocio. Inicia sesión en la plataforma para verlo.`);
        res.json({ mensaje: 'Invitación enviada con éxito.' });
    } catch (error) { res.status(500).json({ error: 'El usuario ya tiene acceso o hubo un error.' }); }
});

// --- NEGOCIOS Y MOVIMIENTOS (Actualizados para leer colaboradores) ---
app.post('/api/negocios', verificarToken, async (req, res) => {
    const result = await pool.query('INSERT INTO negocios (usuario_id, nombre) VALUES ($1, $2) RETURNING *', [req.usuario_id, req.body.nombre]);
    res.json(result.rows[0]);
});

app.get('/api/negocios', verificarToken, async (req, res) => {
    // NUEVO: Trae las marcas tuyas OR las marcas a las que te invitaron
    const result = await pool.query(
        `SELECT * FROM negocios WHERE usuario_id = $1 OR id IN (SELECT negocio_id FROM colaboradores WHERE email_colaborador = $2) ORDER BY id ASC`, 
        [req.usuario_id, req.usuario_email]
    );
    res.json(result.rows);
});

app.delete('/api/negocios/:id', verificarToken, async (req, res) => {
    const result = await pool.query('DELETE FROM negocios WHERE id = $1 AND usuario_id = $2 RETURNING *', [req.params.id, req.usuario_id]);
    if(result.rowCount === 0) return res.status(404).json({error: 'No autorizado'});
    res.json({ mensaje: 'Eliminado' });
});

app.post('/api/movimientos', verificarToken, async (req, res) => {
    const { negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, esCapital } = req.body;
    try {
        const result = await pool.query(
            `INSERT INTO movimientos_tesoreria (usuario_id, negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, es_capital) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
            [req.usuario_id, negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, esCapital]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/movimientos', verificarToken, async (req, res) => {
    // NUEVO: Trae los tickets de tus marcas OR de las marcas a las que estás invitado
    const result = await pool.query(
        `SELECT m.*, n.nombre as empresa_nombre FROM movimientos_tesoreria m 
         JOIN negocios n ON m.negocio_id = n.id 
         WHERE n.usuario_id = $1 OR n.id IN (SELECT negocio_id FROM colaboradores WHERE email_colaborador = $2) 
         ORDER BY m.fecha_registro DESC`, 
         [req.usuario_id, req.usuario_email]
    );
    res.json(result.rows);
});

app.delete('/api/movimientos/:id', verificarToken, async (req, res) => {
    await pool.query('DELETE FROM movimientos_tesoreria WHERE id = $1 AND usuario_id = $2', [req.params.id, req.usuario_id]);
    res.json({ mensaje: 'Eliminado' });
});

app.put('/api/movimientos/:id', verificarToken, async (req, res) => {
    const { negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, esCapital } = req.body;
    const result = await pool.query(
        `UPDATE movimientos_tesoreria SET negocio_id=$1, concepto=$2, categoria_contable=$3, cantidad_unidades=$4, tipo=$5, monto=$6, es_capital=$7 WHERE id=$8 AND usuario_id=$9 RETURNING *`,
        [negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, esCapital, req.params.id, req.usuario_id]
    );
    res.json(result.rows[0]);
});

// --- EL BOT DE WHATSAPP ---
app.post('/api/whatsapp', async (req, res) => {
    res.type('text/xml');
    const mensajeOriginal = req.body.Body.trim();
    const mensaje = mensajeOriginal.toLowerCase(); 
    const remitente = req.body.From.replace('whatsapp:', '').trim();

    try {
        const userRes = await pool.query('SELECT id, nombre, email FROM usuarios WHERE telefono = $1', [remitente]);
        if (userRes.rows.length === 0) return res.send('<Response><Message>❌ Tu número no está autorizado.</Message></Response>');
        const usuario = userRes.rows[0];

        const montoMatch = mensaje.match(/\d+(?:\.\d+)?/);
        if (!montoMatch) return res.send('<Response><Message>❌ Falta el monto numérico.</Message></Response>');
        const monto = parseFloat(montoMatch[0]);

        // El bot ahora también sabe buscar en los negocios a los que fuiste invitado
        const negociosRes = await pool.query(
            'SELECT id, nombre FROM negocios WHERE usuario_id = $1 OR id IN (SELECT negocio_id FROM colaboradores WHERE email_colaborador = $2)', 
            [usuario.id, usuario.email]
        );
        const misNegocios = negociosRes.rows;
        if (misNegocios.length === 0) return res.send('<Response><Message>❌ No tienes negocios.</Message></Response>');

        let negocio_id = null; let marcaNombre = "";
        if (misNegocios.length === 1) { negocio_id = misNegocios[0].id; marcaNombre = misNegocios[0].nombre; } 
        else {
            for (let n of misNegocios) {
                if (mensaje.includes(n.nombre.toLowerCase().split(' ')[0])) { negocio_id = n.id; marcaNombre = n.nombre; break; }
            }
            if (!negocio_id) return res.send('<Response><Message>❌ Tienes varias marcas. Nombra para cuál es (ej: Naturae).</Message></Response>');
        }

        const diccionario = [
            { id: 'Ventas', palabras: ['venta', 'ventas', 'cobré', 'ingreso', 'cliente'] },
            { id: 'Insumos', palabras: ['insumo', 'insumos', 'compra', 'mercaderia', 'proveedor'] },
            { id: 'Sueldos', palabras: ['sueldo', 'sueldos', 'honorario', 'pagué'] },
            { id: 'Marketing', palabras: ['marketing', 'publicidad', 'ads'] }
        ];

        let categoriaElegida = 'Otros gastos'; 
        for (let cat of diccionario) { if (cat.palabras.some(p => mensaje.includes(p))) { categoriaElegida = cat.id; break; } }

        let tipoDeducido = 'egreso'; let esCap = false;
        if (categoriaElegida === 'Ventas') tipoDeducido = 'ingreso';

        await pool.query(
            `INSERT INTO movimientos_tesoreria (usuario_id, negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, es_capital) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [usuario.id, negocio_id, mensajeOriginal, categoriaElegida, 0, tipoDeducido, monto, esCap]
        );

        res.send(`<Response><Message>✅ Registrado en ${marcaNombre}: $${monto} (${categoriaElegida})</Message></Response>`);
    } catch (error) { res.send('<Response><Message>❌ Error en servidor.</Message></Response>'); }
});

app.listen(port, () => { console.log(`🔒 Servidor en puerto ${port}`); });