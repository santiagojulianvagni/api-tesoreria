// server.js - API Backend Completa (SaaS Tesorería)
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto'); 

const app = express();
const port = process.env.PORT || 3000;
const SECRET_KEY = 'super_clave_secreta_financiera_2026'; 

app.use(express.urlencoded({ extended: true })); // <-- NUEVO: Para entender a Twilio
app.use(cors());
app.use(express.json());

const pool = new Pool({
    connectionString: 'postgresql://neondb_owner:npg_ISxCvM4w6jko@ep-still-river-an6gel8k-pooler.c-6.us-east-1.aws.neon.tech/neondb?sslmode=require',
    ssl: { rejectUnauthorized: false }
});

// Simulador de Emails
const enviarCorreo = (destino, asunto, mensaje) => {
    console.log(`\n📧 [NUEVO EMAIL A: ${destino}]\nAsunto: ${asunto}\nMensaje: ${mensaje}\n`);
};

const verificarToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: 'Acceso denegado.' });
    try {
        req.usuario_id = jwt.verify(token.split(' ')[1], SECRET_KEY).id; next(); 
    } catch (error) { res.status(401).json({ error: 'Token inválido.' }); }
};

// --- RUTAS AUTH Y PERFIL ---
app.post('/api/register', async (req, res) => {
    const { email, password, nombre, apellido, pais, telefono } = req.body;
    try {
        const hash = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO usuarios (email, password_hash, nombre, apellido, pais, telefono) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, nombre', 
            [email, hash, nombre, apellido, pais, telefono]
        );
        enviarCorreo(email, "¡Bienvenido a Tesorería SaaS!", `Hola ${nombre}, tu cuenta ha sido creada con éxito.`);
        res.status(201).json(result.rows[0]);
    } catch (error) { res.status(400).json({ error: 'El email ya está registrado' }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [req.body.email]);
        if (result.rows.length === 0 || !(await bcrypt.compare(req.body.password, result.rows[0].password_hash))) 
            return res.status(400).json({ error: 'Credenciales inválidas' });
        
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
            enviarCorreo(email, "Recuperación de Contraseña", `Hola ${result.rows[0].nombre},\nUsa este código de seguridad para tu nueva clave: ${resetToken}`);
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
    try {
        await pool.query('DELETE FROM usuarios WHERE id = $1', [req.usuario_id]);
        res.json({ mensaje: 'Cuenta eliminada' });
    } catch (error) { res.status(500).json({ error: 'Error al eliminar' }); }
});

// --- RUTA ADMIN ---
app.get('/api/admin/stats', verificarToken, async (req, res) => {
    if (req.usuario_id !== 1) return res.status(403).json({ error: 'Solo fundador.' });
    try {
        const users = await pool.query('SELECT COUNT(*) FROM usuarios');
        const negocios = await pool.query('SELECT COUNT(*) FROM negocios');
        const movs = await pool.query('SELECT COUNT(*) FROM movimientos_tesoreria');
        res.json({ total_usuarios: users.rows[0].count, total_negocios: negocios.rows[0].count, total_movimientos: movs.rows[0].count });
    } catch (error) { res.status(500).json({ error: 'Error métricas' }); }
});

// --- RUTAS NEGOCIOS ---
app.post('/api/negocios', verificarToken, async (req, res) => {
    const result = await pool.query('INSERT INTO negocios (usuario_id, nombre) VALUES ($1, $2) RETURNING *', [req.usuario_id, req.body.nombre]);
    res.json(result.rows[0]);
});
app.get('/api/negocios', verificarToken, async (req, res) => {
    const result = await pool.query('SELECT * FROM negocios WHERE usuario_id = $1 ORDER BY id ASC', [req.usuario_id]);
    res.json(result.rows);
});
app.delete('/api/negocios/:id', verificarToken, async (req, res) => {
    const result = await pool.query('DELETE FROM negocios WHERE id = $1 AND usuario_id = $2 RETURNING *', [req.params.id, req.usuario_id]);
    if(result.rowCount === 0) return res.status(404).json({error: 'No encontrado'});
    res.json({ mensaje: 'Eliminado' });
});

// --- RUTAS MOVIMIENTOS ---
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
    const result = await pool.query(`SELECT m.*, n.nombre as empresa_nombre FROM movimientos_tesoreria m JOIN negocios n ON m.negocio_id = n.id WHERE m.usuario_id = $1 ORDER BY m.fecha_registro DESC`, [req.usuario_id]);
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

// ==========================================
// NUEVO: WEBHOOK OMNICANAL PARA WHATSAPP
// ==========================================
app.post('/api/whatsapp', async (req, res) => {
    res.type('text/xml'); // Twilio exige que le respondamos en formato XML
    
    const mensaje = req.body.Body; // Lo que escribiste en el chat
    const remitente = req.body.From; // Tu número (ej: whatsapp:+549112345678)

    try {
        // 1. Limpiar el número (quitarle la palabra 'whatsapp:')
        const telefonoLimpiado = remitente.replace('whatsapp:', '').trim();

        // 2. Seguridad: Buscar al usuario en la BD usando ese teléfono
        const userRes = await pool.query('SELECT id, nombre FROM usuarios WHERE telefono = $1', [telefonoLimpiado]);
        if (userRes.rows.length === 0) {
            return res.send('<Response><Message>❌ Ciberseguridad: Este número de teléfono no está autorizado en el SaaS.</Message></Response>');
        }
        const usuario = userRes.rows[0];

        // 3. Entender el mensaje. Formato esperado: Monto, Categoria, Marca, Detalle
        // Ej: 15000, Insumos, Naturae, Compra de frascos
        const partes = mensaje.split(',');
        if (partes.length < 3) {
             return res.send('<Response><Message>⚠️ Formato incorrecto.\nUsa comas así: Monto, Categoria, Marca, Detalle (Opcional)\nEj: 15000, Ventas, Naturae, Cliente local</Message></Response>');
        }

        const monto = parseFloat(partes[0].trim());
        const categoriaElegida = partes[1].trim();
        const marcaNombre = partes[2].trim();
        const concepto = partes[3] ? partes[3].trim() : 'Carga rápida por WhatsApp';

        // 4. Buscar la marca (Negocio) en la base de datos
        // Usamos ILIKE para que no importe si escribes "naturae" o "Naturae"
        const negocioRes = await pool.query('SELECT id FROM negocios WHERE usuario_id = $1 AND nombre ILIKE $2', [usuario.id, `%${marcaNombre}%`]);
        if (negocioRes.rows.length === 0) {
            return res.send(`<Response><Message>❌ No encontré la marca "${marcaNombre}". Revisa cómo está escrita.</Message></Response>`);
        }
        const negocio_id = negocioRes.rows[0].id;

        // 5. Motor de Deducción (Igual que en la Web)
        let tipoDeducido = 'egreso';
        let esCap = false;
        if (categoriaElegida.toLowerCase() === 'ventas') tipoDeducido = 'ingreso';
        else if (categoriaElegida.toLowerCase() === 'aporte de capital') { tipoDeducido = 'ingreso'; esCap = true; }
        else if (categoriaElegida.toLowerCase() === 'retiro de socio') { tipoDeducido = 'egreso'; esCap = true; }

        // 6. Inyectar en la Bóveda de Neon
        await pool.query(
            `INSERT INTO movimientos_tesoreria (usuario_id, negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, es_capital)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [usuario.id, negocio_id, concepto, categoriaElegida, 0, tipoDeducido, monto, esCap]
        );

        // 7. Responder al chat de WhatsApp con el éxito
        res.send(`<Response><Message>✅ ¡Listo, ${usuario.nombre}!\nSe registró un ${tipoDeducido} de $${monto} en la caja de ${marcaNombre}.</Message></Response>`);

    } catch (error) {
        console.error("Error en WhatsApp Bot:", error);
        res.send('<Response><Message>❌ Error interno en los servidores de Render al procesar el mensaje.</Message></Response>');
    }
});
app.listen(port, () => { console.log(`🔒 Servidor en puerto ${port}`); });