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
// ==========================================
// WEBHOOK OMNICANAL INTELIGENTE (Lectura Natural)
// ==========================================
app.post('/api/whatsapp', async (req, res) => {
    res.type('text/xml');
    const mensajeOriginal = req.body.Body.trim();
    const mensaje = mensajeOriginal.toLowerCase(); // Pasamos todo a minúsculas para analizarlo fácil
    const remitente = req.body.From.replace('whatsapp:', '').trim();

    try {
        // 1. Validar Ciberseguridad
        const userRes = await pool.query('SELECT id, nombre FROM usuarios WHERE telefono = $1', [remitente]);
        if (userRes.rows.length === 0) return res.send('<Response><Message>❌ Tu número no está autorizado en el SaaS.</Message></Response>');
        const usuario = userRes.rows[0];

        // 2. Extraer el Monto (Busca automáticamente cualquier número en el texto)
        const montoMatch = mensaje.match(/\d+(?:\.\d+)?/);
        if (!montoMatch) return res.send('<Response><Message>❌ No detecté ningún monto. Por favor, incluye un número (ej: 5000).</Message></Response>');
        const monto = parseFloat(montoMatch[0]);

        // 3. Identificar la Marca (Unidad de Negocio)
        const negociosRes = await pool.query('SELECT id, nombre FROM negocios WHERE usuario_id = $1', [usuario.id]);
        const misNegocios = negociosRes.rows;
        if (misNegocios.length === 0) return res.send('<Response><Message>❌ No tienes ningún negocio creado en la plataforma.</Message></Response>');

        let negocio_id = null;
        let marcaNombre = "";
        
        if (misNegocios.length === 1) {
            // Si solo tiene una marca, se la asigna automáticamente (no hace falta nombrarla)
            negocio_id = misNegocios[0].id;
            marcaNombre = misNegocios[0].nombre;
        } else {
            // Si tiene varias, busca la primera palabra del negocio en el mensaje (ej: busca "exquisito" para "Exquisito Lunchtime")
            for (let n of misNegocios) {
                const palabraClave = n.nombre.toLowerCase().split(' ')[0];
                if (mensaje.includes(palabraClave)) {
                    negocio_id = n.id;
                    marcaNombre = n.nombre;
                    break;
                }
            }
            if (!negocio_id) return res.send('<Response><Message>❌ Tienes varias marcas. Por favor nombra para cuál es este movimiento (ej: "Naturae" o "Exquisito").</Message></Response>');
        }

        // 4. Diccionario de Sinónimos para Categorías
        const diccionario = [
            { id: 'Ventas', palabras: ['venta', 'ventas', 'cobré', 'ingreso', 'cliente'] },
            { id: 'Insumos', palabras: ['insumo', 'insumos', 'compra', 'mercaderia', 'proveedor', 'frascos', 'materia prima'] },
            { id: 'Sueldos', palabras: ['sueldo', 'sueldos', 'honorario', 'pagué a', 'adelanto'] },
            { id: 'Marketing', palabras: ['marketing', 'publicidad', 'ads', 'meta', 'instagram'] },
            { id: 'Combustible y peaje', palabras: ['nafta', 'combustible', 'peaje', 'gasolina', 'ypf', 'shell', 'axion'] },
            { id: 'Luz', palabras: ['luz', 'edenor', 'edesur'] },
            { id: 'Gas', palabras: ['gas', 'metrogas'] },
            { id: 'Limpieza', palabras: ['limpieza', 'articulos de limpieza'] }
        ];

        let categoriaElegida = 'Otros gastos'; // Si no entiende de qué hablas, va a "Otros gastos"
        for (let cat of diccionario) {
            if (cat.palabras.some(p => mensaje.includes(p))) {
                categoriaElegida = cat.id;
                break;
            }
        }

        // 5. Motor de Deducción (Ingreso/Egreso)
        let tipoDeducido = 'egreso';
        let esCap = false;
        if (categoriaElegida === 'Ventas') tipoDeducido = 'ingreso';

        // 6. El detalle del registro será literalmente la frase entera que mandaste
        const concepto = mensajeOriginal;

        // 7. Inyectar a PostgreSQL
        await pool.query(
            `INSERT INTO movimientos_tesoreria (usuario_id, negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, es_capital)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [usuario.id, negocio_id, concepto, categoriaElegida, 0, tipoDeducido, monto, esCap]
        );

        // 8. Respuesta amigable por WhatsApp
        res.send(`<Response><Message>✅ ¡Registrado con éxito!\n💰 $${monto}\n🏢 ${marcaNombre}\n📂 Se clasificó como: ${categoriaElegida}</Message></Response>`);

    } catch (error) {
        console.error(error);
        res.send('<Response><Message>❌ Uy, hubo un problema técnico en el servidor guardando el dato.</Message></Response>');
    }
});
app.listen(port, () => { console.log(`🔒 Servidor en puerto ${port}`); });