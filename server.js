// server.js - API Backend (Con Paywall y Auditoría Forense)
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;
const SECRET_KEY = 'super_clave_secreta_financiera_2026'; 

// Ciberseguridad: trust proxy permite leer la IP real del usuario en nubes como Render
app.set('trust proxy', true);
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const pool = new Pool({
    connectionString: 'postgresql://neondb_owner:npg_ISxCvM4w6jko@ep-still-river-an6gel8k-pooler.c-6.us-east-1.aws.neon.tech/neondb?sslmode=require',
    ssl: { rejectUnauthorized: false }
});

const enviarCorreo = (destino, asunto, mensaje) => { console.log(`\n📧 [EMAIL A: ${destino}]\nAsunto: ${asunto}\nMensaje: ${mensaje}\n`); };

// --- MOTOR DE AUDITORÍA FORENSE (NUEVO) ---
const registrarAuditoria = async (usuario_id, negocio_id, accion, ip) => {
    try {
        await pool.query(
            'INSERT INTO logs_auditoria (usuario_id, negocio_id, accion, ip_origen) VALUES ($1, $2, $3, $4)',
            [usuario_id, negocio_id, accion, ip]
        );
    } catch (error) { console.error("Error guardando log forense:", error.message); }
};

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

// --- AUTH Y PAYWALL (NUEVO) ---
app.post('/api/register', async (req, res) => {
    const { email, password, nombre, apellido, pais, telefono } = req.body;
    try {
        const hash = await bcrypt.hash(password, 10);
        const result = await pool.query('INSERT INTO usuarios (email, password_hash, nombre, apellido, pais, telefono) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, nombre', [email, hash, nombre, apellido, pais, telefono]);
        enviarCorreo(email, "¡Bienvenido a Tesorería SaaS!", `Hola ${nombre}, disfruta tus 15 días de prueba gratuita.`);
        res.status(201).json(result.rows[0]);
    } catch (error) { res.status(400).json({ error: 'El email ya está registrado' }); }
});

app.post('/api/login', async (req, res) => {
    try {
        // Obtenemos los datos del usuario, incluyendo su fecha de creación y si pagó (es_premium)
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [req.body.email]);
        if (result.rows.length === 0 || !(await bcrypt.compare(req.body.password, result.rows[0].password_hash))) return res.status(400).json({ error: 'Credenciales inválidas' });
        
        const user = result.rows[0];
        
        // Cálculo del Trial de 15 días
        const fechaCreacion = new Date(user.fecha_creacion);
        const hoy = new Date();
        const diasPasados = Math.floor((hoy - fechaCreacion) / (1000 * 60 * 60 * 24));
        const diasRestantes = 15 - diasPasados;

        const payload = { 
            id: user.id, 
            email: user.email, 
            nombre: user.nombre,
            es_premium: user.es_premium,
            dias_restantes: diasRestantes
        };
        
        res.json({ token: jwt.sign(payload, SECRET_KEY, { expiresIn: '8h' }), usuario: payload });
    } catch (error) { res.status(500).json({ error: 'Error en servidor' }); }
});

// --- AUDITORÍA Y ADMIN ---
app.get('/api/auditoria/:negocio_id', verificarToken, async (req, res) => {
    try {
        // Solo el dueño del negocio puede ver la auditoría
        const check = await pool.query('SELECT id FROM negocios WHERE id = $1 AND usuario_id = $2', [req.params.negocio_id, req.usuario_id]);
        if (check.rows.length === 0) return res.status(403).json({ error: 'Acceso denegado a los logs.' });

        const logs = await pool.query(
            `SELECT l.*, u.nombre, u.email FROM logs_auditoria l 
             JOIN usuarios u ON l.usuario_id = u.id 
             WHERE l.negocio_id = $1 ORDER BY l.fecha DESC LIMIT 50`, 
            [req.params.negocio_id]
        );
        res.json(logs.rows);
    } catch (error) { res.status(500).json({ error: 'Error obteniendo auditoría' }); }
});

// SIMULADOR DE PAGO (MercadoPago / Stripe)
app.post('/api/checkout', verificarToken, async (req, res) => {
    try {
        // Aquí iría la conexión real a la API de MercadoPago. Por ahora simulamos el pago exitoso.
        await pool.query('UPDATE usuarios SET es_premium = TRUE WHERE id = $1', [req.usuario_id]);
        res.json({ mensaje: '¡Pago procesado exitosamente! Tu cuenta ahora es Premium.' });
    } catch (error) { res.status(500).json({ error: 'Error en la pasarela de pagos.' }); }
});

// --- RUTAS RESTANTES (Mantenidas con inyección de Auditoría) ---
app.post('/api/colaboradores', verificarToken, async (req, res) => {
    const { negocio_id, email_invitado } = req.body;
    try {
        const check = await pool.query('SELECT id FROM negocios WHERE id = $1 AND usuario_id = $2', [negocio_id, req.usuario_id]);
        if (check.rows.length === 0) return res.status(403).json({ error: 'Solo el dueño puede invitar colaboradores.' });
        await pool.query('INSERT INTO colaboradores (negocio_id, email_colaborador) VALUES ($1, $2)', [negocio_id, email_invitado]);
        
        registrarAuditoria(req.usuario_id, negocio_id, `Invitó al usuario ${email_invitado} como socio.`, req.ip);
        res.json({ mensaje: 'Invitación enviada con éxito.' });
    } catch (error) { res.status(500).json({ error: 'El usuario ya tiene acceso o hubo un error.' }); }
});

app.post('/api/negocios', verificarToken, async (req, res) => {
    const result = await pool.query('INSERT INTO negocios (usuario_id, nombre) VALUES ($1, $2) RETURNING *', [req.usuario_id, req.body.nombre]);
    res.json(result.rows[0]);
});

app.get('/api/negocios', verificarToken, async (req, res) => {
    const result = await pool.query(`SELECT * FROM negocios WHERE usuario_id = $1 OR id IN (SELECT negocio_id FROM colaboradores WHERE email_colaborador = $2) ORDER BY id ASC`, [req.usuario_id, req.usuario_email]);
    res.json(result.rows);
});

app.post('/api/movimientos', verificarToken, async (req, res) => {
    const { negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, esCapital } = req.body;
    try {
        const result = await pool.query(
            `INSERT INTO movimientos_tesoreria (usuario_id, negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, es_capital) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
            [req.usuario_id, negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, esCapital]
        );
        registrarAuditoria(req.usuario_id, negocio_id, `Registró un ${tipo} de $${monto} en la categoría ${categoria_contable}. Concepto: ${concepto}`, req.ip);
        res.status(201).json(result.rows[0]);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/movimientos', verificarToken, async (req, res) => {
    const result = await pool.query(
        `SELECT m.*, n.nombre as empresa_nombre FROM movimientos_tesoreria m 
         JOIN negocios n ON m.negocio_id = n.id 
         WHERE n.usuario_id = $1 OR n.id IN (SELECT negocio_id FROM colaboradores WHERE email_colaborador = $2) 
         ORDER BY m.fecha_registro DESC`, [req.usuario_id, req.usuario_email]
    );
    res.json(result.rows);
});

app.delete('/api/movimientos/:id', verificarToken, async (req, res) => {
    try {
        // Buscamos los datos antes de borrar para el log
        const mov = await pool.query('SELECT negocio_id, monto FROM movimientos_tesoreria WHERE id = $1 AND usuario_id = $2', [req.params.id, req.usuario_id]);
        if (mov.rows.length > 0) {
            await pool.query('DELETE FROM movimientos_tesoreria WHERE id = $1', [req.params.id]);
            registrarAuditoria(req.usuario_id, mov.rows[0].negocio_id, `Eliminó permanentemente un asiento de $${mov.rows[0].monto}.`, req.ip);
        }
        res.json({ mensaje: 'Eliminado' });
    } catch (error) { res.status(500).json({ error: 'Error al eliminar' }); }
});

app.put('/api/movimientos/:id', verificarToken, async (req, res) => {
    const { negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, esCapital } = req.body;
    const result = await pool.query(
        `UPDATE movimientos_tesoreria SET negocio_id=$1, concepto=$2, categoria_contable=$3, cantidad_unidades=$4, tipo=$5, monto=$6, es_capital=$7 WHERE id=$8 AND usuario_id=$9 RETURNING *`,
        [negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, esCapital, req.params.id, req.usuario_id]
    );
    registrarAuditoria(req.usuario_id, negocio_id, `Modificó un asiento. Nuevo monto: $${monto}. Nuevo concepto: ${concepto}`, req.ip);
    res.json(result.rows[0]);
});

app.listen(port, () => { console.log(`🔒 Servidor en puerto ${port} con Motor Forense Activo`); });