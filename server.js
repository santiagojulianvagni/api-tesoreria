// server.js - API Backend (Con Panel de Superadministrador)
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
const SECRET_KEY = 'super_clave_secreta_financiera_2026'; 

app.use(cors());
app.use(express.json());

const pool = new Pool({
    connectionString: 'postgresql://neondb_owner:npg_ISxCvM4w6jko@ep-still-river-an6gel8k-pooler.c-6.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require',
    ssl: { rejectUnauthorized: false }
});

const verificarToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: 'Acceso denegado.' });
    try {
        req.usuario_id = jwt.verify(token.split(' ')[1], SECRET_KEY).id; 
        next(); 
    } catch (error) { res.status(401).json({ error: 'Token inválido.' }); }
};

// --- RUTAS DE AUTH ---
app.post('/api/register', async (req, res) => {
    try {
        const hash = await bcrypt.hash(req.body.password, 10);
        const result = await pool.query('INSERT INTO usuarios (email, password_hash) VALUES ($1, $2) RETURNING id, email', [req.body.email, hash]);
        res.status(201).json(result.rows[0]);
    } catch (error) { res.status(400).json({ error: 'El email ya está registrado' }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [req.body.email]);
        if (result.rows.length === 0 || !(await bcrypt.compare(req.body.password, result.rows[0].password_hash))) 
            return res.status(400).json({ error: 'Credenciales inválidas' });
        res.json({ token: jwt.sign({ id: result.rows[0].id, email: result.rows[0].email }, SECRET_KEY, { expiresIn: '8h' }) });
    } catch (error) { res.status(500).json({ error: 'Error en servidor' }); }
});

app.put('/api/usuarios/password', verificarToken, async (req, res) => {
    const { passwordActual, passwordNueva } = req.body;
    try {
        const result = await pool.query('SELECT password_hash FROM usuarios WHERE id = $1', [req.usuario_id]);
        const valid = await bcrypt.compare(passwordActual, result.rows[0].password_hash);
        if (!valid) return res.status(400).json({ error: 'La contraseña actual es incorrecta' });

        const nuevoHash = await bcrypt.hash(passwordNueva, 10);
        await pool.query('UPDATE usuarios SET password_hash = $1 WHERE id = $2', [nuevoHash, req.usuario_id]);
        res.json({ mensaje: 'Contraseña actualizada exitosamente' });
    } catch (error) { res.status(500).json({ error: 'Error al cambiar contraseña' }); }
});

app.delete('/api/usuarios', verificarToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM usuarios WHERE id = $1', [req.usuario_id]);
        res.json({ mensaje: 'Cuenta eliminada permanentemente' });
    } catch (error) { res.status(500).json({ error: 'Error al eliminar cuenta' }); }
});

// --- NUEVO: RUTA SUPERADMINISTRADOR ---
app.get('/api/admin/stats', verificarToken, async (req, res) => {
    if (req.usuario_id !== 1) return res.status(403).json({ error: 'Acceso denegado. Se requieren permisos de Fundador.' });
    
    try {
        const users = await pool.query('SELECT COUNT(*) FROM usuarios');
        const negocios = await pool.query('SELECT COUNT(*) FROM negocios');
        const movs = await pool.query('SELECT COUNT(*) FROM movimientos_tesoreria');
        
        res.json({
            total_usuarios: users.rows[0].count,
            total_negocios: negocios.rows[0].count,
            total_movimientos: movs.rows[0].count
        });
    } catch (error) { res.status(500).json({ error: 'Error obteniendo métricas' }); }
});

// --- RUTAS DE NEGOCIOS ---
app.post('/api/negocios', verificarToken, async (req, res) => {
    const result = await pool.query('INSERT INTO negocios (usuario_id, nombre) VALUES ($1, $2) RETURNING *', [req.usuario_id, req.body.nombre]);
    res.json(result.rows[0]);
});

app.get('/api/negocios', verificarToken, async (req, res) => {
    const result = await pool.query('SELECT * FROM negocios WHERE usuario_id = $1 ORDER BY id ASC', [req.usuario_id]);
    res.json(result.rows);
});

app.delete('/api/negocios/:id', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('DELETE FROM negocios WHERE id = $1 AND usuario_id = $2 RETURNING *', [req.params.id, req.usuario_id]);
        if(result.rowCount === 0) return res.status(404).json({error: 'Negocio no encontrado'});
        res.json({ mensaje: 'Negocio eliminado' });
    } catch (error) { res.status(500).json({ error: 'Error al eliminar negocio' }); }
});

// --- RUTAS DE MOVIMIENTOS ---
app.post('/api/movimientos', verificarToken, async (req, res) => {
    const { negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, esCapital } = req.body;
    try {
        const result = await pool.query(
            `INSERT INTO movimientos_tesoreria (usuario_id, negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, es_capital) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
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

app.listen(port, () => { console.log(`🔒 Servidor conectado a Neon Cloud en http://localhost:${port}`); });