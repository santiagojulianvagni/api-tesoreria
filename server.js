// server.js - API Backend Completo (Sin Mercado Pago)

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;
const SECRET_KEY = 'super_clave_secreta_financiera_2026'; 

app.set('trust proxy', true);
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const pool = new Pool({
    connectionString: 'postgresql://neondb_owner:npg_ISxCvM4w6jko@ep-still-river-an6gel8k-pooler.c-6.us-east-1.aws.neon.tech/neondb?sslmode=require',
    ssl: { rejectUnauthorized: false }
});

const enviarCorreo = (destino, asunto, mensaje) => { console.log(`\n📧 [EMAIL A: ${destino}]\nAsunto: ${asunto}\nMensaje: ${mensaje}\n`); };

const registrarAuditoria = async (usuario_id, negocio_id, accion, ip) => {
    try { await pool.query('INSERT INTO logs_auditoria (usuario_id, negocio_id, accion, ip_origen) VALUES ($1, $2, $3, $4)', [usuario_id, negocio_id, accion, ip]); } 
    catch (error) { console.error("Error log:", error.message); }
};

const verificarToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: 'Acceso denegado.' });
    try {
        const decoded = jwt.verify(token.split(' ')[1], SECRET_KEY);
        req.usuario_id = decoded.id; req.usuario_email = decoded.email; next(); 
    } catch (error) { res.status(401).json({ error: 'Token inválido.' }); }
};

// ==========================================
// AUTH Y MOTOR DE SUSCRIPCIONES
// ==========================================
app.post('/api/register', async (req, res) => {
    const { email, password, nombre, apellido, pais, telefono } = req.body;
    try {
        const hash = await bcrypt.hash(password, 10);
        const result = await pool.query('INSERT INTO usuarios (email, password_hash, nombre, apellido, pais, telefono) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, nombre', [email, hash, nombre, apellido, pais, telefono]);
        enviarCorreo(email, "¡Bienvenido a Tesorería SaaS!", `Hola ${nombre}, disfruta tus 15 días.`);
        res.status(201).json(result.rows[0]);
    } catch (error) { res.status(400).json({ error: 'El email ya está registrado' }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [req.body.email]);
        if (result.rows.length === 0 || !(await bcrypt.compare(req.body.password, result.rows[0].password_hash))) return res.status(400).json({ error: 'Credenciales inválidas' });
        
        const user = result.rows[0];
        
        // Guardamos en el reloj a qué hora entró (Para el DAU)
        await pool.query("UPDATE usuarios SET ultimo_login = NOW() WHERE id = $1", [user.id]);

        const hoy = new Date(); let diasRestantes = 0; let estadoPlan = user.plan_actual;

        if (user.es_premium && user.vencimiento_suscripcion) {
            const vencimiento = new Date(user.vencimiento_suscripcion);
            diasRestantes = Math.ceil((vencimiento - hoy) / (1000 * 60 * 60 * 24));
            if (diasRestantes <= 0) estadoPlan = 'Expirado';
        } else {
            const fechaCreacion = new Date(user.fecha_creacion);
            diasRestantes = 15 - Math.floor((hoy - fechaCreacion) / (1000 * 60 * 60 * 24));
        }

        const payload = { id: user.id, email: user.email, nombre: user.nombre, es_premium: user.es_premium, plan_actual: estadoPlan, dias_restantes: diasRestantes, vencimiento: user.vencimiento_suscripcion };
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
            enviarCorreo(email, "Recuperación de Contraseña", `Usa este código: ${resetToken}`);
        }
        res.json({ mensaje: 'Instrucciones enviadas.' });
    } catch (error) { res.status(500).json({ error: 'Error' }); }
});

app.put('/api/usuarios/password', verificarToken, async (req, res) => {
    const { passwordActual, passwordNueva } = req.body;
    try {
        const result = await pool.query('SELECT password_hash FROM usuarios WHERE id = $1', [req.usuario_id]);
        if (!(await bcrypt.compare(passwordActual, result.rows[0].password_hash))) return res.status(400).json({ error: 'Contraseña actual incorrecta' });
        await pool.query('UPDATE usuarios SET password_hash = $1 WHERE id = $2', [await bcrypt.hash(passwordNueva, 10), req.usuario_id]);
        res.json({ mensaje: 'Contraseña actualizada' });
    } catch (error) { res.status(500).json({ error: 'Error' }); }
});

app.delete('/api/usuarios', verificarToken, async (req, res) => {
    try { await pool.query('DELETE FROM usuarios WHERE id = $1', [req.usuario_id]); res.json({ mensaje: 'Cuenta eliminada' }); } 
    catch (error) { res.status(500).json({ error: 'Error' }); }
});

// ==========================================
// SIMULADOR DE PASARELA DE PAGOS
// ==========================================
app.post('/api/checkout', verificarToken, async (req, res) => {
    const { tipo_plan } = req.body; 
    const diasASumar = tipo_plan === 'Anual' ? 365 : 30;
    try {
        await pool.query(
            `UPDATE usuarios SET es_premium = TRUE, plan_actual = $1, vencimiento_suscripcion = NOW() + INTERVAL '1 day' * $2 WHERE id = $3`, 
            [tipo_plan, diasASumar, req.usuario_id]
        );
        // Simulamos que MercadoPago aprobó y nos mandó de vuelta
        res.json({ mensaje: `¡Suscripción ${tipo_plan} simulada y activada con éxito!` });
    } catch (error) { 
        res.status(500).json({ error: 'Error simulando pago' }); 
    }
});

// ==========================================
// ADMIN, MÉTRICAS Y SUPERPODERES (EL BACKOFFICE CEO)
// ==========================================
app.get('/api/admin/stats', verificarToken, async (req, res) => {
    if (req.usuario_id !== 1) return res.status(403).json({ error: 'Denegado.' });
    try {
        const users = await pool.query('SELECT COUNT(*) FROM usuarios');
        const negocios = await pool.query('SELECT COUNT(*) FROM negocios');
        const movs = await pool.query('SELECT COUNT(*) FROM movimientos_tesoreria');
        const dau = await pool.query("SELECT COUNT(*) FROM usuarios WHERE ultimo_login >= NOW() - INTERVAL '24 hours'");
        const mrrQuery = await pool.query("SELECT SUM(CASE WHEN plan_actual = 'Mensual' THEN 74999 WHEN plan_actual = 'Anual' THEN 62499 ELSE 0 END) as total_mrr FROM usuarios WHERE es_premium = TRUE AND plan_actual != 'Expirado'");

        res.json({ 
            total_usuarios: users.rows[0].count, 
            total_negocios: negocios.rows[0].count, 
            total_movimientos: movs.rows[0].count,
            dau: dau.rows[0].count,
            mrr: mrrQuery.rows[0].total_mrr || 0
        });
    } catch (error) { res.status(500).json({ error: 'Error métricas' }); }
});

app.get('/api/admin/usuarios', verificarToken, async (req, res) => {
    if (req.usuario_id !== 1) return res.status(403).json({ error: 'Denegado.' });
    try {
        const lista = await pool.query('SELECT id, nombre, apellido, email, telefono, es_premium, plan_actual, vencimiento_suscripcion, fecha_creacion, ultimo_login FROM usuarios ORDER BY id DESC');
        res.json(lista.rows);
    } catch (error) { res.status(500).json({ error: 'Error usuarios' }); }
});

app.put('/api/admin/usuarios/:id/premium', verificarToken, async (req, res) => {
    if (req.usuario_id !== 1) return res.status(403).json({ error: 'Denegado.' });
    try {
        await pool.query("UPDATE usuarios SET es_premium = TRUE, plan_actual = 'Regalo Founder', vencimiento_suscripcion = NOW() + INTERVAL '30 days' WHERE id = $1", [req.params.id]);
        res.json({ mensaje: 'Premium regalado (30 días).' });
    } catch (error) { res.status(500).json({ error: 'Error' }); }
});

app.put('/api/admin/usuarios/:id/trial', verificarToken, async (req, res) => {
    if (req.usuario_id !== 1) return res.status(403).json({ error: 'Denegado.' });
    try {
        await pool.query("UPDATE usuarios SET fecha_creacion = fecha_creacion + INTERVAL '7 days' WHERE id = $1", [req.params.id]);
        res.json({ mensaje: 'Trial extendido (+7 días).' });
    } catch (error) { res.status(500).json({ error: 'Error' }); }
});

app.delete('/api/admin/usuarios/:id', verificarToken, async (req, res) => {
    if (req.usuario_id !== 1) return res.status(403).json({ error: 'Denegado.' });
    try {
        await pool.query('DELETE FROM usuarios WHERE id = $1', [req.params.id]);
        res.json({ mensaje: 'Usuario Eliminado.' });
    } catch (error) { res.status(500).json({ error: 'Error' }); }
});

app.post('/api/admin/impersonate/:id', verificarToken, async (req, res) => {
    if (req.usuario_id !== 1) return res.status(403).json({ error: 'Denegado.' });
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE id = $1', [req.params.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'No encontrado' });
        
        const user = result.rows[0];
        const payload = { id: user.id, email: user.email, nombre: user.nombre, es_premium: user.es_premium, plan_actual: user.plan_actual, dias_restantes: 15, vencimiento: user.vencimiento_suscripcion };
        res.json({ token: jwt.sign(payload, SECRET_KEY, { expiresIn: '2h' }), usuario: payload });
    } catch (error) { res.status(500).json({ error: 'Error' }); }
});

// ==========================================
// RESTO DEL SISTEMA: NEGOCIOS Y MOVIMIENTOS
// ==========================================
app.get('/api/auditoria/:negocio_id', verificarToken, async (req, res) => {
    try {
        const check = await pool.query('SELECT id FROM negocios WHERE id = $1 AND usuario_id = $2', [req.params.negocio_id, req.usuario_id]);
        if (check.rows.length === 0) return res.status(403).json({ error: 'Denegado.' });
        const logs = await pool.query(`SELECT l.*, u.nombre, u.email FROM logs_auditoria l JOIN usuarios u ON l.usuario_id = u.id WHERE l.negocio_id = $1 ORDER BY l.fecha DESC LIMIT 50`, [req.params.negocio_id]);
        res.json(logs.rows);
    } catch (error) { res.status(500).json({ error: 'Error auditoría' }); }
});

app.post('/api/colaboradores', verificarToken, async (req, res) => {
    const { negocio_id, email_invitado } = req.body;
    try {
        const check = await pool.query('SELECT id FROM negocios WHERE id = $1 AND usuario_id = $2', [negocio_id, req.usuario_id]);
        if (check.rows.length === 0) return res.status(403).json({ error: 'Solo dueño invita.' });
        await pool.query('INSERT INTO colaboradores (negocio_id, email_colaborador) VALUES ($1, $2)', [negocio_id, email_invitado]);
        registrarAuditoria(req.usuario_id, negocio_id, `Invitó a ${email_invitado}`, req.ip); res.json({ mensaje: 'Enviada.' });
    } catch (error) { res.status(500).json({ error: 'Error' }); }
});

app.post('/api/negocios', verificarToken, async (req, res) => {
    const result = await pool.query('INSERT INTO negocios (usuario_id, nombre) VALUES ($1, $2) RETURNING *', [req.usuario_id, req.body.nombre]); res.json(result.rows[0]);
});

app.get('/api/negocios', verificarToken, async (req, res) => {
    const result = await pool.query(`SELECT * FROM negocios WHERE usuario_id = $1 OR id IN (SELECT negocio_id FROM colaboradores WHERE email_colaborador = $2) ORDER BY id ASC`, [req.usuario_id, req.usuario_email]); res.json(result.rows);
});

app.put('/api/negocios/:id/tema', verificarToken, async (req, res) => {
    const { tema } = req.body;
    try { const result = await pool.query('UPDATE negocios SET tema = $1 WHERE id = $2 AND usuario_id = $3 RETURNING *', [tema, req.params.id, req.usuario_id]); if(result.rowCount === 0) return res.status(403).json({error: 'No eres dueño'}); res.json(result.rows[0]); } 
    catch (error) { res.status(500).json({ error: 'Error branding' }); }
});

app.delete('/api/negocios/:id', verificarToken, async (req, res) => {
    const result = await pool.query('DELETE FROM negocios WHERE id = $1 AND usuario_id = $2 RETURNING *', [req.params.id, req.usuario_id]); if(result.rowCount === 0) return res.status(404).json({error: 'No autorizado'}); res.json({ mensaje: 'Eliminado' });
});

app.post('/api/movimientos', verificarToken, async (req, res) => {
    const { negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, esCapital, estado_pago, entidad, fecha_vencimiento } = req.body;
    try {
        const result = await pool.query(`INSERT INTO movimientos_tesoreria (usuario_id, negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, es_capital, estado_pago, entidad, fecha_vencimiento) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`, [req.usuario_id, negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, esCapital, estado_pago || 'pagado', entidad || null, fecha_vencimiento || null]);
        registrarAuditoria(req.usuario_id, negocio_id, `Creó ${tipo} $${monto} (${estado_pago || 'pagado'}).`, req.ip); res.status(201).json(result.rows[0]);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/movimientos', verificarToken, async (req, res) => {
    const result = await pool.query(`SELECT m.*, n.nombre as empresa_nombre FROM movimientos_tesoreria m JOIN negocios n ON m.negocio_id = n.id WHERE n.usuario_id = $1 OR n.id IN (SELECT negocio_id FROM colaboradores WHERE email_colaborador = $2) ORDER BY m.fecha_registro ASC`, [req.usuario_id, req.usuario_email]); res.json(result.rows);
});

app.get('/api/deudas/:negocio_id', verificarToken, async (req, res) => {
    try { const result = await pool.query(`SELECT * FROM movimientos_tesoreria WHERE negocio_id = $1 AND estado_pago = 'pendiente' ORDER BY fecha_vencimiento ASC`, [req.params.negocio_id]); res.json(result.rows); } 
    catch (error) { res.status(500).json({ error: 'Error deudas' }); }
});

app.put('/api/movimientos/:id/pagar', verificarToken, async (req, res) => {
    try { const result = await pool.query(`UPDATE movimientos_tesoreria SET estado_pago = 'pagado' WHERE id = $1 AND negocio_id IN (SELECT id FROM negocios WHERE usuario_id = $2 OR id IN (SELECT negocio_id FROM colaboradores WHERE email_colaborador = $3)) RETURNING *`, [req.params.id, req.usuario_id, req.usuario_email]); registrarAuditoria(req.usuario_id, result.rows[0].negocio_id, `Pagó asiento #${req.params.id}.`, req.ip); res.json(result.rows[0]); } 
    catch (error) { res.status(500).json({ error: 'Error pago' }); }
});

app.delete('/api/movimientos/:id', verificarToken, async (req, res) => {
    try { const mov = await pool.query('SELECT negocio_id, monto FROM movimientos_tesoreria WHERE id = $1 AND usuario_id = $2', [req.params.id, req.usuario_id]); if (mov.rows.length > 0) { await pool.query('DELETE FROM movimientos_tesoreria WHERE id = $1', [req.params.id]); registrarAuditoria(req.usuario_id, mov.rows[0].negocio_id, `Borró asiento $${mov.rows[0].monto}.`, req.ip); } res.json({ mensaje: 'Eliminado' }); } 
    catch (error) { res.status(500).json({ error: 'Error' }); }
});

app.put('/api/movimientos/:id', verificarToken, async (req, res) => {
    const { negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, esCapital, estado_pago, entidad, fecha_vencimiento } = req.body;
    try { const result = await pool.query(`UPDATE movimientos_tesoreria SET negocio_id=$1, concepto=$2, categoria_contable=$3, cantidad_unidades=$4, tipo=$5, monto=$6, es_capital=$7, estado_pago=$8, entidad=$9, fecha_vencimiento=$10 WHERE id=$11 AND usuario_id=$12 RETURNING *`, [negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, esCapital, estado_pago, entidad, fecha_vencimiento, req.params.id, req.usuario_id]); registrarAuditoria(req.usuario_id, negocio_id, `Editó asiento a $${monto}.`, req.ip); res.json(result.rows[0]); } 
    catch (error) { res.status(500).json({ error: 'Error' }); }
});

// ==========================================
// WHATSAPP NLP
// ==========================================
app.post('/api/whatsapp', async (req, res) => {
    res.type('text/xml'); const mensajeOriginal = req.body.Body.trim(); const mensajeNormalizado = mensajeOriginal.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, ""); const remitente = req.body.From.replace('whatsapp:', '').trim();
    try {
        const userRes = await pool.query('SELECT id, nombre, email FROM usuarios WHERE telefono = $1', [remitente]); if (userRes.rows.length === 0) return res.send('<Response><Message>❌ Número no autorizado.</Message></Response>'); const usuario = userRes.rows[0];
        const montoMatch = mensajeNormalizado.match(/\d+(?:\.\d+)?/); if (!montoMatch) return res.send('<Response><Message>❌ Falta monto.</Message></Response>'); const monto = parseFloat(montoMatch[0]);
        const negociosRes = await pool.query('SELECT id, nombre FROM negocios WHERE usuario_id = $1 OR id IN (SELECT negocio_id FROM colaboradores WHERE email_colaborador = $2)', [usuario.id, usuario.email]); const misNegocios = negociosRes.rows; if (misNegocios.length === 0) return res.send('<Response><Message>❌ No tienes negocios.</Message></Response>');
        let negocio_id = null; let marcaNombre = "";
        if (misNegocios.length === 1) { negocio_id = misNegocios[0].id; marcaNombre = misNegocios[0].nombre; } else { for (let n of misNegocios) { if (mensajeNormalizado.includes(n.nombre.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").split(' ')[0])) { negocio_id = n.id; marcaNombre = n.nombre; break; } } if (!negocio_id) return res.send('<Response><Message>❌ Nombra la marca (ej: Naturae).</Message></Response>'); }
        const diccionario = [ { id: 'Ventas', palabras: ['venta', 'ventas', 'cobre', 'ingreso', 'cliente', 'cobro'] }, { id: 'Insumos', palabras: ['insumo', 'insumos', 'compra', 'mercaderia', 'proveedor'] }, { id: 'Sueldos', palabras: ['sueldo', 'sueldos', 'honorario', 'pague', 'adelanto'] }, { id: 'Marketing', palabras: ['marketing', 'publicidad', 'ads'] } ];
        let categoriaElegida = 'Otros gastos'; for (let cat of diccionario) { if (cat.palabras.some(p => mensajeNormalizado.includes(p))) { categoriaElegida = cat.id; break; } } let tipoDeducido = 'egreso'; let esCap = false; if (categoriaElegida === 'Ventas') tipoDeducido = 'ingreso';
        let estado_pago = 'pagado'; let fecha_vencimiento = null; let entidad = null; const fechaMatch = mensajeNormalizado.match(/(\d{1,2})[\/\-](\d{1,2})/); if (fechaMatch) { fecha_vencimiento = `${new Date().getFullYear()}-${fechaMatch[2].padStart(2, '0')}-${fechaMatch[1].padStart(2, '0')}`; estado_pago = 'pendiente'; } if (mensajeNormalizado.includes('a pagar') || mensajeNormalizado.includes('pendiente') || mensajeNormalizado.includes('debe')) estado_pago = 'pendiente';
        const entidadMatch = mensajeOriginal.match(/(?:venta|ventas a|cobre a|cobré a|pague a|pagué a) ([a-zA-Z]+)/i); if (entidadMatch) entidad = entidadMatch[1]; else if (mensajeNormalizado.includes('venta ')) { const parts = mensajeOriginal.split(/venta /i); if (parts[1]) entidad = parts[1].split(' ')[0]; } if (entidad && entidad.match(/\d+/)) entidad = null;
        await pool.query(`INSERT INTO movimientos_tesoreria (usuario_id, negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, es_capital, estado_pago, entidad, fecha_vencimiento) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, [usuario.id, negocio_id, mensajeOriginal, categoriaElegida, 0, tipoDeducido, monto, esCap, estado_pago, entidad, fecha_vencimiento]); registrarAuditoria(usuario.id, negocio_id, `[WhatsApp] ${categoriaElegida} $${monto} (${estado_pago})`, req.ip || 'Bot');
        const msjEntidad = entidad ? `\n👤 Entidad: ${entidad.charAt(0).toUpperCase() + entidad.slice(1)}` : ''; let msjDeuda = '\n✅ PAGADO'; if (estado_pago === 'pendiente') { const fText = fecha_vencimiento ? fecha_vencimiento.split('-').reverse().join('/') : 'Sin fecha'; msjDeuda = `\n⏳ PENDIENTE\n📅 Vence: ${fText}`; } res.send(`<Response><Message>🏢 ${marcaNombre}\n💰 $${monto} en ${categoriaElegida}${msjEntidad}${msjDeuda}</Message></Response>`);
    } catch (error) { res.send('<Response><Message>❌ Error servidor.</Message></Response>'); }
});

app.listen(port, () => { console.log(`🔒 Servidor en puerto ${port} (Backoffice Listo sin MP)`); });