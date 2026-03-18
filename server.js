// server.js - API Backend Completo (Paywall, Auditoría Forense y WhatsApp NLP)
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;
const SECRET_KEY = 'super_clave_secreta_financiera_2026'; 

// Ciberseguridad: trust proxy permite leer la IP real del usuario en servidores de nube
app.set('trust proxy', true);
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const pool = new Pool({
    connectionString: 'postgresql://neondb_owner:npg_ISxCvM4w6jko@ep-still-river-an6gel8k-pooler.c-6.us-east-1.aws.neon.tech/neondb?sslmode=require',
    ssl: { rejectUnauthorized: false }
});

const enviarCorreo = (destino, asunto, mensaje) => { 
    console.log(`\n📧 [EMAIL A: ${destino}]\nAsunto: ${asunto}\nMensaje: ${mensaje}\n`); 
};

// ==========================================
// MOTOR DE AUDITORÍA FORENSE
// ==========================================
const registrarAuditoria = async (usuario_id, negocio_id, accion, ip) => {
    try {
        await pool.query(
            'INSERT INTO logs_auditoria (usuario_id, negocio_id, accion, ip_origen) VALUES ($1, $2, $3, $4)',
            [usuario_id, negocio_id, accion, ip]
        );
    } catch (error) { 
        console.error("Error guardando log forense:", error.message); 
    }
};

const verificarToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: 'Acceso denegado.' });
    try {
        const decoded = jwt.verify(token.split(' ')[1], SECRET_KEY);
        req.usuario_id = decoded.id; 
        req.usuario_email = decoded.email; 
        next(); 
    } catch (error) { 
        res.status(401).json({ error: 'Token inválido.' }); 
    }
};

// ==========================================
// AUTH, PERFIL Y PAYWALL
// ==========================================
app.post('/api/register', async (req, res) => {
    const { email, password, nombre, apellido, pais, telefono } = req.body;
    try {
        const hash = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO usuarios (email, password_hash, nombre, apellido, pais, telefono) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, nombre', 
            [email, hash, nombre, apellido, pais, telefono]
        );
        enviarCorreo(email, "¡Bienvenido a Tesorería SaaS!", `Hola ${nombre}, disfruta tus 15 días de prueba gratuita.`);
        res.status(201).json(result.rows[0]);
    } catch (error) { 
        res.status(400).json({ error: 'El email ya está registrado' }); 
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [req.body.email]);
        if (result.rows.length === 0 || !(await bcrypt.compare(req.body.password, result.rows[0].password_hash))) {
            return res.status(400).json({ error: 'Credenciales inválidas' });
        }
        
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
    } catch (error) { 
        res.status(500).json({ error: 'Error en servidor' }); 
    }
});

app.post('/api/recuperar', async (req, res) => {
    const { email } = req.body;
    try {
        const result = await pool.query('SELECT id, nombre FROM usuarios WHERE email = $1', [email]);
        if (result.rows.length > 0) {
            const resetToken = crypto.randomBytes(32).toString('hex');
            await pool.query("UPDATE usuarios SET reset_token = $1, reset_expires = NOW() + INTERVAL '1 hour' WHERE email = $2", [resetToken, email]);
            enviarCorreo(email, "Recuperación de Contraseña", `Hola ${result.rows[0].nombre},\nUsa este código de seguridad para crear una nueva clave: ${resetToken}`);
        }
        res.json({ mensaje: 'Si el correo existe, hemos enviado las instrucciones de recuperación.' });
    } catch (error) { 
        res.status(500).json({ error: 'Error procesando solicitud' }); 
    }
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
    } catch (error) { 
        res.status(500).json({ error: 'Error al cambiar contraseña' }); 
    }
});

app.delete('/api/usuarios', verificarToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM usuarios WHERE id = $1', [req.usuario_id]);
        res.json({ mensaje: 'Cuenta eliminada permanentemente' });
    } catch (error) { 
        res.status(500).json({ error: 'Error al eliminar cuenta' }); 
    }
});

// ==========================================
// ADMIN Y AUDITORÍA
// ==========================================
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
    } catch (error) { 
        res.status(500).json({ error: 'Error obteniendo métricas' }); 
    }
});

app.get('/api/auditoria/:negocio_id', verificarToken, async (req, res) => {
    try {
        // Solo el dueño del negocio puede ver la auditoría
        const check = await pool.query('SELECT id FROM negocios WHERE id = $1 AND usuario_id = $2', [req.params.negocio_id, req.usuario_id]);
        if (check.rows.length === 0) return res.status(403).json({ error: 'Acceso denegado a los logs forenses.' });

        const logs = await pool.query(
            `SELECT l.*, u.nombre, u.email FROM logs_auditoria l 
             JOIN usuarios u ON l.usuario_id = u.id 
             WHERE l.negocio_id = $1 ORDER BY l.fecha DESC LIMIT 50`, 
            [req.params.negocio_id]
        );
        res.json(logs.rows);
    } catch (error) { 
        res.status(500).json({ error: 'Error obteniendo auditoría' }); 
    }
});

app.post('/api/checkout', verificarToken, async (req, res) => {
    try {
        // Simulador de pago exitoso (Aquí iría la API de MercadoPago)
        await pool.query('UPDATE usuarios SET es_premium = TRUE WHERE id = $1', [req.usuario_id]);
        res.json({ mensaje: '¡Pago procesado exitosamente! Tu cuenta ahora es Premium.' });
    } catch (error) { 
        res.status(500).json({ error: 'Error en la pasarela de pagos.' }); 
    }
});

// ==========================================
// COLABORADORES, NEGOCIOS Y MOVIMIENTOS
// ==========================================
app.post('/api/colaboradores', verificarToken, async (req, res) => {
    const { negocio_id, email_invitado } = req.body;
    try {
        // Solo el dueño puede invitar
        const check = await pool.query('SELECT id FROM negocios WHERE id = $1 AND usuario_id = $2', [negocio_id, req.usuario_id]);
        if (check.rows.length === 0) return res.status(403).json({ error: 'Solo el dueño puede invitar colaboradores.' });
        
        await pool.query('INSERT INTO colaboradores (negocio_id, email_colaborador) VALUES ($1, $2)', [negocio_id, email_invitado]);
        
        // Registro Forense
        registrarAuditoria(req.usuario_id, negocio_id, `Invitó al usuario ${email_invitado} como socio colaborador.`, req.ip);
        
        res.json({ mensaje: 'Invitación enviada con éxito.' });
    } catch (error) { 
        res.status(500).json({ error: 'El usuario ya tiene acceso o hubo un error.' }); 
    }
});

app.post('/api/negocios', verificarToken, async (req, res) => {
    const result = await pool.query('INSERT INTO negocios (usuario_id, nombre) VALUES ($1, $2) RETURNING *', [req.usuario_id, req.body.nombre]);
    res.json(result.rows[0]);
});

app.get('/api/negocios', verificarToken, async (req, res) => {
    const result = await pool.query(
        `SELECT * FROM negocios WHERE usuario_id = $1 OR id IN (SELECT negocio_id FROM colaboradores WHERE email_colaborador = $2) ORDER BY id ASC`, 
        [req.usuario_id, req.usuario_email]
    );
    res.json(result.rows);
});

app.delete('/api/negocios/:id', verificarToken, async (req, res) => {
    const result = await pool.query('DELETE FROM negocios WHERE id = $1 AND usuario_id = $2 RETURNING *', [req.params.id, req.usuario_id]);
    if(result.rowCount === 0) return res.status(404).json({error: 'Negocio no encontrado o no tienes permisos'});
    res.json({ mensaje: 'Negocio eliminado' });
});

app.post('/api/movimientos', verificarToken, async (req, res) => {
    const { negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, esCapital } = req.body;
    try {
        const result = await pool.query(
            `INSERT INTO movimientos_tesoreria (usuario_id, negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, es_capital) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
            [req.usuario_id, negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, esCapital]
        );
        
        registrarAuditoria(req.usuario_id, negocio_id, `Creó un ${tipo} de $${monto} en la categoría ${categoria_contable}. Concepto: ${concepto}`, req.ip);
        res.status(201).json(result.rows[0]);
    } catch (error) { 
        res.status(500).json({ error: error.message }); 
    }
});

app.get('/api/movimientos', verificarToken, async (req, res) => {
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
    try {
        const mov = await pool.query('SELECT negocio_id, monto FROM movimientos_tesoreria WHERE id = $1 AND usuario_id = $2', [req.params.id, req.usuario_id]);
        if (mov.rows.length > 0) {
            await pool.query('DELETE FROM movimientos_tesoreria WHERE id = $1', [req.params.id]);
            registrarAuditoria(req.usuario_id, mov.rows[0].negocio_id, `Eliminó permanentemente un asiento de $${mov.rows[0].monto}.`, req.ip);
        }
        res.json({ mensaje: 'Eliminado' });
    } catch (error) { 
        res.status(500).json({ error: 'Error al eliminar' }); 
    }
});

app.put('/api/movimientos/:id', verificarToken, async (req, res) => {
    const { negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, esCapital } = req.body;
    try {
        const result = await pool.query(
            `UPDATE movimientos_tesoreria SET negocio_id=$1, concepto=$2, categoria_contable=$3, cantidad_unidades=$4, tipo=$5, monto=$6, es_capital=$7 WHERE id=$8 AND usuario_id=$9 RETURNING *`,
            [negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, esCapital, req.params.id, req.usuario_id]
        );
        registrarAuditoria(req.usuario_id, negocio_id, `Modificó un asiento. Nuevo monto: $${monto}. Nuevo concepto: ${concepto}`, req.ip);
        res.json(result.rows[0]);
    } catch (error) { 
        res.status(500).json({ error: 'Error al actualizar' }); 
    }
});

// ==========================================
// WEBHOOK OMNICANAL INTELIGENTE (WhatsApp)
// ==========================================
app.post('/api/whatsapp', async (req, res) => {
    res.type('text/xml');
    const mensajeOriginal = req.body.Body.trim();
    const mensaje = mensajeOriginal.toLowerCase(); 
    const remitente = req.body.From.replace('whatsapp:', '').trim();

    try {
        const userRes = await pool.query('SELECT id, nombre, email FROM usuarios WHERE telefono = $1', [remitente]);
        if (userRes.rows.length === 0) return res.send('<Response><Message>❌ Tu número no está autorizado en el SaaS.</Message></Response>');
        const usuario = userRes.rows[0];

        const montoMatch = mensaje.match(/\d+(?:\.\d+)?/);
        if (!montoMatch) return res.send('<Response><Message>❌ No detecté ningún monto. Por favor, incluye un número (ej: 5000).</Message></Response>');
        const monto = parseFloat(montoMatch[0]);

        const negociosRes = await pool.query(
            'SELECT id, nombre FROM negocios WHERE usuario_id = $1 OR id IN (SELECT negocio_id FROM colaboradores WHERE email_colaborador = $2)', 
            [usuario.id, usuario.email]
        );
        const misNegocios = negociosRes.rows;
        if (misNegocios.length === 0) return res.send('<Response><Message>❌ No tienes ningún negocio creado en la plataforma.</Message></Response>');

        let negocio_id = null;
        let marcaNombre = "";
        
        if (misNegocios.length === 1) {
            negocio_id = misNegocios[0].id;
            marcaNombre = misNegocios[0].nombre;
        } else {
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

        let categoriaElegida = 'Otros gastos'; 
        for (let cat of diccionario) {
            if (cat.palabras.some(p => mensaje.includes(p))) {
                categoriaElegida = cat.id;
                break;
            }
        }

        let tipoDeducido = 'egreso';
        let esCap = false;
        if (categoriaElegida === 'Ventas') tipoDeducido = 'ingreso';

        const concepto = mensajeOriginal;

        await pool.query(
            `INSERT INTO movimientos_tesoreria (usuario_id, negocio_id, concepto, categoria_contable, cantidad_unidades, tipo, monto, es_capital)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [usuario.id, negocio_id, concepto, categoriaElegida, 0, tipoDeducido, monto, esCap]
        );
        
        // Registrar en Auditoría que se cargó vía WhatsApp
        registrarAuditoria(usuario.id, negocio_id, `[WhatsApp Bot] Registró un ${tipoDeducido} de $${monto} en ${categoriaElegida}. Mensaje original: "${concepto}"`, req.ip || 'Bot');

        res.send(`<Response><Message>✅ ¡Registrado con éxito!\n💰 $${monto}\n🏢 ${marcaNombre}\n📂 Se clasificó como: ${categoriaElegida}</Message></Response>`);

    } catch (error) {
        console.error(error);
        res.send('<Response><Message>❌ Uy, hubo un problema técnico en el servidor guardando el dato.</Message></Response>');
    }
});

app.listen(port, () => { console.log(`🔒 Servidor en puerto ${port} con Motor Forense Activo y WhatsApp Bot`); });