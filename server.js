import express from 'express';
import session from 'express-session';
import bcrypt from 'bcrypt';
import mysql from 'mysql2/promise';
import path from 'path';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();
const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(process.cwd(), 'public')));

// Configurar CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    next();
});

app.use(session({
    secret: process.env.SESSION_SECRET || 'tech-biomedical-secret-2024',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// ===== CONEXIÓN A MYSQL CON TU USUARIO =====
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: 'estudios',  // Tu usuario
    password: 'biomedica',  // Tu contraseña
    database: process.env.DB_NAME || 'lab_estudios',
    waitForConnections: true,
    connectionLimit: 10,
    timezone: 'Z'
});

// ===== FUNCIONES Y MIDDLEWARE =====
function requireLogin(req, res, next) {
    if (!req.session.usuario) {
        return res.redirect('/login.html');
    }
    next();
}

function requireRole(allowedRoles) {
    return (req, res, next) => {
        const usuario = req.session.usuario;
        if (!usuario) {
            return res.redirect('/login.html');
        }
        
        const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];
        if (!roles.includes(usuario.tipo)) {
            return res.status(403).send(`
                <div style="padding: 2rem; text-align: center;">
                    <h2>Acceso Denegado</h2>
                    <p>No tienes permisos para acceder a esta página.</p>
                    <p>Tu rol: ${usuario.tipo}</p>
                    <p>Rol requerido: ${roles.join(', ')}</p>
                    <a href="/index.html">Volver al inicio</a>
                </div>
            `);
        }
        next();
    };
}

// ===== RUTAS DE PÁGINAS HTML =====

// Página principal (dashboard)
app.get('/', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/index.html', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Login y registro (públicas)
app.get('/login.html', (req, res) => {
    // Si ya está logueado, redirigir al dashboard
    if (req.session.usuario) {
        return res.redirect('/index.html');
    }
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/registro.html', (req, res) => {
    // Si ya está logueado, redirigir al dashboard
    if (req.session.usuario) {
        return res.redirect('/index.html');
    }
    res.sendFile(path.join(__dirname, 'public', 'registro.html'));
});

// Admin panel
app.get('/admin.html', requireLogin, requireRole(['ADMIN', 'admin']), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Otras páginas protegidas
const protectedPages = [
    'ordenes.html',
    'resultados.html',
    'catalogo.html',
    'nueva-orden.html',
    'pacientes.html',
    'mis-resultados.html',
    'procesar-estudios.html',
    'validar-resultados.html',
    'reportes.html',
    'importar.html',
    'buscar-orden.html',
    'orden-detalle.html',
    'mis-ordenes.html',
    'citas.html'
];

protectedPages.forEach(page => {
    app.get(`/${page}`, requireLogin, (req, res) => {
        res.sendFile(path.join(__dirname, 'public', page));
    });
});

// Navbar (acceso público para incluir en páginas)
app.get('/navbar.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'navbar.html'));
});

// ===== API ENDPOINTS =====

// Verificar sesión
app.get('/session-check', (req, res) => {
    if (req.session.usuario) {
        res.json({ loggedIn: true, usuario: req.session.usuario });
    } else {
        res.json({ loggedIn: false });
    }
});

// Verificar código de acceso
app.post('/verificar-codigo', async (req, res) => {
    const { codigo } = req.body;
    
    if (!codigo) {
        return res.json({ 
            valido: false, 
            mensaje: 'No se proporcionó código' 
        });
    }
    
    try {
        const [codigoRows] = await pool.query(
            'SELECT tipo_usuario FROM codigos_access WHERE codigo = ?',
            [codigo.toUpperCase()]
        );
        
        if (codigoRows.length > 0) {
            res.json({
                valido: true,
                tipo_usuario: codigoRows[0].tipo_usuario,
                mensaje: `Código válido para rol: ${codigoRows[0].tipo_usuario}`
            });
        } else {
            res.json({
                valido: false,
                mensaje: 'Código inválido. Prueba con: ADMIN, MED, AUDITOR o INV'
            });
        }
    } catch (err) {
        console.error('Error verificando código:', err);
        res.status(500).json({
            valido: false,
            mensaje: 'Error al verificar código'
        });
    }
});

// Registro de usuario
app.post('/registro', async (req, res) => {
    const { username, password, codigo_acceso } = req.body;
    
    if (!username || !password || !codigo_acceso) {
        return res.json({ 
            success: false, 
            message: 'Faltan datos requeridos' 
        });
    }
    
    try {
        // Verificar código
        const [codigoRows] = await pool.query(
            'SELECT tipo_usuario FROM codigos_access WHERE codigo = ?',
            [codigo_acceso.toUpperCase()]
        );
        
        if (codigoRows.length === 0) {
            return res.json({ 
                success: false, 
                message: 'Código inválido. Usa: ADMIN, MED, AUDITOR o INV' 
            });
        }
        
        // Verificar usuario existente
        const [userRows] = await pool.query(
            'SELECT id FROM usuarios WHERE nombre_usuario = ?',
            [username]
        );
        
        if (userRows.length > 0) {
            return res.json({ 
                success: false, 
                message: 'El usuario ya existe' 
            });
        }
        
        // Crear hash de contraseña
        const hash = await bcrypt.hash(password, 12);
        const tipo_usuario = codigoRows[0].tipo_usuario;
        
        // Insertar usuario
        await pool.query(
            'INSERT INTO usuarios (nombre_usuario, password_hash, tipo_usuario) VALUES (?, ?, ?)',
            [username, hash, tipo_usuario]
        );
        
        res.json({
            success: true,
            message: 'Usuario registrado exitosamente',
            tipo_usuario: tipo_usuario
        });
        
    } catch (err) {
        console.error('Error en registro:', err);
        res.status(500).json({
            success: false,
            message: 'Error en el registro: ' + err.message
        });
    }
});

// Login - VERSIÓN CORREGIDA
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    try {
        const [rows] = await pool.query(
            'SELECT * FROM usuarios WHERE nombre_usuario = ?',
            [username]
        );
        
        if (rows.length === 0) {
            return res.status(401).json({ 
                success: false, 
                message: 'Usuario no encontrado' 
            });
        }
        
        const user = rows[0];
        
        // Verificar contraseña
        const valid = await bcrypt.compare(password, user.password_hash);
        
        if (!valid) {
            // También verificar si es contraseña en texto plano (para migración)
            if (password === user.password_hash) {
                // Actualizar a hash bcrypt
                const hash = await bcrypt.hash(password, 12);
                await pool.query(
                    'UPDATE usuarios SET password_hash = ? WHERE id = ?',
                    [hash, user.id]
                );
                console.log(`✅ Actualizado hash para usuario: ${username}`);
            } else {
                return res.status(401).json({ 
                    success: false, 
                    message: 'Contraseña incorrecta' 
                });
            }
        }
        
        // Crear sesión
        req.session.usuario = {
            id: user.id,
            username: user.nombre_usuario,
            tipo: user.tipo_usuario,
            fecha_registro: user.fecha_registro
        };
        
        console.log(`✅ Login exitoso: ${username} (${user.tipo_usuario})`);
        
        // AQUÍ ESTÁ LA CLAVE: Enviar respuesta JSON con redirect
        res.json({
            success: true,
            message: 'Login exitoso',
            usuario: req.session.usuario,
            redirect: '/index.html'  // ← ESTA LÍNEA ES IMPORTANTE
        });
        
    } catch (err) {
        console.error('Error en login:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error en login: ' + err.message
        });
    }
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error cerrando sesión:', err);
        }
        res.redirect('/login.html');
    });
});

// ===== API PARA DASHBOARD =====

// Métricas del sistema
app.get('/api/metricas', requireLogin, async (req, res) => {
    try {
        const [totalOrdenes] = await pool.query('SELECT COUNT(*) as total FROM ordenes_estudios');
        const [totalUsuarios] = await pool.query('SELECT COUNT(*) as total FROM usuarios');
        const [totalEstudios] = await pool.query('SELECT COUNT(*) as total FROM catalogo_estudios WHERE activo = TRUE');
        const [ordenesCompletadas] = await pool.query("SELECT COUNT(*) as total FROM ordenes_estudios WHERE estado_order = 'Validado'");
        
        res.json({
            metricas_generales: {
                total_ordenes: totalOrdenes[0].total,
                total_usuarios: totalUsuarios[0].total,
                total_estudios: totalEstudios[0].total,
                ordenes_completadas: ordenesCompletadas[0].total
            }
        });
    } catch (err) {
        console.error('Error obteniendo métricas:', err);
        res.json({
            metricas_generales: {
                total_ordenes: 0,
                total_usuarios: 0,
                total_estudios: 0,
                ordenes_completadas: 0
            }
        });
    }
});

// Órdenes recientes
app.get('/api/ordenes', requireLogin, async (req, res) => {
    try {
        const limit = req.query.limit || 10;
        const [ordenes] = await pool.query(
            'SELECT * FROM ordenes_estudios ORDER BY fecha_solicitud DESC LIMIT ?',
            [parseInt(limit)]
        );
        res.json(ordenes);
    } catch (err) {
        console.error('Error obteniendo órdenes:', err);
        res.json([]);
    }
});

// Estudios del catálogo
app.get('/api/catalogo-estudios', requireLogin, async (req, res) => {
    try {
        const [estudios] = await pool.query(
            'SELECT * FROM catalogo_estudios WHERE activo = TRUE ORDER BY nombre_prueba'
        );
        res.json(estudios);
    } catch (err) {
        console.error('Error obteniendo catálogo:', err);
        res.json([]);
    }
});

// Búsqueda
app.get('/api/buscar', requireLogin, async (req, res) => {
    try {
        const { q, tipo } = req.query;
        
        if (!q || q.length < 2) {
            return res.json([]);
        }
        
        let results = [];
        
        if (tipo === 'ordenes') {
            const [ordenes] = await pool.query(
                `SELECT * FROM ordenes_estudios 
                 WHERE id_orden LIKE ? 
                 OR observaciones LIKE ?
                 ORDER BY fecha_solicitud DESC 
                 LIMIT 10`,
                [`%${q}%`, `%${q}%`]
            );
            results = ordenes;
        } else if (tipo === 'usuarios' && req.session.usuario.tipo === 'ADMIN') {
            const [usuarios] = await pool.query(
                `SELECT * FROM usuarios 
                 WHERE nombre_usuario LIKE ? 
                 OR tipo_usuario LIKE ?
                 ORDER BY nombre_usuario 
                 LIMIT 10`,
                [`%${q}%`, `%${q}%`]
            );
            results = usuarios;
        }
        
        res.json(results);
    } catch (err) {
        console.error('Error en búsqueda:', err);
        res.json([]);
    }
});

// ===== API PARA ADMIN =====

// Usuarios (solo admin)
app.get('/api/usuarios', requireLogin, requireRole(['ADMIN', 'admin']), async (req, res) => {
    try {
        const [usuarios] = await pool.query(`
            SELECT u.*,
                   (SELECT COUNT(*) FROM ordenes_estudios WHERE id_paciente = u.id) as ordenes_como_paciente,
                   (SELECT COUNT(*) FROM ordenes_estudios WHERE id_medico = u.id) as ordenes_como_medico
            FROM usuarios u
            ORDER BY fecha_registro DESC
        `);
        res.json(usuarios);
    } catch (err) {
        console.error('Error obteniendo usuarios:', err);
        res.status(500).json({ error: 'Error al obtener usuarios' });
    }
});

// Crear usuario (solo admin)
app.post('/api/usuarios', requireLogin, requireRole(['ADMIN', 'admin']), async (req, res) => {
    try {
        const { nombre_usuario, password, tipo_usuario } = req.body;
        
        const hash = await bcrypt.hash(password, 12);
        
        await pool.query(
            'INSERT INTO usuarios (nombre_usuario, password_hash, tipo_usuario) VALUES (?, ?, ?)',
            [nombre_usuario, hash, tipo_usuario]
        );
        
        res.json({ success: true, message: 'Usuario creado exitosamente' });
    } catch (err) {
        console.error('Error creando usuario:', err);
        res.status(500).json({ error: 'Error al crear usuario' });
    }
});

// Códigos de acceso (solo admin)
app.get('/api/codigos', requireLogin, requireRole(['ADMIN', 'admin']), async (req, res) => {
    try {
        const [codigos] = await pool.query(
            'SELECT * FROM codigos_access ORDER BY codigo'
        );
        res.json(codigos);
    } catch (err) {
        console.error('Error obteniendo códigos:', err);
        res.json([]);
    }
});

// Generar códigos (solo admin)
app.post('/api/generar-codigos', requireLogin, requireRole(['ADMIN', 'admin']), async (req, res) => {
    try {
        const { cantidad, tipo_usuario } = req.body;
        const codigosGenerados = [];
        
        for (let i = 0; i < cantidad; i++) {
            const codigo = `${tipo_usuario.slice(0, 3)}${Date.now().toString().slice(-6)}${Math.random().toString(36).substr(2, 3).toUpperCase()}`;
            
            await pool.query(
                'INSERT INTO codigos_access (codigo, tipo_usuario) VALUES (?, ?)',
                [codigo, tipo_usuario]
            );
            
            codigosGenerados.push(codigo);
        }
        
        res.json({
            success: true,
            message: `Se generaron ${cantidad} códigos`,
            codigos: codigosGenerados
        });
    } catch (err) {
        console.error('Error generando códigos:', err);
        res.status(500).json({ error: 'Error al generar códigos' });
    }
});

// Estadísticas avanzadas (solo admin)
app.get('/api/admin/estadisticas-completas', requireLogin, requireRole(['ADMIN', 'admin']), async (req, res) => {
    try {
        const [totalUsuarios] = await pool.query('SELECT COUNT(*) as total FROM usuarios');
        const [totalOrdenes] = await pool.query('SELECT COUNT(*) as total FROM ordenes_estudios');
        const [usuariosPorTipo] = await pool.query(
            'SELECT tipo_usuario, COUNT(*) as cantidad FROM usuarios GROUP BY tipo_usuario'
        );
        
        res.json({
            estadisticas_generales: {
                total_usuarios: totalUsuarios[0].total,
                total_ordenes: totalOrdenes[0].total
            },
            usuarios_por_tipo: usuariosPorTipo
        });
    } catch (err) {
        console.error('Error obteniendo estadísticas:', err);
        res.json({
            estadisticas_generales: { total_usuarios: 0, total_ordenes: 0 },
            usuarios_por_tipo: []
        });
    }
});

// ===== INICIALIZACIÓN DE BASE DE DATOS =====
app.get('/init-db', async (req, res) => {
    try {
        // Verificar conexión
        const connection = await pool.getConnection();
        
        // Crear tablas si no existen
        await connection.query(`
            CREATE TABLE IF NOT EXISTS usuarios (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nombre_usuario VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                tipo_usuario VARCHAR(50) NOT NULL,
                fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                activo BOOLEAN DEFAULT TRUE
            )
        `);
        
        await connection.query(`
            CREATE TABLE IF NOT EXISTS codigos_access (
                codigo VARCHAR(20) PRIMARY KEY,
                tipo_usuario VARCHAR(50) NOT NULL
            )
        `);
        
        await connection.query(`
            CREATE TABLE IF NOT EXISTS catalogo_estudios (
                id_catalogo_prueba INT AUTO_INCREMENT PRIMARY KEY,
                nombre_prueba VARCHAR(100) NOT NULL,
                descripcion TEXT,
                unidad_medida VARCHAR(50),
                valores_referencia VARCHAR(255),
                precio DECIMAL(10,2) DEFAULT 0.00,
                categoria VARCHAR(50),
                tiempo_procesamiento INT DEFAULT 24,
                activo BOOLEAN DEFAULT TRUE
            )
        `);
        
        await connection.query(`
            CREATE TABLE IF NOT EXISTS ordenes_estudios (
                id_orden INT AUTO_INCREMENT PRIMARY KEY,
                id_paciente INT,
                id_medico INT,
                fecha_solicitud DATETIME DEFAULT CURRENT_TIMESTAMP,
                fecha_toma_muestra DATETIME,
                estado_order VARCHAR(50) DEFAULT 'Pendiente',
                observaciones TEXT,
                total DECIMAL(10,2) DEFAULT 0.00
            )
        `);
        
        // Insertar códigos por defecto
        await connection.query(`
            INSERT IGNORE INTO codigos_access (codigo, tipo_usuario) VALUES
            ('ADMIN', 'ADMIN'),
            ('MED', 'MEDICO'),
            ('AUDITOR', 'AUDITOR'),
            ('INV', 'INVESTIGADOR'),
            ('PACIENTE', 'PACIENTE'),
            ('LAB', 'LABORATORISTA')
        `);
        
        // Crear usuario admin por defecto
        const adminHash = await bcrypt.hash('Admin123!', 12);
        await connection.query(`
            INSERT IGNORE INTO usuarios (nombre_usuario, password_hash, tipo_usuario) 
            VALUES ('admin', ?, 'ADMIN')
        `, [adminHash]);
        
        connection.release();
        
        res.json({
            success: true,
            message: 'Base de datos inicializada',
            usuario_admin: 'admin / Admin123!',
            codigos_disponibles: ['ADMIN', 'MED', 'AUDITOR', 'INV', 'PACIENTE', 'LAB']
        });
        
    } catch (err) {
        console.error('Error inicializando DB:', err);
        res.status(500).json({
            error: 'Error al inicializar la base de datos',
            details: err.message
        });
    }
});

// ===== INFO DE CONEXIÓN =====
app.get('/db-info', async (req, res) => {
    try {
        const connection = await pool.getConnection();
        const [dbInfo] = await connection.query('SELECT DATABASE() as db, USER() as user');
        const [tables] = await connection.query('SHOW TABLES');
        connection.release();
        
        res.json({
            database: dbInfo[0].db,
            user: dbInfo[0].user,
            tables: tables.map(t => Object.values(t)[0]),
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ===== MANEJO DE ERRORES =====
app.use((req, res) => {
    res.status(404).send(`
        <div style="padding: 2rem; text-align: center;">
            <h2>404 - Página no encontrada</h2>
            <p>La página que buscas no existe.</p>
            <a href="/index.html">Volver al inicio</a>
        </div>
    `);
});

app.use((err, req, res, next) => {
    console.error('Error no manejado:', err);
    res.status(500).send(`
        <div style="padding: 2rem; text-align: center;">
            <h2>Error del servidor</h2>
            <p>Ha ocurrido un error inesperado.</p>
            <a href="/index.html">Volver al inicio</a>
        </div>
    `);
});

// ===== INICIAR SERVIDOR =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`
    🚀 SERVIDOR BIOMÉDICO INICIADO
    ================================
    
    🌐 URL: http://localhost:${PORT}
    
    📍 RUTAS PRINCIPALES:
    🔐 Login:        http://localhost:${PORT}/login.html
    📝 Registro:     http://localhost:${PORT}/registro.html
    🏠 Dashboard:    http://localhost:${PORT}/
    👑 Admin:        http://localhost:${PORT}/admin.html
    
    🗄️  RUTAS DE CONFIGURACIÓN:
    • Ver DB info:   http://localhost:${PORT}/db-info
    • Inicializar:   http://localhost:${PORT}/init-db
    
    👤 Usuario MySQL: estudios / biomedica
    🗃️  Base de datos: ${process.env.DB_NAME || 'lab_estudios'}
    
    `);
});
