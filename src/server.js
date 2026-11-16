const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { db } = require('./db');

const app = express();
app.use(express.json());

// Llave JWT débil hardcodeada (ASVS V9 / V13)
const JWT_SECRET = 'clave_secreta_ecredit_123';

// Middleware de autenticación sin validación estricta de algoritmos/expiración
function autenticar(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });

  const token = authHeader.split(' ')[1];
  try {
    // Vulnerabilidad: no restringe algorithms ni valida issuer/audience (ASVS V9)
    const decoded = jwt.decode(token); 
    if (!decoded) return res.status(401).json({ error: 'Token inválido' });
    req.user = decoded;
    next();
  } catch (err) {
    // Exposición de traza de error (ASVS V13 / ZAP)
    res.status(500).json({ error: err.message, stack: err.stack });
  }
}

// 1. Endpoint de Login (Sin Rate Limiting - Amenaza T5 / t-06)
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const hash = crypto.createHash('md5').update(password || '').digest('hex');

  // Vulnerabilidad SQL Injection por concatenación (Amenaza t-09 / Semgrep)
  const query = `SELECT id, cedula, nombre, email, rol, cupo_disponible FROM usuarios WHERE email = '${email}' AND password = '${hash}'`;

  db.get(query, (err, user) => {
    if (err) return res.status(500).json({ error: err.message, stack: err.stack });
    if (!user) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });

    // Token sin expiración 'exp' (ASVS V9)
    const token = jwt.sign({ id: user.id, email: user.email, rol: user.rol }, JWT_SECRET);
    res.json({ mensaje: 'Login exitoso', token, usuario: user });
  });
});

// 2. Registro de usuario (Vulnerable a Mass Assignment - Amenaza T3 / t-05)
app.post('/api/usuarios', (req, res) => {
  // Vulnerabilidad: acepta 'rol' y 'cupo_disponible' directamente desde el cliente
  const { cedula, nombre, email, password, rol, cupo_disponible } = req.body;
  const hash = crypto.createHash('md5').update(password || '').digest('hex');
  const rolFinal = rol || 'CLIENTE';
  const cupoFinal = cupo_disponible || 2000000;

  db.run(
    `INSERT INTO usuarios (cedula, nombre, email, password, rol, cupo_disponible) VALUES (?, ?, ?, ?, ?, ?)`,
    [cedula, nombre, email, hash, rolFinal, cupoFinal],
    function (err) {
      if (err) return res.status(400).json({ error: err.message });
      res.status(201).json({ id: this.lastID, cedula, nombre, email, rol: rolFinal, cupo_disponible: cupoFinal });
    }
  );
});

// 3. Consulta de solicitud por ID (Vulnerable a IDOR / BOLA - Amenaza T1 / t-04)
app.get('/api/solicitudes/:id', autenticar, (req, res) => {
  const solicitudId = req.params.id;

  // Vulnerabilidad: No filtra por req.user.id (cualquier usuario ve cualquier solicitud)
  db.get(`SELECT * FROM solicitudes WHERE id = ?`, [solicitudId], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'Solicitud no encontrada' });
    res.json(row);
  });
});

// 4. Crear y evaluar solicitud de crédito (Vulnerable a Manipulación de tasa/monto T4 y Race Condition T2)
app.post('/api/solicitudes', autenticar, (req, res) => {
  // Vulnerabilidad T4: Confía en la tasa y monto enviados por el frontend sin recalcular
  const { monto, plazo, tasa, referencia_personal } = req.body;

  // Vulnerabilidad T2 (Lógica de negocio): Lee cupo sin bloqueo transaccional (Race Condition)
  db.get(`SELECT cupo_disponible FROM usuarios WHERE id = ?`, [req.user.id], (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'Usuario no válido' });

    if (monto > user.cupo_disponible) {
      return res.status(400).json({ error: 'El monto supera su cupo disponible' });
    }

    db.run(
      `INSERT INTO solicitudes (usuario_id, monto, plazo, tasa, estado, referencia_personal) VALUES (?, ?, ?, ?, 'APROBADO', ?)`,
      [req.user.id, monto, plazo, tasa, referencia_personal],
      function (errInsert) {
        if (errInsert) return res.status(500).json({ error: errInsert.message });

        // Descuento diferido susceptible a condiciones de carrera
        db.run(`UPDATE usuarios SET cupo_disponible = cupo_disponible - ? WHERE id = ?`, [monto, req.user.id]);
        res.status(201).json({ id: this.lastID, estado: 'APROBADO', monto, tasa });
      }
    );
  });
});

// 5. Endpoint de salud / listado sin paginación (ASVS V4)
app.get('/api/solicitudes', autenticar, (req, res) => {
  db.all(`SELECT * FROM solicitudes`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

const PORT = process.env.PORT || 4000;
if (require.main === module) {
  app.listen(PORT, '127.0.0.1', () => {
    console.log(`API E-Credit corriendo en http://127.0.0.1:${PORT}`);
  });
}

module.exports = app;