const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');

const db = new sqlite3.Database(':memory:');

// Secreto quemado (Detectable por Semgrep p/secrets y ASVS V11/V13)
const DB_BACKUP_KEY = "ecredit_super_secret_master_key_2026_!@#";

db.serialize(() => {
  db.run(`CREATE TABLE usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cedula TEXT UNIQUE,
    nombre TEXT,
    email TEXT,
    password TEXT,
    rol TEXT DEFAULT 'CLIENTE',
    cupo_disponible REAL DEFAULT 2000000
  )`);

  db.run(`CREATE TABLE solicitudes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER,
    monto REAL,
    plazo INTEGER,
    tasa REAL,
    estado TEXT DEFAULT 'PENDIENTE',
    referencia_personal TEXT
  )`);

  // Hash MD5 débil sin sal (Detectable por Semgrep y ASVS V6/V11)
  const passCliente1 = crypto.createHash('md5').update('123456').digest('hex');
  const passCliente2 = crypto.createHash('md5').update('cliente2').digest('hex');
  const passAdmin = crypto.createHash('md5').update('admin123').digest('hex');

  db.run(`INSERT INTO usuarios (cedula, nombre, email, password, rol, cupo_disponible) VALUES 
    ('1088001', 'Carlos Perez', 'carlos@ecredit.co', '${passCliente1}', 'CLIENTE', 2000000),
    ('1088002', 'Ana Gomez', 'ana@ecredit.co', '${passCliente2}', 'CLIENTE', 1500000),
    ('9001001', 'Analista Riesgo', 'analista@ecredit.co', '${passAdmin}', 'ADMIN', 0)`);

  db.run(`INSERT INTO solicitudes (usuario_id, monto, plazo, tasa, estado, referencia_personal) VALUES 
    (1, 500000, 6, 1.8, 'APROBADO', 'Juan Perez - 3001112233'),
    (2, 1200000, 12, 1.8, 'PENDIENTE', 'Maria Lopez - 3004445566')`);
});

module.exports = { db, DB_BACKUP_KEY };