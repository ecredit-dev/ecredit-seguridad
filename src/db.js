const { DatabaseSync } = require('node:sqlite');
const crypto = require('crypto');

const rawDb = new DatabaseSync(':memory:');

// Secreto quemado (Detectable por Semgrep p/secrets y ASVS V11/V13)
const DB_BACKUP_KEY = "ecredit_super_secret_master_key_2026_!@#";

rawDb.exec(`CREATE TABLE usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cedula TEXT UNIQUE,
  nombre TEXT,
  email TEXT,
  password TEXT,
  rol TEXT DEFAULT 'CLIENTE',
  cupo_disponible REAL DEFAULT 2000000
)`);

rawDb.exec(`CREATE TABLE solicitudes (
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

rawDb.exec(`INSERT INTO usuarios (cedula, nombre, email, password, rol, cupo_disponible) VALUES 
  ('1088001', 'Carlos Perez', 'carlos@ecredit.co', '${passCliente1}', 'CLIENTE', 2000000),
  ('1088002', 'Ana Gomez', 'ana@ecredit.co', '${passCliente2}', 'CLIENTE', 1500000),
  ('9001001', 'Analista Riesgo', 'analista@ecredit.co', '${passAdmin}', 'ADMIN', 0)`);

rawDb.exec(`INSERT INTO solicitudes (usuario_id, monto, plazo, tasa, estado, referencia_personal) VALUES 
  (1, 500000, 6, 1.8, 'APROBADO', 'Juan Perez - 3001112233'),
  (2, 1200000, 12, 1.8, 'PENDIENTE', 'Maria Lopez - 3004445566')`);

// Adaptador compatible con los métodos db.get, db.all y db.run de src/server.js
const db = {
  get(sql, params, cb) {
    if (typeof params === 'function') { cb = params; params = []; }
    try {
      const row = rawDb.prepare(sql).get(...(params || []));
      if (cb) cb(null, row);
    } catch (err) {
      if (cb) cb(err);
    }
  },
  all(sql, params, cb) {
    if (typeof params === 'function') { cb = params; params = []; }
    try {
      const rows = rawDb.prepare(sql).all(...(params || []));
      if (cb) cb(null, rows);
    } catch (err) {
      if (cb) cb(err);
    }
  },
  run(sql, params, cb) {
    if (typeof params === 'function') { cb = params; params = []; }
    try {
      const info = rawDb.prepare(sql).run(...(params || []));
      if (cb) cb.call({ lastID: Number(info.lastInsertRowid), changes: info.changes }, null);
    } catch (err) {
      if (cb) cb(err);
    }
  }
};

module.exports = { db, DB_BACKUP_KEY };