const test = require('node:test');
const assert = require('node:assert');
const app = require('../src/server');

async function iniciarServidor() {
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      resolve({ server, port: server.address().port });
    });
  });
}

test('Prueba funcional: login exitoso retorna token JWT', async () => {
  const { server, port } = await iniciarServidor();
  try {
    const res = await fetch(`http://127.0.0.1:${port}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'carlos@ecredit.co', password: '123456' })
    });
    const data = await res.json();
    assert.strictEqual(res.status, 200);
    assert.ok(data.token);
  } finally {
    server.closeAllConnections();
    server.close();
  }
});

test('Seguridad ASVS V8.2.1 / Lab 1 T1: Bloquear acceso IDOR a solicitud de otro usuario', async () => {
  const { server, port } = await iniciarServidor();
  try {
    // 1. Iniciar sesión como Carlos (usuario_id = 1)
    const loginRes = await fetch(`http://127.0.0.1:${port}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'carlos@ecredit.co', password: '123456' })
    });
    const { token } = await loginRes.json();

    // 2. Intentar consultar la solicitud id=2 que pertenece a Ana (usuario_id = 2)
    const resAjena = await fetch(`http://127.0.0.1:${port}/api/solicitudes/2`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    // Debe devolver 404 Not Found para no filtrar existencia ni datos ajenos
    assert.strictEqual(resAjena.status, 404, 'Un usuario no debe poder leer solicitudes de otro cliente');
  } finally {
    server.closeAllConnections();
    server.close();
  }
});