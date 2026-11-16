const test = require('node:test');
const assert = require('node:assert');
const app = require('../src/server');

test('Prueba funcional básica: el servidor responde al login', async () => {
  const server = app.listen(0, '127.0.0.1');
  const port = server.address().port;

  try {
    const res = await fetch(`http://127.0.0.1:${port}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'carlos@ecredit.co', password: '123456' })
    });
    const data = await res.json();
    assert.strictEqual(res.status, 200);
    assert.ok(data.token, 'Debe retornar un token JWT');
  } finally {
    server.close();
  }
});