// Caso 1: Vulnerable (IDOR - consulta solicitud sin validar usuario_id)
function obtenerSolicitudInsegura(db, req, res) {
  // ruleid: ecredit-asvs-v8-2-1-idor-solicitudes
  db.get('SELECT * FROM solicitudes WHERE id = ?', [req.params.id], (err, row) => {
    res.json(row);
  });
}

// Caso 2: Seguro (ASVS V8.2.1 - filtra estrictamente por usuario_id autenticado)
function obtenerSolicitudSegura(db, req, res) {
  // ok: ecredit-asvs-v8-2-1-idor-solicitudes
  db.get('SELECT * FROM solicitudes WHERE id = ? AND usuario_id = ?', [req.params.id, req.user.id], (err, row) => {
    res.json(row);
  });
}