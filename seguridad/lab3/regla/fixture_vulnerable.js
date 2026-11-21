// Caso 1: Vulnerable (IDOR - consulta solicitud sin validar usuario_id)
function obtenerSolicitudInsegura(db, req, res) {
  // ruleid: ecredit-asvs-v8-2-1-idor-solicitudes
  db.get('SELECT * FROM solicitudes WHERE id = ?', [req.params.id], (err, row) => {
    res.json(row);
  });
}