# Laboratorio 3 · Gate de Seguridad en el Pipeline (Auditgate)

## Reflexión: ¿Qué vio el gate y qué vio el triage?

1. **¿Qué hallazgo bloqueó el gate que una persona habría dejado pasar?**
   En el PR #2 (`feature/falla-demo`), el gate bloqueó de forma determinista una inyección de comandos (`child_process.exec` concatenando `req.query.host`) que en una revisión manual rápida puede pasarse por alto cuando va mezclada con código funcional.

2. **¿El triage acertó en el verdadero/falso positivo?**
   Sí: el hallazgo nuevo detectado en el diff era un verdadero positivo alcanzable en el endpoint recién introducido (`/api/debug/ping`). Tras eliminar el código inseguro en el segundo commit del PR #2, los checks pasaron a verde (`All checks have passed`).

3. **¿Qué deuda vieja dejó pasar el gate por no ser nueva (y por qué está bien)?**
   Dejó pasar hallazgos preexistentes en `main` (como el `JWT_SECRET` quemado en `src/server.js:43` identificado en el Lab 2) porque Auditgate evalúa únicamente el diff respecto al `merge-base`. Esto permite frenar de inmediato vulnerabilidades nuevas sin paralizar las entregas del equipo por deuda técnica acumulada.

## Trazabilidad de la Regla Personalizada
- **Amenaza Lab 1:** T1 (`t-04`) — IDOR en consulta de solicitudes de crédito
- **Requisito ASVS 5.0:** V8.2.1 (Autorización a nivel de objeto)
- **Regla y Fixtures:** `seguridad/lab3/regla/ecredit-idor-solicitudes.yml` y `ecredit-idor-solicitudes.js` (junto con `fixture_vulnerable.js` y `fixture_seguro.js`), validados con `semgrep --test`.