# Proyecto integrador – Plantilla

## Equipo

- Integrantes: Equipo E Credit (`ecredit-dev`) — Dawian Stiven Arce Velásquez, Samuel Vera, Jhon Barrios
- Repositorio del proyecto: `https://github.com/ecredit-dev/ecredit-seguridad`

## 1. Contexto (entregable 1)

- **Aplicación y propósito:** **E Credit**, aplicación web y API REST en Node.js/Express (`src/server.js`) con persistencia en SQLite (`src/db.js`) diseñada para la gestión y consulta de solicitudes de crédito de bajo monto, autenticación de usuarios mediante JWT y validación de estado de trámites financieros.
- **Usuarios y datos que maneja (¿datos personales? ¿financieros?):**
  - *Usuarios:* Solicitantes de crédito (clientes) y analistas/administradores internos.
  - *Datos personales (PII):* Nombres, correo electrónico, número de identificación/cédula, teléfono y credenciales de acceso (hashes de contraseña).
  - *Datos financieros:* Monto solicitado, plazo, estado de aprobación/rechazo de la solicitud de crédito e historial asociado al `usuario_id`.
- **Obligaciones normativas aplicables (Ley 1581, ISO/IEC 27001, CRA, sector):**
  - **Ley 1581 de 2012 (Colombia):** Protección de datos personales, principio de seguridad, confidencialidad y autorización explícita del titular para el tratamiento de datos personales y crediticios.
  - **ISO/IEC 27001:** Controles de gestión de acceso, desarrollo seguro (SDLC), gestión de vulnerabilidades técnicas y protección de secretos/criptografía.
  - **Normativa sectorial / Fintech (Superintendencia Financiera / Circular Básica Jurídica - ciberseguridad):** Trazabilidad, control de acceso a nivel de objeto y prevención de fraude o divulgación no autorizada de información crediticia.
- **Diagrama de arquitectura (adjuntar imagen):** Documentado en el modelo de amenazas del repositorio (`seguridad/lab1/`), representando el flujo entre el cliente HTTP externo, la frontera de la API REST (`src/server.js`), la capa de acceso a datos (`src/db.js`) y el pipeline de integración continua en GitHub Actions.

## 2. Modelo de amenazas (entregable 1)

- **Archivo de OWASP Threat Dragon:** `seguridad/lab1/ecredit-threat-model.json`
- **Límites de confianza identificados:**
  1. **Internet / Cliente no confiable $\rightarrow$ API E Credit (`src/server.js`):** Peticiones HTTP entrantes donde parámetros de ruta (`req.params.id`), query (`req.query`) y cabeceras `Authorization` pueden ser manipulados por un atacante autenticado o anónimo.
  2. **API E Credit (`src/server.js`) $\rightarrow$ Base de datos SQLite (`src/db.js`):** Consultas SQL que requieren parametrización estricta y validación de propiedad (`usuario_id`) antes de devolver registros.
  3. **Desarrollador / Rama `feature/*` $\rightarrow$ Rama protegida `main` (GitHub Actions / Auditgate):** Frontera de despliegue protegida por controles automatizados de seguridad antes de integrar código a producción.
- **Amenazas STRIDE priorizadas:**

| ID | Amenaza | Categoría STRIDE | Impacto | Probabilidad | Requisito ASVS |
|---|---|---|---|---|---|
| T1 (`t-04`) | **IDOR en consulta de solicitudes de crédito:** Un usuario autenticado altera el identificador `id` en la petición y accede a los datos financieros de la solicitud de otro cliente porque la consulta filtra por `id` sin verificar `usuario_id`. | Information Disclosure / Elevation of Privilege | Alto | Alta | V8.2.1 |
| T2 (`t-02`) | **Inyección de código / comandos o SQLi por entradas no sanitizadas:** Manipulación de parámetros de entrada en endpoints de diagnóstico o consulta que alcanza intérpretes del sistema (`child_process.exec`) o consultas dinámicas. | Tampering / Elevation of Privilege | Crítico | Media | V1.2 / V5.3 |
| T3 (`t-01`) | **Falsificación de identidad por secretos débiles o expuestos:** Compromiso del `JWT_SECRET` quemado en código (`src/server.js:43`) o filtración de llaves API en commits. | Spoofing / Information Disclosure | Alto | Media | V6.4 / V2.1 |
| T4 (`t-03`) | **Exposición de datos sensibles en tránsito o respuestas excesivas:** Retorno de campos internos o credenciales en respuestas JSON de endpoints de consulta. | Information Disclosure | Medio | Media | V8.3 / V9.1 |

## 3. Requisitos y controles

| Requisito ASVS 5.0 | Control implementado | Evidencia (commit, prueba) | Estado |
|---|---|---|---|
| **V8.2.1** (Autorización a nivel de objeto / prevención de IDOR) | Validación obligatoria de titularidad (`WHERE id = ? AND usuario_id = ?`) en consultas de solicitudes y creación de la regla SAST personalizada `ecredit-asvs-v8-2-1-idor-solicitudes` en Semgrep para bloquear consultas sin filtro por `usuario_id`. | `seguridad/lab3/regla/ecredit-idor-solicitudes.yml`, `seguridad/lab3/regla/ecredit-idor-solicitudes.js`, `fixture_vulnerable.js`, `fixture_seguro.js` (`semgrep --test` $\rightarrow$ `All tests passed`) y `tests/seguridad.test.js` | Implementado y verificado |
| **V5.3.8 / V1.2** (Prevención de inyección de comandos y sanitización de entradas) | Uso de consultas parametrizadas (`?`) en `src/db.js` y bloqueo determinista mediante Auditgate + Semgrep frente a sumideros peligrosos (`child_process.exec`). | Bloqueo en **PR #2** (`feature/falla-demo`) por `auditgate.node.command-injection-child-process` y remediación verificada en el segundo commit del PR #2 | Implementado y verificado |
| **V6.4 / V2.10** (Gestión segura de secretos y credenciales) | Escaneo automático de secretos en cada PR mediante Gitleaks en Auditgate y protección nativa de Push Protection en GitHub (rechazo `GH013` ante llaves expuestas). | Workflow `.github/workflows/auditgate.yml` (`Secrets` check en verde en PR #2) y bloqueo local/remoto ante tokens de prueba | Implementado y verificado |
| **V14.2** (Verificación de dependencias de terceros) | Análisis continuo de vulnerabilidades conocidas (CVE) en paquetes `npm` mediante OSV-Scanner integrado en el gate del pipeline. | Job `Dependencies` ejecutado en `.github/workflows/auditgate.yml` (`All checks have passed` en PR #2) | Implementado y verificado |

## 4. Pipeline DevSecOps (entregable 2)

- **Workflow de GitHub Actions:** `.github/workflows/auditgate.yml` (ejecución automática en cada `pull_request` hacia `main` utilizando Auditgate en modo determinista).
- **Etapas configuradas:**
  - **Secretos (`Secrets`):** Ejecuta **Gitleaks** sobre el diff del PR para bloquear cualquier credencial, token o llave privada nueva.
  - **SAST (`SAST`):** Ejecuta **Semgrep** con las reglas base para JavaScript/Node.js más las reglas personalizadas del proyecto (`seguridad/lab3/regla/`), bloqueando hallazgos nuevos de severidad alta/error.
  - **SCA (`Dependencies`):** Ejecuta **OSV-Scanner** sobre `package-lock.json` para detectar dependencias con vulnerabilidades conocidas introducidas en el PR.
  - **DAST:** Análisis dinámico ejecutado con OWASP ZAP sobre la aplicación en ejecución (`seguridad/lab2/zap.yaml` y reporte `seguridad/lab2/zap.html`).
  - **IaC / Imágenes (`Container`):** Evaluados condicionalmente por Auditgate (se omiten automáticamente —`Skipped`— cuando el PR no modifica archivos de infraestructura o contenedores).
  - **SBOM / Firma:** Trazabilidad de artefactos y fijación de acciones de GitHub por SHA verificada por Auditgate (`actions auditgate fijadas por SHA`).
- **Políticas de bloqueo:**
  - **Branch Protection en `main`:** Configurado en GitHub exigiendo Pull Request antes de fusionar y marcando **`Auditgate / auditgate / Security Gate (pull_request)`** como **Required**.
  - **Comportamiento diferencial (Merge-Base):** El gate evalúa únicamente los hallazgos nuevos respecto a `main`, bloqueando el botón *Merge pull request* (`Merging is blocked`) si se introduce una vulnerabilidad nueva —como se demostró en el **PR #2** (`feature/falla-demo`)— y habilitándolo (`All checks have passed`) una vez corregida.

## 5. Informe final

- **Checklist ASVS L1 (adjuntar):** Documentado en `seguridad/lab2/ASVS.md` junto con el análisis de hallazgos en `seguridad/lab2/TRIAGE.md`.
- **Riesgos residuales:**
  1. **Deuda técnica preexistente en `main`:** El `JWT_SECRET` quemado en `src/server.js:43` (identificado en Lab 2) permanece como riesgo residual en la rama base porque Auditgate solo bloquea regresiones nuevas en el diff del PR.
  2. **Reglas SAST limitadas a patrones sintácticos conocidos:** Aunque la regla `ecredit-asvs-v8-2-1-idor-solicitudes` cubre consultas directas a `solicitudes`, consultas dinámicas complejas o nuevos modelos requieren ampliar las reglas personalizadas y pruebas de integración.
  3. **Revisión manual en Branch Protection:** Requiere mantener disciplina en la aprobación de PRs y evitar el uso de la opción administrativa *bypass rules*.
- **Plan de remediación priorizado:**
  1. **Prioridad 1 (Inmediata — Crítica):** Externalizar el `JWT_SECRET` y cualquier secreto de configuración de `src/server.js` hacia variables de entorno (`process.env.JWT_SECRET`) y rotar la llave en todos los entornos.
  2. **Prioridad 2 (Corto plazo — Alta):** Integrar la carpeta `seguridad/lab3/regla/` directamente en la configuración de Semgrep dentro de `.github/workflows/auditgate.yml` para que cada PR ejecute automáticamente la regla anti-IDOR junto con las reglas estándar, y ampliar `tests/seguridad.test.js` con pruebas negativas de autorización.
  3. **Prioridad 3 (Mediano plazo — Media):** Automatizar la ejecución de OWASP ZAP (DAST) en un entorno de staging previo a producción y corregir las cabeceras HTTP de seguridad reportadas en `seguridad/lab2/zap.html`.
- **Recomendaciones al negocio:**
  - Mantener el `Security Gate` como requisito obligatorio e innegociable en todos los repositorios de E Credit: frena vulnerabilidades críticas (como IDOR o inyección de comandos) antes de producción sin detener el flujo de negocio por deuda histórica.
  - Exigir que cada nueva historia de usuario que manipule datos financieros o personales incluya su caso de prueba de autorización (usuario A intentando acceder a recursos del usuario B) antes de aprobar el PR.

## 6. Seguridad de IA y gobernanza (sesión 5)

- **¿El proyecto usa IA? ¿Dónde (chatbot, agente, clasificación, generación)?:**
  - En su versión actual (`src/server.js`), el núcleo transaccional de E Credit **no ejecuta un LLM en producción** (utiliza lógica determinista y reglas de negocio en Node.js), aunque se emplea asistencia de IA en el flujo de ingeniería (triage advisory de Auditgate y desarrollo asistido) y se proyecta un asistente de orientación crediticia para clientes. Por ello, se establece formalmente la **política de uso seguro y gobernanza de IA** del proyecto:
- **Modelo de amenazas del componente de IA** (marquen lo aplicable):
  - [x] **Prompt injection (directa / indirecta)** — *¿qué contenido no confiable llega al modelo?:* Campos de texto libre ingresados por solicitantes (motivo del crédito, observaciones, documentos adjuntos) o comentarios en PRs/issues analizados durante el triage asistido.
  - [x] **Manejo inseguro de la salida (LLM05)** — *¿la salida entra a un intérprete, DB o HTML?:* Cualquier respuesta generada por un modelo se trata como texto no confiable; queda prohibido concatenar salidas de un LLM directamente en consultas SQL (`src/db.js`), comandos del sistema (`child_process`) o renderizado HTML sin escape.
  - [x] **Agencia excesiva (LLM06)** — *¿qué herramientas y permisos tiene el agente?:* Ningún asistente o agente tiene permisos de escritura directa sobre la base de datos de créditos, aprobación de desembolsos ni capacidad de hacer `merge` automático a `main`.
  - [x] **Fuga de datos sensibles (LLM02)** — *¿qué datos salen en el prompt?:* Riesgo de exposición de cédulas, correos, historial crediticio de clientes o secretos del código (`JWT_SECRET`, API keys) hacia proveedores externos de modelos.
- **Guardarraíles aplicados** (entrada / ejecución / salida):
  - *Entrada:* Validación estricta de esquemas y tipos de datos en la API, delimitación clara entre instrucciones del sistema y datos del usuario, y bloqueo de secretos mediante Gitleaks antes de cualquier análisis.
  - *Ejecución:* Controles deterministas obligatorios en el pipeline (`Security Gate` con Semgrep, Gitleaks y OSV-Scanner) como autoridad final de bloqueo; las sugerencias de IA (*AI triage advisory*) son únicamente informativas y nunca sustituyen un check determinista.
  - *Salida:* Parametrización obligatoria (`?`) en todas las consultas SQL, validación de formato JSON estricto en respuestas y filtrado de datos internos antes de responder al cliente.
- **Human-in-the-loop:**
  - Toda decisión crítica o irreversible requiere aprobación humana explícita: (1) aprobación o rechazo final de solicitudes de crédito, (2) fusión (*merge*) de Pull Requests hacia `main`, (3) modificación de reglas de protección de rama o políticas del `Security Gate`, y (4) rotación o despliegue de secretos en producción.
- **Gobernanza:**
  - *Procedencia y acceso:* Uso exclusivo de proveedores/modelos autorizados por el equipo con autenticación mediante tokens efímeros (OIDC en GitHub Actions) y prohibición absoluta de llaves de API de larga vida en el código fuente.
  - *Retención y auditoría:* Desactivación del entrenamiento con datos del proyecto en herramientas de IA, sin retención de prompts con datos de negocio y trazabilidad completa de cambios mediante historial de commits, PRs y logs de GitHub Actions.
- **Minimización de datos:**
  - En cumplimiento de la **Ley 1581 de 2012**, está prohibido incluir PII real (nombres completos, cédulas, teléfonos, correos) o registros financieros reales en prompts de prueba o desarrollo; todas las pruebas y fixtures (`fixture_vulnerable.js`, `fixture_seguro.js`, `tests/seguridad.test.js`) utilizan exclusivamente identificadores y datos sintéticos.