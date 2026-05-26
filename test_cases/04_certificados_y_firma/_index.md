# 04 — Certificados y Firma Digital

Casos de prueba para el ciclo de vida de certificados X.509, la carga del archivo .key, validación de firma digital y el middleware de expiración.

| Roles | Descripción | Metodología | ID caso |
|---|---|---|---|
| Administrador | Ingresar firma con archivo .key válido y passphrase correcta. Verificar mensaje de éxito, que `llave_privada_firma` se guarda en sesión y que `tiempo_firma_reciente` se establece con timestamp actual. | Login — Ingresar Firma | |
| Coordinador | Ingresar firma con archivo .key válido y passphrase correcta. Verificar que el módulus de la llave privada coincide con el del certificado X.509 registrado. | Login — Ingresar Firma | |
| Coordinador | Ingresar firma con passphrase incorrecta. Verificar mensaje de error "Error al validar la firma." | Login — Ingresar Firma | |
| Coordinador | Ingresar firma con archivo .key que no corresponde al certificado del usuario (módulus diferente). Verificar mensaje "La llave no corresponde a tu certificado actual." | Login — Ingresar Firma | |
| Coordinador | Ingresar firma sin subir archivo. Verificar mensaje "Debes subir tu archivo .key y proporcionar la contraseña." | Login — Ingresar Firma | |
| Coordinador | Ingresar firma sin proporcionar passphrase. Verificar mensaje de validación. | Login — Ingresar Firma | |
| Coordinador | Ingresar firma con archivo que no es un .key válido (archivo corrupto o formato incorrecto). Verificar mensaje de error descriptivo. | Login — Ingresar Firma | |
| Operativo | Intentar acceder a Ingresar Firma como Operativo. Verificar redirect al Dashboard con mensaje "Tu rol no requiere ni tiene permisos para usar firma digital." | Login — Ingresar Firma (acceso directo por URL) | |
| Usuario | Intentar acceder a Ingresar Firma como Usuario. Verificar redirect al Dashboard con mensaje "Tu rol no requiere ni tiene permisos para usar firma digital." | Login — Ingresar Firma (acceso directo por URL) | |
| Coordinador | Intentar operación crítica (editar expediente) sin haber cargado .key. Verificar redirect a Ingresar Firma con mensaje informativo. | Login — Lista Expedientes — Editar expediente | |
| Coordinador | Intentar operación crítica después de que la firma expiró (>15 minutos). Verificar redirect a Ingresar Firma con indicación de re-validar. | Login — Ingresar Firma — (esperar 15 min) — Editar expediente | |
| Coordinador | Verificar que tras ingresar la firma, el redirect `?next=` lleva de vuelta a la operación original que requería firma. | Login — Editar expediente — Ingresar Firma — Redirect automático a Editar | |
| Administrador | Regenerar identidad criptográfica de un Coordinador. Verificar que se genera nuevo certificado X.509 firmado por el Admin, nuevo .key, nuevo ZIP descargable, y que la fecha de expiración se actualiza a +1 año. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Criptografía — Regenerar identidad | |
| Administrador | Regenerar identidad de un usuario con rol Usuario u Operativo. Verificar mensaje "Los roles Usuario y Operativo no usan certificados de firma." | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Criptografía — Regenerar identidad | |
| Administrador | Revocar certificado de un usuario Coordinador. Verificar que `certificado_digital` y `fecha_expiracion_certificado` se establecen en null y se registra en bitácora. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Revocar certificado | |
| Coordinador | Verificar que el middleware `CertificadoExpiracionMiddleware` bloquea el acceso (force logout) cuando el certificado del Coordinador ha expirado. Verificar mensaje de sesión bloqueada. | Login (con certificado expirado) — Cualquier ruta | |
| Administrador | Verificar que el middleware bloquea el acceso cuando el Admin no tiene certificado digital (campo null). | Login (sin certificado) — Cualquier ruta | |
| Operativo | Verificar que el middleware NO bloquea el acceso para roles Operativo (no requieren certificado). | Login — Dashboard | |
| Usuario | Verificar que el middleware NO bloquea el acceso para roles Usuario (no requieren certificado). | Login — Dashboard | |
| Administrador | Verificar que el middleware excluye las rutas de Login y Logout del chequeo de certificado. | Login — Logout (con certificado expirado) | |
| Administrador | Verificar visualización de badges de seguridad en Admin Panel: "🔑 OK / NO" para llaves RSA y "📜 OK / EXP / NO" para certificado. | Login — Ingresar Firma — Admin Panel (tab Usuarios) | |
| Coordinador | Verificar que el certificado X.509 generado muestra correctamente `issuer=CN:admin_username` y `subject=CN:coordinador_username` (jerarquía SAT). | Login — Ingresar Firma — Admin Panel — Crear Coordinador — Inspeccionar certificado | |
