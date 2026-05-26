# 07 — Auditoría

Casos de prueba para la bitácora de eventos, encadenamiento de hashes SHA-256 e integridad del registro.

| Roles | Descripción | Metodología | ID caso |
|---|---|---|---|
| Administrador | Verificar que el login genera un registro en BitacoraEvento con tipo='login', usuario correcto, IP del cliente y hash_registro calculado. | Login — Verificar BD (BitacoraEvento) | |
| Administrador | Verificar que el logout genera un registro con tipo='logout' y datos correctos. | Login — Logout — Verificar BD | |
| Administrador | Verificar que la creación de un expediente genera registro con tipo='verificacion_expediente' (o tipo correspondiente) con descripción del evento. | Login — Registrar migrante — Guardar — Verificar BD | |
| Administrador | Verificar que la edición de un expediente genera registro en bitácora con tipo='verificacion_expediente' y descripción "editó el expediente #N". | Login — Ingresar Firma — Ver expedientes — Editar — Guardar — Verificar BD | |
| Administrador | Verificar que la eliminación de un expediente genera registro con tipo='eliminar_expediente'. | Login — Ingresar Firma — Ver expedientes — Eliminar — Verificar BD | |
| Administrador | Verificar que la verificación de expedientes genera registro con tipo='verificacion_expediente' indicando cuántos fueron verificados. | Login — Ingresar Firma — Ver expedientes — Verificar batch — Verificar BD | |
| Administrador | Verificar que el cambio de rol genera registro con tipo='cambio_rol' y descripción con rol anterior y nuevo. | Login — Ingresar Firma — Admin Panel — Cambiar rol — Verificar BD | |
| Administrador | Verificar que el toggle de permiso genera registro con tipo='toggle_permiso' indicando el permiso y la acción (agregado/quitado). | Login — Ingresar Firma — Admin Panel — Toggle permiso — Verificar BD | |
| Administrador | Verificar que el toggle activo/inactivo genera registro con tipo='toggle_activo' indicando si fue activado o desactivado. | Login — Ingresar Firma — Admin Panel — Toggle activo — Verificar BD | |
| Usuario | Verificar que la creación de solicitud de rol genera registro con tipo='solicitud_creada'. | Login — Solicitar cambio de rol — Verificar BD | |
| Administrador | Verificar que la aprobación de solicitud genera registro con tipo='solicitud_aprobada'. | Login — Ingresar Firma — Admin Panel — Aprobar solicitud — Verificar BD | |
| Administrador | Verificar que el rechazo de solicitud genera registro con tipo='solicitud_rechazada'. | Login — Ingresar Firma — Admin Panel — Rechazar solicitud — Verificar BD | |
| Administrador | Verificar encadenamiento de hashes: el hash_registro de cada evento se calcula como SHA-256 del hash anterior concatenado con usuario_id, tipo, descripción y fecha. | Verificar BD — Recalcular cadena de hashes | |
| Administrador | Verificar que el primer registro usa 'GENESIS' como hash previo para iniciar la cadena. | Verificar BD — Primer registro de BitacoraEvento | |
| Administrador | Verificar integridad de la cadena: simular modificación de un registro intermedio y confirmar que la verificación de cadena detecta la manipulación. | Verificar BD — Alterar registro — Recalcular cadena | |
| Administrador | Verificar que la pestaña "Bitácora" del Admin Panel muestra los últimos 20 eventos con íconos por tipo, descripción, fecha e IP. | Login — Ingresar Firma — Admin Panel (tab Bitácora) | |
| Administrador | Verificar que los eventos muestran íconos diferenciados por tipo (colores distintos para login, logout, cambio_rol, toggle, solicitudes). | Login — Ingresar Firma — Admin Panel (tab Bitácora) | |
| Administrador | Verificar que el cambio de contraseña propio genera registro con tipo='cambio_rol' (reusa tipo) con descripción "cambió su contraseña". | Login — Cambiar contraseña — Verificar BD | |
| Administrador | Verificar que el reset de contraseña por admin genera registro con tipo='cambio_rol' con descripción "Reseteó contraseña y llaves de login para username". | Login — Ingresar Firma — Admin Panel — Reset password — Verificar BD | |
