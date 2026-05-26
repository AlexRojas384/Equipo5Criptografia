# 03 — Roles y Permisos

Casos de prueba para el sistema RBAC: cambio de rol, permisos individuales, solicitudes de cambio de rol y su aprobación/rechazo.

| Roles | Descripción | Metodología | ID caso |
|---|---|---|---|
| Administrador | Cambiar rol de un usuario de Usuario a Operativo. Verificar que se actualizan los grupos de Django, se distribuye la llave de rol correspondiente y se registra en bitácora. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Cambiar rol | |
| Administrador | Cambiar rol de un usuario de Operativo a Coordinador. Verificar que se genera distribución de llave de rol Coordinador y el usuario puede descifrar expedientes tras re-login. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Cambiar rol | |
| Administrador | Cambiar rol de un usuario a Administrador. Verificar que se distribuyen TODAS las llaves de rol del sistema al nuevo admin. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Cambiar rol | |
| Administrador | Cambiar rol de Coordinador a Usuario. Verificar que se limpian los grupos de Django (el usuario pierde permisos de grupo). | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Cambiar rol | |
| Administrador | Intentar cambiar rol con un valor inválido (manipulación de formulario). Verificar mensaje "Rol inválido." | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Cambiar rol | |
| Administrador | Toggle de permiso individual: agregar permiso `puede_exportar_expediente` a un usuario que no lo tiene por rol. Verificar que aparece como "individual" en el panel de permisos. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Permisos — Toggle permiso | |
| Administrador | Toggle de permiso individual: quitar un permiso individual previamente agregado. Verificar que el permiso desaparece de la lista individual del usuario. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Permisos — Toggle permiso | |
| Administrador | Verificar que los permisos heredados del rol (marcados como "rol" en el panel) no pueden ser removidos individualmente — solo se muestran como informativos. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Permisos | |
| Administrador | Verificar la visualización correcta del panel de permisos expandible: badges azules para permisos de rol, badges verdes para permisos individuales. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Permisos | |
| Usuario | Solicitar cambio de rol desde la vista de solicitud. Verificar que se crea la solicitud con estado "pendiente" y se registra en bitácora. | Login — Dashboard — Solicitar cambio de rol | |
| Operativo | Solicitar cambio de rol con un rol que ya se posee. Verificar mensaje "Ya tienes ese rol." | Login — Dashboard — Solicitar cambio de rol | |
| Coordinador | Solicitar cambio de rol cuando ya existe una solicitud pendiente. Verificar mensaje "Ya tienes una solicitud pendiente." | Login — Dashboard — Solicitar cambio de rol | |
| Operativo | Solicitar cambio de rol con rol inválido (manipulación de formulario). Verificar mensaje "Rol inválido." | Login — Dashboard — Solicitar cambio de rol | |
| Usuario, Operativo, Coordinador | Verificar que el historial de solicitudes se muestra en la vista de solicitud (anteriores aprobadas, rechazadas y pendientes). | Login — Dashboard — Solicitar cambio de rol | |
| Administrador | Aprobar solicitud de cambio de rol. Verificar que el rol del solicitante se actualiza, se distribuyen llaves de rol, se registra en bitácora y la solicitud cambia a estado "aprobada". | Login — Ingresar Firma — Admin Panel (tab Solicitudes) — Aprobar | |
| Administrador | Rechazar solicitud de cambio de rol con respuesta textual. Verificar que la solicitud cambia a estado "rechazada" con respuesta del admin y se registra en bitácora. | Login — Ingresar Firma — Admin Panel (tab Solicitudes) — Rechazar | |
| Administrador | Verificar badge de notificación en tab "Solicitudes" cuando hay solicitudes pendientes. Verificar que el badge desaparece cuando no hay pendientes. | Login — Ingresar Firma — Admin Panel (tab Solicitudes) | |
| Administrador | Verificar badge de notificación en tarjeta "Gestionar usuarios" del Dashboard cuando hay solicitudes pendientes. | Login — Dashboard | |
| Administrador | Verificar que la pestaña "Solicitar cambio de rol" NO aparece en el Dashboard para el Administrador. | Login — Dashboard | |
| Usuario, Operativo, Coordinador | Verificar que la pestaña "Solicitar cambio de rol" SÍ aparece en el Dashboard para roles no-Admin. | Login — Dashboard | |
