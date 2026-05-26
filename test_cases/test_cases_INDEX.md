# Índice Maestro de Casos de Prueba — Casa Monarca

> Documento generado automáticamente por `merge_indexes.py`.
> Contiene todos los casos de prueba del sistema organizados por categoría.
>
> **Sistema:** Plataforma de gestión segura de expedientes para Casa Monarca
> **Arquitectura de Seguridad:** Doble Llave (Login Key + Firma SAT)
> **Roles:** Administrador, Coordinador (5 tipos), Operativo, Usuario

---

## Autenticación

📁 `01_autenticacion/` — **13 casos**

| Roles | Descripción | Metodología | ID caso |
|---|---|---|---|
| Administrador | Login exitoso con credenciales válidas de Administrador. Verificar redirect a Dashboard y que la sesión criptográfica se desbloquee automáticamente (llaves RSA y llaves de rol en caché). | Login | [TC-01-01](TC-01-01.md) |
| Coordinador | Login exitoso con credenciales válidas de cualquier Coordinador (Legal, Administración, Psicosocial, Humanitario, Comunicación). Verificar redirect a Dashboard, desbloqueo de llave privada y carga de llaves de rol correspondientes. | Login | [TC-01-02](TC-01-02.md) |
| Operativo | Login exitoso con credenciales válidas de Operativo. Verificar redirect a Dashboard y desbloqueo de llave privada. Verificar que se carga la llave de rol Operativo en caché. | Login | [TC-01-03](TC-01-03.md) |
| Usuario | Login exitoso con credenciales válidas de Usuario. Verificar redirect a Dashboard. Verificar que NO se carga llave de rol (el rol Usuario no tiene LlaveRol). | Login | [TC-01-04](TC-01-04.md) |
| Administrador, Coordinador, Operativo, Usuario | Login fallido con contraseña incorrecta. Verificar que se muestra mensaje de error "Usuario o contraseña incorrectos" y no se crea sesión. | Login | [TC-01-05](TC-01-05.md) |
| Administrador, Coordinador, Operativo, Usuario | Login fallido con usuario inexistente. Verificar mensaje de error genérico (no revelar si el usuario existe). | Login | [TC-01-06](TC-01-06.md) |
| Administrador, Coordinador, Operativo, Usuario | Login con cuenta desactivada (activo=False). Verificar mensaje "Tu cuenta está desactivada. Contacta al administrador." y que no se crea sesión. | Login | [TC-01-07](TC-01-07.md) |
| Administrador, Coordinador, Operativo, Usuario | Login exitoso registra evento en BitacoraEvento con tipo='login', descripción con username e IP del cliente. | Login — Bitácora (verificar BD) | [TC-01-08](TC-01-08.md) |
| Administrador, Coordinador, Operativo, Usuario | Logout exitoso. Verificar que se registra evento tipo='logout' en bitácora y se redirige a la página de Login. | Dashboard — Logout — Login | [TC-01-09](TC-01-09.md) |
| Administrador, Coordinador, Operativo, Usuario | Acceso a Dashboard sin estar autenticado. Verificar redirect automático a Login. | Dashboard (directo sin sesión) | [TC-01-10](TC-01-10.md) |
| Administrador, Coordinador, Operativo, Usuario | Acceso a cualquier ruta protegida sin autenticación. Verificar que el decorator `@login_required` redirige a Login. | Cualquier ruta protegida (directo sin sesión) | [TC-01-11](TC-01-11.md) |
| Administrador, Coordinador, Operativo, Usuario | Login exitoso cuando el usuario ya está autenticado. Verificar que se redirige directamente al Dashboard sin mostrar el formulario de login. | Login (ya autenticado) | [TC-01-12](TC-01-12.md) |
| Coordinador, Administrador | Login con llave privada corrupta o salt inválido. Verificar que el login Django procede pero la sesión criptográfica queda vacía (sin `_llave_privada_cache`). El usuario no podrá descifrar expedientes. | Login | [TC-01-13](TC-01-13.md) |

---

## Gestión de Usuarios

📁 `02_gestion_usuarios/` — **22 casos**

| Roles | Descripción | Metodología | ID caso |
|---|---|---|---|
| Administrador | Crear usuario con rol Usuario. Verificar que se genera par RSA-2048, salt_login, llave_privada cifrada. NO se genera certificado X.509 ni archivo .key. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Crear usuario | |
| Administrador | Crear usuario con rol Operativo. Verificar que se genera par RSA-2048 y llave de rol. NO se genera certificado X.509 ni archivo .key. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Crear usuario | |
| Administrador | Crear usuario con rol Coordinador (cualquier tipo). Verificar que se genera par RSA-2048, certificado X.509 firmado por el Admin, archivo .key, llave de firma (passphrase de 64 hex), y ZIP descargable. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Crear usuario — Descargar certificado | |
| Administrador | Crear usuario con rol Administrador. Verificar generación completa de identidad criptográfica igual que Coordinador, más la distribución de TODAS las llaves de rol (no solo la del rol asignado). | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Crear usuario — Descargar certificado | |
| Administrador | Crear usuario sin nombre de usuario. Verificar mensaje de error "El nombre de usuario y la contraseña son obligatorios." | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Crear usuario | |
| Administrador | Crear usuario sin contraseña. Verificar mensaje de error de validación. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Crear usuario | |
| Administrador | Crear usuario con contraseña menor a 8 caracteres. Verificar mensaje "La contraseña debe tener al menos 8 caracteres." | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Crear usuario | |
| Administrador | Crear usuario con username duplicado. Verificar mensaje "El usuario ya existe." | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Crear usuario | |
| Administrador | Crear usuario con rol inválido (manipulación de formulario). Verificar mensaje "Rol inválido." | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Crear usuario | |
| Administrador | Crear usuario Coordinador cuando la firma del admin ha expirado (>15 min). Verificar redirect a Ingresar Firma con aviso de sesión expirada. | Login — Admin Panel (tab Usuarios) — Crear usuario (firma expirada) — Ingresar Firma | |
| Administrador | Descargar ZIP de certificado (.cer + .key) tras crear usuario Coordinador. Verificar que contiene archivos `username.cer` y `username.key`. | Login — Ingresar Firma — Admin Panel — Crear usuario — Descargar certificado | |
| Administrador | Intentar descargar certificado por segunda vez. Verificar mensaje "El certificado ya fue descargado o la sesión expiró." (el ZIP se borra de la sesión tras la primera descarga). | Login — Ingresar Firma — Admin Panel — Descargar certificado (segunda vez) | |
| Administrador | Visualización de la llave de firma (passphrase) en modal tras crear usuario. Verificar que se muestra UNA sola vez y desaparece al recargar. | Login — Ingresar Firma — Admin Panel — Crear usuario — Modal passphrase | |
| Administrador | Toggle activar/desactivar usuario. Verificar que el campo `activo` e `is_active` cambian, que se registra en bitácora y que el usuario desactivado no puede hacer login. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Toggle activo | |
| Administrador | Intentar desactivarse a sí mismo. Verificar mensaje "No puedes desactivarte a ti mismo." | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Toggle activo (propio) | |
| Administrador | Reset de contraseña de otro usuario. Verificar que se generan nuevas llaves RSA, nuevo salt, se eliminan AccesoLlaveRol antiguos y se redistribuyen llaves de rol con la nueva llave pública. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Criptografía — Restablecer contraseña | |
| Administrador | Reset de contraseña con nueva contraseña menor a 8 caracteres. Verificar mensaje de error de validación. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Criptografía — Restablecer contraseña | |
| Coordinador, Operativo, Usuario | Intentar acceder al Admin Panel sin ser Administrador. Verificar redirect al Dashboard con mensaje "No tienes permisos para acceder a esta sección." | Login — Admin Panel (acceso directo por URL) | |
| Administrador, Coordinador, Operativo, Usuario | Cambiar contraseña propia con contraseña actual correcta. Verificar re-cifrado de llave privada con nuevo salt, actualización de sesión y que el login funciona con la nueva contraseña. | Login — Dashboard — Cambiar contraseña | |
| Administrador, Coordinador, Operativo, Usuario | Cambiar contraseña propia con contraseña actual incorrecta. Verificar mensaje "La contraseña actual es incorrecta." | Login — Dashboard — Cambiar contraseña | |
| Administrador, Coordinador, Operativo, Usuario | Cambiar contraseña propia con nueva contraseña menor a 8 caracteres. Verificar mensaje de validación. | Login — Dashboard — Cambiar contraseña | |
| Administrador, Coordinador, Operativo, Usuario | Cambiar contraseña propia con confirmación que no coincide. Verificar mensaje "Las contraseñas nuevas no coinciden." | Login — Dashboard — Cambiar contraseña | |

---

## Roles y Permisos

📁 `03_roles_y_permisos/` — **20 casos**

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

---

## Certificados y Firma Digital

📁 `04_certificados_y_firma/` — **22 casos**

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

---

## Expedientes (CRUD)

📁 `05_expedientes/` — **25 casos**

| Roles | Descripción | Metodología | ID caso |
|---|---|---|---|
| Usuario | Crear expediente como Usuario. Verificar que se genera llave AES-256 aleatoria, datos se cifran con AES-EAX, se calcula hash SHA-256, se crean AccesoExpediente para el creador y para los 7 roles destino, y el expediente queda con verificado=False. | Login — Dashboard — Registrar migrante — Llenar formulario — Guardar | |
| Operativo | Crear expediente como Operativo. Verificar misma mecánica de cifrado y distribución de acceso. Verificar redirect al Dashboard con mensaje de éxito. | Login — Dashboard — Registrar migrante — Llenar formulario — Guardar | |
| Coordinador | Crear expediente como Coordinador. Verificar que se crean copias de llave AES cifrada para el creador (llave personal) y para cada rol en ROLES_DESTINO_EXPEDIENTE. | Login — Dashboard — Registrar migrante — Llenar formulario — Guardar | |
| Administrador | Crear expediente como Administrador. Verificar creación correcta con distribución de acceso completa. | Login — Dashboard — Registrar migrante — Llenar formulario — Guardar | |
| Usuario, Operativo, Coordinador, Administrador | Crear expediente con campos obligatorios vacíos. Verificar que el formulario Django muestra errores de validación sin guardar. | Login — Dashboard — Registrar migrante — Formulario incompleto — Guardar | |
| Operativo | Ver lista de expedientes como Operativo. Verificar que muestra TODOS los expedientes del sistema (no solo los propios) con datos descifrados usando la llave de rol. | Login — Dashboard — Ver expedientes | |
| Coordinador | Ver lista de expedientes como Coordinador. Verificar descifrado exitoso usando llave de rol del Coordinador. Verificar columnas: ID, Fecha Atención, Nombre Completo, Género, País, Creador, Estado. | Login — Dashboard — Ver expedientes | |
| Administrador | Ver lista de expedientes como Administrador. Verificar descifrado usando llave de rol Administrador. Verificar que se muestran columnas de acciones (editar, eliminar) y checkbox de validación. | Login — Ingresar Firma — Dashboard — Ver expedientes | |
| Usuario | Ver lista de expedientes como Usuario. Verificar que solo muestra los expedientes creados por el propio usuario (filtro `creado_por=yo`). El título debe ser "Mis Expedientes". | Login — Dashboard — Mis expedientes | |
| Operativo | Verificar que la columna "Acciones" (editar/eliminar) NO aparece para Operativo (no tiene permisos de edición ni eliminación). | Login — Dashboard — Ver expedientes | |
| Usuario | Verificar que la columna "Validar" (checkbox) NO aparece para el rol Usuario. | Login — Dashboard — Mis expedientes | |
| Coordinador | Verificar que la columna "Validar" (checkbox) SÍ aparece para Coordinador. | Login — Dashboard — Ver expedientes | |
| Coordinador, Administrador | Verificar que la columna "Acciones" con botón de editar SÍ aparece para Coordinador y Admin. | Login — Dashboard — Ver expedientes | |
| Administrador | Verificar que el botón de eliminar (🗑️) solo aparece para Administrador en la columna de acciones. | Login — Ingresar Firma — Dashboard — Ver expedientes | |
| Operativo, Coordinador, Administrador | Filtrar expedientes por estado de verificación (Verificados / Pendientes). Verificar que la lista filtra correctamente. | Login — Dashboard — Ver expedientes — Filtro verificado | |
| Operativo, Coordinador, Administrador | Filtrar expedientes por creador. Verificar que el dropdown muestra los creadores disponibles y filtra la tabla. | Login — Dashboard — Ver expedientes — Filtro creador | |
| Operativo, Coordinador, Administrador | Filtrar expedientes por rango de fechas (desde/hasta). Verificar que solo se muestran expedientes dentro del rango. | Login — Dashboard — Ver expedientes — Filtro fechas | |
| Operativo, Coordinador, Administrador | Limpiar filtros. Verificar que se restablecen todos los filtros y se muestran todos los expedientes. | Login — Dashboard — Ver expedientes — Limpiar filtros | |
| Coordinador | Editar expediente existente. Verificar que se descifra con la llave AES, se prellenan los campos del formulario, al guardar se re-cifra con la misma llave AES, se calcula nuevo hash, se firma digitalmente y se marca como verificado=True. | Login — Ingresar Firma — Dashboard — Ver expedientes — Editar (✏️) — Modificar campos — Guardar | |
| Administrador | Editar expediente existente como Admin. Verificar misma mecánica que Coordinador. | Login — Ingresar Firma — Dashboard — Ver expedientes — Editar (✏️) — Modificar campos — Guardar | |
| Operativo | Intentar editar expediente como Operativo (acceso directo por URL). Verificar redirect con mensaje de permisos insuficientes. | Login — Editar expediente (URL directo) | |
| Administrador | Eliminar expediente. Verificar confirmación con dialog JavaScript, registro en bitácora tipo='eliminar_expediente', y que el expediente y sus AccesoExpediente se eliminan de la BD. | Login — Ingresar Firma — Dashboard — Ver expedientes — Eliminar (🗑️) — Confirmar | |
| Coordinador | Intentar eliminar expediente como Coordinador (acceso directo por URL). Verificar redirect con mensaje "No tienes permisos para acceder a esta sección." | Login — Eliminar expediente (URL directo) | |
| Operativo, Coordinador, Administrador | Verificar descifrado fallback: si la llave de rol no funciona, el sistema intenta con otras llaves de rol en caché, y finalmente con la llave del creador. | Login — Dashboard — Ver expedientes (con expediente de otro rol) | |
| Operativo, Coordinador, Administrador | Verificar que expedientes para los que no se tiene ninguna llave muestran "Datos cifrados (sin acceso)" en lugar de los datos personales. | Login — Dashboard — Ver expedientes (sin llave correspondiente) | |

---

## Verificación de Expedientes

📁 `06_verificacion_expedientes/` — **10 casos**

| Roles | Descripción | Metodología | ID caso |
|---|---|---|---|
| Coordinador | Verificar un solo expediente pendiente. Seleccionar checkbox, enviar formulario. Verificar que se requiere firma (.key), se calcula hash SHA-256 del ciphertext, se firma con RSA-2048-PKCS1v15, se guarda firma_digital en Base64, verificado=True, y se registra en bitácora. | Login — Ingresar Firma — Dashboard — Ver expedientes — Checkbox — Firmar y verificar | |
| Coordinador | Verificar múltiples expedientes en batch. Seleccionar varios checkboxes. Verificar que se procesan todos, el mensaje de éxito indica la cantidad correcta verificada. | Login — Ingresar Firma — Dashboard — Ver expedientes — Múltiples checkboxes — Firmar y verificar | |
| Administrador | Verificar expedientes como Administrador. Misma mecánica que Coordinador. | Login — Ingresar Firma — Dashboard — Ver expedientes — Checkbox — Firmar y verificar | |
| Coordinador | Intentar verificar sin seleccionar ningún expediente. Verificar mensaje "No seleccionaste ningún expediente para verificar." | Login — Ingresar Firma — Dashboard — Ver expedientes — Firmar y verificar (sin selección) | |
| Coordinador | Intentar verificar sin haber cargado .key. Verificar redirect a Ingresar Firma. Tras ingresar firma, verificar que los datos POST pendientes se recuperan de la sesión y la verificación procede automáticamente. | Login — Dashboard — Ver expedientes — Checkbox — Firmar y verificar — Ingresar Firma — Redirect automático | |
| Coordinador | Verificar que un expediente ya verificado no muestra checkbox (no se puede re-verificar). Solo expedientes con verificado=False y datos descifrados muestran checkbox. | Login — Dashboard — Ver expedientes | |
| Operativo | Verificar que el botón "Firmar y verificar seleccionados" NO aparece para Operativo. | Login — Dashboard — Ver expedientes | |
| Usuario | Verificar que el botón de verificación batch NO aparece para Usuario. | Login — Dashboard — Mis expedientes | |
| Coordinador | Re-verificar un expediente editado (que fue re-firmado al editar). Verificar que la firma digital previa se reemplaza con la nueva del editor. | Login — Ingresar Firma — Dashboard — Ver expedientes — Editar — Guardar — Ver estado verificado | |
| Administrador | Verificar la nota informativa en la barra de validación: "Se requerirá la llave de firma (.key) si no ha sido cargada en esta sesión." | Login — Ingresar Firma — Dashboard — Ver expedientes | |

---

## Auditoría

📁 `07_auditoria/` — **19 casos**

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

---

## Seguridad Criptográfica

📁 `08_seguridad_criptografica/` — **20 casos**

| Roles | Descripción | Metodología | ID caso |
|---|---|---|---|
| Administrador | Verificar que al crear un usuario no-Usuario, se crea un registro AccesoLlaveRol con la llave privada del rol cifrada con la llave pública RSA del nuevo usuario. | Login — Ingresar Firma — Admin Panel — Crear usuario — Verificar BD (AccesoLlaveRol) | |
| Administrador | Verificar que al crear un usuario Administrador, se crean registros AccesoLlaveRol para TODOS los roles del sistema (Administrador, todos los Coordinadores, Operativo). | Login — Ingresar Firma — Admin Panel — Crear usuario Admin — Verificar BD | |
| Administrador | Verificar que al cambiar rol de un usuario, se crean nuevos AccesoLlaveRol para el nuevo rol (sin eliminar los anteriores). | Login — Ingresar Firma — Admin Panel — Cambiar rol — Verificar BD | |
| Administrador | Verificar que al reset de password, se eliminan los AccesoLlaveRol anteriores y se redistribuyen con la nueva llave pública del usuario. | Login — Ingresar Firma — Admin Panel — Reset password — Verificar BD | |
| Administrador | Verificar que la llave privada del usuario está doblemente cifrada: AES-EAX(SECRET_KEY) externo + AES-EAX(Scrypt(password, salt)) interno. | Verificar BD — Inspeccionar campo llave_privada | |
| Administrador | Verificar que el campo `telefono` está cifrado con AES-EAX derivado de SECRET_KEY (EncryptedCharField). Comparar valor en BD vs valor descifrado en la app. | Verificar BD — Comparar campo cifrado vs app | |
| Coordinador | Verificar que al crear un expediente, se crean 8 registros AccesoExpediente: 1 para el Creador + 7 para los roles destino (Admin, 5 Coordinadores, Operativo). | Login — Registrar migrante — Guardar — Verificar BD (AccesoExpediente) | |
| Coordinador | Verificar que la llave AES de cada AccesoExpediente está cifrada con la llave pública RSA correspondiente (del usuario para Creador, del rol para los demás). | Login — Registrar migrante — Verificar BD | |
| Coordinador | Verificar integridad del expediente: recalcular SHA-256 de datos_cifrados y comparar con hash_expediente almacenado. | Verificar BD — Recalcular hash | |
| Coordinador | Verificar la firma digital de un expediente verificado: usar la llave pública del firmante para verificar RSA-2048-PKCS1v15(SHA-256(hash_exp)). | Verificar BD — Verificar firma con llave pública | |
| Administrador | Verificar que la sesión criptográfica (`_llave_privada_cache`, `_llaves_rol_cache`) se limpia completamente al hacer logout. | Login — Logout — Verificar sesión vacía | |
| Administrador | Verificar que el cambio de contraseña re-cifra la llave privada con nuevo salt y nueva clave derivada, y actualiza `_llave_privada_cache` en sesión para que las llaves de rol sigan funcionando sin re-login. | Login — Cambiar contraseña — Ver expedientes (verificar que sigue descifrando) | |
| Coordinador | Verificar que un usuario cuya sesión no tiene `_llave_privada_cache` (desbloqueo fallido) es forzado a logout con mensaje descriptivo al intentar acceder a rutas protegidas por `@rol_requerido`. | Login (con llave corrupta) — Dashboard — Ver expedientes | |
| Administrador | Verificar que si el Admin no tiene la llave de un rol en su caché, muestra warning al intentar distribuirla a otro usuario. | Login — Ingresar Firma — Admin Panel — Crear usuario (sin caché de llave) | |
| Operativo, Coordinador | Verificar aislamiento criptográfico: un Operativo NO puede descifrar datos usando la llave de rol de un Coordinador (no tiene acceso a esa llave privada). | Login (Operativo) — Ver expedientes — Intentar descifrar con llave de otro rol | |
| Coordinador | Verificar que la edición de expediente reutiliza la misma llave AES (no genera una nueva). Verificar que los AccesoExpediente existentes siguen funcionando para todos los roles. | Login — Ingresar Firma — Editar expediente — Verificar BD (llave_aes_cifrada no cambió) | |
| Administrador | Verificar que el decorador `@firma_requerida` bloquea roles Usuario y Operativo con mensaje "Tu rol no tiene permisos para realizar esta acción crítica (requiere firma)." incluso si intentan acceder por URL directo. | Login (Operativo/Usuario) — URL directa de operación crítica | |
| Coordinador | Verificar que el decorador `@firma_requerida` guarda los datos POST pendientes en sesión cuando la firma expiró, y los recupera automáticamente tras re-validar la firma. | Login — Ingresar Firma — (esperar expiración) — Verificar expedientes — Re-ingresar firma — Verificar que se procesó | |
| Administrador | Verificar que el campo `llave_firma` (passphrase del .key) tiene exactamente 64 caracteres hexadecimales (32 bytes de entropía). | Login — Ingresar Firma — Crear usuario Coordinador — Inspeccionar modal passphrase | |
| Administrador | Verificar que el archivo .key exportado usa formato PKCS#8 DER cifrado con la passphrase generada. Verificar que se puede importar correctamente con la passphrase. | Crear usuario Coordinador — Descargar ZIP — Importar .key con passphrase | |

---

## Resumen

**Total de casos de prueba: 151**

| Categoría | Casos |
|---|---|
| Autenticación | 13 |
| Gestión de Usuarios | 22 |
| Roles y Permisos | 20 |
| Certificados y Firma Digital | 22 |
| Expedientes (CRUD) | 25 |
| Verificación de Expedientes | 10 |
| Auditoría | 19 |
| Seguridad Criptográfica | 20 |
| **Total** | **151** |
