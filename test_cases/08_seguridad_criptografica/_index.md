# 08 — Seguridad Criptográfica

Casos de prueba para la distribución de llaves de rol, cifrado/descifrado de datos, integridad de expedientes y edge cases de seguridad.

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
