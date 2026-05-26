# 01 — Autenticación

Casos de prueba relacionados con el inicio de sesión, cierre de sesión y el desbloqueo automático de la sesión criptográfica.

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
