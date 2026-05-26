# 02 — Gestión de Usuarios

Casos de prueba para la creación, activación/desactivación y restablecimiento de contraseña de usuarios desde el Panel de Administración.

| Roles | Descripción | Metodología | ID caso |
|---|---|---|---|
| Administrador | Crear usuario con rol Usuario. Verificar que se genera par RSA-2048, salt_login, llave_privada cifrada. NO se genera certificado X.509 ni archivo .key. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Crear usuario | TC-02-01 |
| Administrador | Crear usuario con rol Operativo. Verificar que se genera par RSA-2048 y llave de rol. NO se genera certificado X.509 ni archivo .key. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Crear usuario | TC-02-02 |
| Administrador | Crear usuario con rol Coordinador (cualquier tipo). Verificar que se genera par RSA-2048, certificado X.509 firmado por el Admin, archivo .key, llave de firma (passphrase de 64 hex), y ZIP descargable. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Crear usuario — Descargar certificado | TC-02-03 |
| Administrador | Crear usuario con rol Administrador. Verificar generación completa de identidad criptográfica igual que Coordinador, más la distribución de TODAS las llaves de rol (no solo la del rol asignado). | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Crear usuario — Descargar certificado | TC-02-04 |
| Administrador | Crear usuario sin nombre de usuario. Verificar mensaje de error "El nombre de usuario y la contraseña son obligatorios." | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Crear usuario | TC-02-05 |
| Administrador | Crear usuario sin contraseña. Verificar mensaje de error de validación. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Crear usuario | TC-02-06 |
| Administrador | Crear usuario con contraseña menor a 8 caracteres. Verificar mensaje "La contraseña debe tener al menos 8 caracteres." | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Crear usuario | TC-02-07 |
| Administrador | Crear usuario con username duplicado. Verificar mensaje "El usuario ya existe." | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Crear usuario | TC-02-08 |
| Administrador | Crear usuario con rol inválido (manipulación de formulario). Verificar mensaje "Rol inválido." | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Crear usuario | TC-02-09 |
| Administrador | Crear usuario Coordinador cuando la firma del admin ha expirado (>15 min). Verificar redirect a Ingresar Firma con aviso de sesión expirada. | Login — Admin Panel (tab Usuarios) — Crear usuario (firma expirada) — Ingresar Firma | TC-02-10 |
| Administrador | Descargar ZIP de certificado (.cer + .key) tras crear usuario Coordinador. Verificar que contiene archivos `username.cer` y `username.key`. | Login — Ingresar Firma — Admin Panel — Crear usuario — Descargar certificado | TC-02-11 |
| Administrador | Intentar descargar certificado por segunda vez. Verificar mensaje "El certificado ya fue descargado o la sesión expiró." (el ZIP se borra de la sesión tras la primera descarga). | Login — Ingresar Firma — Admin Panel — Descargar certificado (segunda vez) | TC-02-12 |
| Administrador | Visualización de la llave de firma (passphrase) en modal tras crear usuario. Verificar que se muestra UNA sola vez y desaparece al recargar. | Login — Ingresar Firma — Admin Panel — Crear usuario — Modal passphrase | TC-02-13 |
| Administrador | Toggle activar/desactivar usuario. Verificar que el campo `activo` e `is_active` cambian, que se registra en bitácora y que el usuario desactivado no puede hacer login. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Toggle activo | TC-02-14 |
| Administrador | Intentar desactivarse a sí mismo. Verificar mensaje "No puedes desactivarte a ti mismo." | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Toggle activo (propio) | TC-02-15 |
| Administrador | Reset de contraseña de otro usuario. Verificar que se generan nuevas llaves RSA, nuevo salt, se eliminan AccesoLlaveRol antiguos y se redistribuyen llaves de rol con la nueva llave pública. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Criptografía — Restablecer contraseña | TC-02-16 |
| Administrador | Reset de contraseña con nueva contraseña menor a 8 caracteres. Verificar mensaje de error de validación. | Login — Ingresar Firma — Admin Panel (tab Usuarios) — Criptografía — Restablecer contraseña | TC-02-17 |
| Coordinador, Operativo, Usuario | Intentar acceder al Admin Panel sin ser Administrador. Verificar redirect al Dashboard con mensaje "No tienes permisos para acceder a esta sección." | Login — Admin Panel (acceso directo por URL) | TC-02-18 |
| Administrador, Coordinador, Operativo, Usuario | Cambiar contraseña propia con contraseña actual correcta. Verificar re-cifrado de llave privada con nuevo salt, actualización de sesión y que el login funciona con la nueva contraseña. | Login — Dashboard — Cambiar contraseña | TC-02-19 |
| Administrador, Coordinador, Operativo, Usuario | Cambiar contraseña propia con contraseña actual incorrecta. Verificar mensaje "La contraseña actual es incorrecta." | Login — Dashboard — Cambiar contraseña | TC-02-20 |
| Administrador, Coordinador, Operativo, Usuario | Cambiar contraseña propia con nueva contraseña menor a 8 caracteres. Verificar mensaje de validación. | Login — Dashboard — Cambiar contraseña | TC-02-21 |
| Administrador, Coordinador, Operativo, Usuario | Cambiar contraseña propia con confirmación que no coincide. Verificar mensaje "Las contraseñas nuevas no coinciden." | Login — Dashboard — Cambiar contraseña | TC-02-22 |
