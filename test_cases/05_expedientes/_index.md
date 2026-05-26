# 05 — Expedientes (CRUD)

Casos de prueba para la creación, lectura, edición y eliminación de expedientes, incluyendo cifrado/descifrado y filtros.

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
