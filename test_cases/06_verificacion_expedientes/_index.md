# 06 — Verificación de Expedientes

Casos de prueba para la verificación batch de expedientes, firma digital y re-verificación.

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
