# Equipo 5

## Integrantes

- Alejandro Rojas
- Daniel DePool
- Luis Eduardo Martínez
- David Aguirre
- Arturo Camacho

[Setup](https://github.com/AlexRojas384/Equipo5Criptografia/blob/main/Setup.md)

Link a la presentacion ejecutiva https://canva.link/xnb0wiufwzc7n1f  

Respuesta a la pregunta de Anas respecto a la integridad de los datos: debido a que se utiliza un cifrado a los datos en reposo, o mejor dicho a los datos en la base de datos, siempre se cumple que toda la inforamción está cifrada, además de eso, hay una protección extra debido a que las sesiones de los adminsitradores y coordinadores tienen 15 minutos hasta que vuelven a requerir subir la  llave, también después de cualquier cambio de identificación, se actualizan las credenciales de la persona afectada.

La pregunta de Raul hizo preguntas respecto a las contraseñas y expedientes, es importante tener en cuenta que como hubo un enfoque prioritario a la gestión de registros, cada rol tiene permisos diferentes y es imprescindible que los administradores y coordinadores utilicen su llave y el token/passphrase para validar su identidad al momento de confirmar la identidad y hacer acciones que se pueden considerar tratar con datos sensibles.

## Acerca del Proyecto

Este proyecto es una plataforma de gestión segura de expedientes para Casa Monarca. Utiliza una **Arquitectura de Seguridad de Doble Llave** y un portal público para el ejercicio de derechos del migrante.

- **Acceso Básico (colaboradores):** descifrado de expedientes transparente al hacer login con la Llave de Login (Scrypt + AES + RSA por rol).
- **Operaciones Críticas:** validación estricta con Certificados X.509 y Llaves Privadas (estilo SAT, `.key` con passphrase) exigidas para edición, verificación, borrado y firma de expedientes.
- **Portal del Migrante (`/mi-expediente/`):** acceso anónimo del migrante usando su folio + nombre completo (Scrypt simétrico). Solo lectura; permite ejercer derechos ARCO (Rectificación, Cancelación, Oposición).
- **Flujo ARCO multinivel:** Operativo propone cambios → Coordinador firma criptográficamente → en Cancelación, un Administrador adicional debe firmar la ejecución final del borrado del expediente. Toda decisión queda firmada y auditada en bitácora encadenada con SHA-256.

Documentación técnica completa en [FLUJO_CRIPTOGRAFICO.md](FLUJO_CRIPTOGRAFICO.md).
