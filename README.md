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

Este proyecto es una plataforma de gestión segura de expedientes para Casa Monarca. Recientemente ha sido actualizada para utilizar una **Arquitectura de Seguridad de Doble Llave**.
- **Acceso Básico:** Descifrado de expedientes transparente al hacer login (Llave de Login).
- **Operaciones Críticas:** Validación estricta con Certificados y Llaves Privadas (Estilo SAT) exigidas solo para la edición, verificación o borrado de expedientes por parte de la Coordinación y la Administración.
