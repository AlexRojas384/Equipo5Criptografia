# Flujo Criptográfico del Sistema — Casa Monarca

> Documento técnico que describe el modelo de cifrado, las tablas de la base de datos y los flujos de autenticación y uso de certificados por rol.

---

## Índice

1. [Primitivas Criptográficas](#1-primitivas-criptográficas)
2. [Esquema de Base de Datos](#2-esquema-de-base-de-datos)
3. [Qué Cifra a Qué](#3-qué-cifra-a-qué)
4. [Flujo de Login](#4-flujo-de-login)
5. [Flujo de Certificados por Rol](#5-flujo-de-certificados-por-rol)
6. [Flujo de Creación de Expediente](#6-flujo-de-creación-de-expediente)
7. [Flujo de Operación Crítica (Firma)](#7-flujo-de-operación-crítica-firma)
8. [Cadena de Auditoría](#8-cadena-de-auditoría)
9. [Diagrama General del Sistema](#9-diagrama-general-del-sistema)
10. [Portal del Migrante y Flujo ARCO](#10-portal-del-migrante-y-flujo-arco)

---

## 1. Primitivas Criptográficas

| Algoritmo        | Parámetros                           | Uso en el sistema                                                                                                             |
| ---------------- | ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| **RSA-2048**     | PKCS1-OAEP / PKCS#1 v1.5             | Par de llaves por usuario, par de llaves por rol, certificados X.509                                                          |
| **AES-256-EAX**  | Nonce 16B, Tag 16B                   | Cifrado de datos de expedientes y llaves privadas en reposo                                                                   |
| **Scrypt**       | N=16384, r=8, p=1, dklen=32          | Derivación de clave desde la contraseña del usuario (login)                                                                   |
| **SHA-256**      | Hex 64 chars                         | Hash de expedientes, encadenamiento de bitácora, firma digital                                                                |
| **X.509**        | 1 año de vigencia                    | Certificado digital jerárquico (estilo SAT). Administrador: auto-firmado. Coordinadores: firmado por el Administrador emisor. |
| **PKCS#8**       | Cifrado con AES-256-CBC + Scrypt     | Exportación de llave privada de firma al archivo `.key` descargable (protegido por contraseña generada de 64 caracteres)      |
| **AES-EAX (DB)** | Derivada de `SECRET_KEY` via SHA-256 | Cifrado transparente de campos sensibles en base de datos                                                                     |

---

## 2. Esquema de Base de Datos

### 2.1 `usuarios_usuario`

Modelo de usuario extendido de Django `AbstractUser`.

| Columna                        | Tipo        | Cifrado                  | Descripción                                                                                                                                         |
| ------------------------------ | ----------- | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`                           | INT         | No                       | Identificador primario                                                                                                                              |
| `username`                     | VARCHAR     | No                       | Nombre de usuario único                                                                                                                             |
| `password`                     | VARCHAR     | Django PBKDF2            | Hash de contraseña gestionado por Django Auth                                                                                                       |
| `rol`                          | VARCHAR     | No                       | Rol RBAC asignado (uno de los 8 roles del sistema)                                                                                                  |
| `telefono`                     | TEXT        | **AES-EAX (SECRET_KEY)** | Teléfono cifrado transparentemente con `EncryptedCharField`                                                                                         |
| `activo`                       | BOOL        | No                       | Indica si la cuenta está habilitada                                                                                                                 |
| `llave_publica`                | LONGTEXT    | No                       | Llave pública RSA-2048 en formato PEM — accesible públicamente                                                                                      |
| `llave_privada`                | LONGTEXT    | **AES-EAX (SECRET_KEY)** | Llave privada RSA-2048 PEM protegida con `EncryptedTextField` (cifrado transparente de BD) + internamente re-cifrada con Scrypt(password) + AES-EAX |
| `salt_login`                   | VARCHAR(64) | No                       | Salt hexadecimal de 32 bytes para Scrypt; único por usuario                                                                                         |
| `certificado_digital`          | LONGTEXT    | No                       | Certificado X.509 PEM (Jerárquico: auto-firmado para Admin, emitido por Admin para Coordinadores. Nulo para roles menores).                         |
| `fecha_expiracion_certificado` | DATETIME    | No                       | Fecha de expiración del certificado; el middleware bloquea el acceso si expiró                                                                      |

> **Doble cifrado en `llave_privada`:** el campo en la BD siempre está envuelto por `EncryptedTextField` (AES-EAX derivado de `SECRET_KEY`). El valor descifrado de BD es, a su vez, la llave privada RSA-2048 re-cifrada con `Scrypt(password) + AES-EAX`. Sólo el usuario que conoce su contraseña puede descifrar su llave privada.

---

### 2.2 `usuarios_llaverol`

Una fila por cada rol del sistema. Almacena el par RSA-2048 **del rol**, no del usuario.

| Columna         | Tipo        | Cifrado | Descripción                                                                                                |
| --------------- | ----------- | ------- | ---------------------------------------------------------------------------------------------------------- |
| `id`            | INT         | No      | Identificador primario                                                                                     |
| `rol`           | VARCHAR(50) | No      | Nombre del rol (`Administrador`, `Coordinador_Legal`, etc.) — único                                        |
| `llave_publica` | LONGTEXT    | No      | Llave pública RSA-2048 PEM del rol; usada para cifrar las llaves AES de expedientes accesibles por ese rol |

---

### 2.3 `usuarios_accesollaverol`

Tabla de unión que entrega la llave **privada** de cada rol a cada usuario autorizado.

| Columna                     | Tipo                | Cifrado                    | Descripción                                                                                                                                                                        |
| --------------------------- | ------------------- | -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`                        | INT                 | No                         | Identificador primario                                                                                                                                                             |
| `llave_rol_id`              | INT (FK → LlaveRol) | No                         | Referencia al rol cuya llave privada se está distribuyendo                                                                                                                         |
| `usuario_id`                | INT (FK → Usuario)  | No                         | Referencia al usuario receptor                                                                                                                                                     |
| `llave_privada_rol_cifrada` | LONGTEXT            | **RSA-2048 + AES-256-EAX** | JSON con paquete híbrido: `{nonce, tag, llave_aes_cifrada, datos_cifrados}`. La llave AES se cifra con la llave pública del usuario; los datos (llave privada del rol) con AES-EAX |

> **Principio:** cada usuario sólo puede desempaquetar la llave privada de su rol usando su propia llave privada RSA. Sin ella, la llave privada del rol es ilegible.

---

### 2.4 `usuarios_solicitudrol`

Solicitudes de cambio de rol enviadas por usuarios y respondidas por administradores.

| Columna             | Tipo               | Cifrado | Descripción                            |
| ------------------- | ------------------ | ------- | -------------------------------------- |
| `id`                | INT                | No      | Identificador primario                 |
| `solicitante_id`    | INT (FK → Usuario) | No      | Usuario que solicita el cambio         |
| `rol_actual`        | VARCHAR            | No      | Rol vigente al momento de la solicitud |
| `rol_solicitado`    | VARCHAR            | No      | Rol al que se desea cambiar            |
| `estado`            | VARCHAR            | No      | `pendiente`, `aprobada` o `rechazada`  |
| `respondido_por_id` | INT (FK → Usuario) | No      | Administrador que respondió (nullable) |
| `fecha_solicitud`   | DATETIME           | No      | Marca temporal de la solicitud         |

---

### 2.5 `expediente_expediente`

Expedientes de personas atendidas. **Ningún dato personal es legible en reposo.**

| Columna               | Tipo               | Cifrado                  | Descripción                                                                                                            |
| --------------------- | ------------------ | ------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| `id`                  | INT                | No                       | Identificador primario                                                                                                 |
| `creado_por_id`       | INT (FK → Usuario) | No                       | Usuario que creó el expediente                                                                                         |
| `fecha_creacion`      | DATETIME           | No                       | Timestamp de creación (auto)                                                                                           |
| `fecha_atencion`      | DATE               | No                       | Fecha de atención al caso                                                                                              |
| `datos_cifrados`      | LONGTEXT           | **AES-256-EAX**          | Ciphertext Base64 con todos los datos personales del expediente                                                        |
| `nonce`               | TEXT               | No                       | Nonce AES-EAX en Base64 (16 bytes); único por expediente                                                               |
| `tag`                 | TEXT               | No                       | Tag de autenticación AES-EAX en Base64; permite detectar manipulación                                                  |
| `verificado`          | BOOL               | No                       | Indica si el expediente fue verificado/firmado por un rol autorizado                                                   |
| `firma_digital`       | LONGTEXT           | No                       | Firma RSA-2048 + SHA-256 (PKCS#1 v1.5) en Base64 del hash del expediente                                               |
| `hash_expediente`     | VARCHAR(64)        | No                       | SHA-256 del ciphertext; parte de lo firmado digitalmente                                                               |
| `folio_hash`          | VARCHAR(64)        | No (es un hash)          | SHA-256 del folio en texto claro; índice de búsqueda segura para el portal del migrante (el folio en claro vive cifrado dentro de `datos_cifrados`) |
| `etiquetas_oposicion` | LONGTEXT           | **AES-EAX (SECRET_KEY)** | JSON con la lista de etiquetas de Oposición ARCO aplicadas: `[{fecha, etiqueta, coordinador, solicitud_arco_id}]`. Cifrado en BD; visible a los roles de lectura |

---

### 2.6 `expediente_accesoexpediente`

Control de acceso granular: una fila por cada entidad (usuario o rol) que puede descifrar un expediente.

| Columna             | Tipo                  | Cifrado                   | Descripción                                                                                                                                                         |
| ------------------- | --------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`                | INT                   | No                        | Identificador primario                                                                                                                                              |
| `expediente_id`     | INT (FK → Expediente) | No                        | Expediente al que da acceso                                                                                                                                         |
| `tipo_acceso`       | VARCHAR               | No                        | `'Creador'` o nombre del rol (ej. `'Coordinador_Legal'`)                                                                                                            |
| `usuario_id`        | INT (FK → Usuario)    | No                        | Usuario concreto (nullable para accesos de rol genérico)                                                                                                            |
| `llave_aes_cifrada` | LONGTEXT              | **RSA-2048 (PKCS1-OAEP)** | La llave AES-256 del expediente, cifrada con la llave pública del usuario o del rol. Sólo quien tenga la llave privada correspondiente puede recuperar la llave AES |

> **Cifrado sobre-enumerado:** si un expediente tiene 3 roles con acceso, existirán 3 filas `AccesoExpediente`, cada una con la misma llave AES-256 cifrada con una llave pública diferente. Los datos cifrados (`datos_cifrados`) son únicos y compartidos.

---

### 2.7 `auditoria_bitacoraevento`

Registro de auditoría con integridad garantizada por encadenamiento de hashes.

| Columna         | Tipo               | Cifrado | Descripción                                               |
| --------------- | ------------------ | ------- | --------------------------------------------------------- |
| `id`            | INT                | No      | Identificador primario                                    |
| `usuario_id`    | INT (FK → Usuario) | No      | Usuario que generó el evento (nullable si es del sistema) |
| `tipo`          | VARCHAR            | No      | Tipo de evento (login, creación, edición, firma, etc.)    |
| `descripcion`   | TEXT               | No      | Descripción legible del evento                            |
| `fecha`         | DATETIME           | No      | Timestamp del evento                                      |
| `ip`            | VARCHAR            | No      | Dirección IP del cliente                                  |
| `hash_registro` | VARCHAR(64)        | No      | SHA-256 del registro actual encadenado con el anterior    |

---

### 2.8 `portal_migrante_solicitudarco`

Solicitudes de ejercicio de derechos ARCO (Acceso, Rectificación, Cancelación, Oposición) enviadas por el migrante desde el portal público. Todos los textos sensibles están cifrados a nivel de BD con `SECRET_KEY` (cifrado transparente vía `EncryptedTextFieldArco`); el flujo es interno y no requiere descifrado del migrante fuera del servidor.

| Columna                   | Tipo                  | Cifrado                  | Descripción                                                                                                                       |
| ------------------------- | --------------------- | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------- |
| `id`                      | INT                   | No                       | Identificador primario                                                                                                            |
| `expediente_id`           | INT (FK → Expediente) | No                       | Expediente sobre el que se ejerce el derecho. `SET_NULL` para conservar la solicitud como registro histórico tras una cancelación |
| `tipo`                    | VARCHAR(20)           | No                       | `rectificacion` / `cancelacion` / `oposicion`                                                                                     |
| `estado`                  | VARCHAR(25)           | No                       | `pendiente` / `aprobada_operativo` / `firmada_coordinador` / `ejecutada` / `rechazada`                                            |
| `descripcion_cifrada`     | LONGTEXT              | **AES-EAX (SECRET_KEY)** | Texto libre del migrante: motivo y detalles                                                                                       |
| `campos_solicitados`      | LONGTEXT              | **AES-EAX (SECRET_KEY)** | JSON con `{campo: valor}` o `{descripcion_libre: ...}` propuesto por el migrante                                                  |
| `cambios_propuestos`      | LONGTEXT              | **AES-EAX (SECRET_KEY)** | JSON con el diff que el **Operativo** propone aplicar (solo `rectificacion`); el Coordinador lo aplica al firmar                  |
| `etiqueta_oposicion`      | LONGTEXT              | **AES-EAX (SECRET_KEY)** | Texto libre del **Operativo** que se anexará a `Expediente.etiquetas_oposicion` al firmar (solo `oposicion`)                      |
| `hash_solicitud`          | VARCHAR(64)           | No                       | SHA-256 de `descripcion + tipo + expediente_id`; integridad del registro                                                          |
| `folio_hash_verificacion` | VARCHAR(64)           | No                       | SHA-256 del folio usado al crear la solicitud; verifica titularidad del migrante                                                  |
| `operativo_id`            | INT (FK → Usuario)    | No                       | Operativo que aprobó/rechazó la solicitud                                                                                         |
| `respuesta_operativo`     | TEXT                  | No                       | Comentario libre del Operativo                                                                                                    |
| `fecha_respuesta_operativo` | DATETIME            | No                       | Timestamp de la respuesta del Operativo                                                                                           |
| `coordinador_id`          | INT (FK → Usuario)    | No                       | Coordinador (o Admin actuando como Coordinador) que firmó                                                                         |
| `respuesta_coordinador`   | TEXT                  | No                       | Comentario del Coordinador                                                                                                        |
| `fecha_firma_coordinador` | DATETIME              | No                       | Timestamp de la firma                                                                                                             |
| `firma_digital`           | LONGTEXT              | No                       | Firma RSA-2048 + SHA-256 (PKCS#1 v1.5) del Coordinador sobre `f"ARCO-{pk}-{tipo}-{hash_solicitud}-{timestamp}"`                    |
| `admin_id`                | INT (FK → Usuario)    | No                       | Administrador que ejecutó la cancelación final (solo `cancelacion` ejecutada)                                                     |
| `respuesta_admin`         | TEXT                  | No                       | Comentario del Admin al ejecutar                                                                                                  |
| `fecha_ejecucion_admin`   | DATETIME              | No                       | Timestamp de la ejecución final                                                                                                   |
| `firma_digital_admin`     | LONGTEXT              | No                       | Firma RSA-2048 del Admin sobre `f"ARCO-CANCEL-{pk}-{exp_id}-{exp_hash}-{timestamp}"`                                              |
| `fecha_creacion`          | DATETIME              | No                       | Timestamp de creación de la solicitud                                                                                             |

> **Por qué `SECRET_KEY` y no AES por rol:** la solicitud ARCO es un canal de comunicación interna entre el migrante (sin sesión persistente) y la organización. El migrante no necesita re-descifrarla después de enviarla, y los roles autorizados (Operativo/Coordinador/Admin) pueden leerla porque comparten acceso al servidor. Usar el esquema AES-por-expediente añadiría complejidad sin ganancia de privacidad real.

---

## 3. Qué Cifra a Qué

```
CONTRASEÑA DEL USUARIO
    │
    ├─ [Django PBKDF2] ──────────────────────────────► campo `password` (auth estándar)
    │
    └─ [Scrypt(password, salt_login)] ──► clave_login_32B
            │
            └─ [AES-256-EAX] ──────────────────────────► llave_privada_RSA_usuario
                                                               │
                                    (también envuelta con)     │
                                    [AES-EAX(SECRET_KEY)] ─────┘ (EncryptedTextField en BD)

SECRET_KEY (Django)
    │
    └─ [SHA-256] ──► db_key_32B
            │
            └─ [AES-256-EAX] ──────────────────────────► campo `telefono` (EncryptedCharField)

LLAVE PÚBLICA RSA DEL USUARIO (o del ROL)
    │
    ├─ [RSA-2048 PKCS1-OAEP] ──────────────────────────► llave_aes_cifrada (en AccesoExpediente)
    │
    └─ [AES-256-EAX + RSA-2048 híbrido] ──────────────► llave_privada_rol_cifrada (en AccesoLlaveRol)

LLAVE AES-256 (por expediente, aleatoria)
    │
    └─ [AES-256-EAX] ──────────────────────────────────► datos_cifrados (Expediente)

LLAVE PRIVADA RSA DEL USUARIO (de firma / .key file)
    │
    └─ [RSA-2048 + SHA-256 PKCS#1 v1.5] ───────────────► firma_digital (Expediente / SolicitudARCO)

FOLIO + NOMBRE_COMPLETO DEL MIGRANTE (portal público)
    │
    └─ [Scrypt(folio:nombre, salt=SHA-256(folio))] ──► clave_folio_32B
            │
            └─ [AES-256-EAX] ──────────────────────────► llave_aes_cifrada
                                                          (AccesoExpediente tipo='Migrante')

HASH DEL REGISTRO ANTERIOR + DATOS DEL EVENTO
    │
    └─ [SHA-256] ───────────────────────────────────────► hash_registro (BitacoraEvento)
```

---

## 4. Flujo de Login

```
USUARIO                         SERVIDOR                          BASE DE DATOS
  │                                │                                    │
  │── username + password ────────►│                                    │
  │                                │── SELECT usuario WHERE username ──►│
  │                                │◄─ {rol, salt_login, llave_privada, │
  │                                │    certificado_digital, ...} ──────│
  │                                │                                    │
  │                                ├─ [1] Django auth.authenticate()    │
  │                                │   verifica PBKDF2(password) vs     │
  │                                │   campo `password`                 │
  │                                │                                    │
  │                                ├─ [2] Descifrar `llave_privada`:    │
  │                                │   a) AES-EAX(SECRET_KEY) ──► PEM   │
  │                                │      cifrado con Scrypt             │
  │                                │   b) clave = Scrypt(password,       │
  │                                │              salt_login)            │
  │                                │   c) AES-EAX(clave) ──► PEM puro  │
  │                                │      → sesión: _llave_privada_cache│
  │                                │                                    │
  │                                ├─ [3] Verificar certificado X.509:  │
  │                                │   ¿fecha_expiracion > ahora?       │
  │                                │   Si expiró → redirige a renovar   │
  │                                │                                    │
  │                                ├─ [4] Cargar llaves de rol:         │
  │                                │   SELECT AccesoLlaveRol WHERE      │
  │                                │   usuario_id = usuario.id ────────►│
  │                                │◄─ [{llave_privada_rol_cifrada}] ───│
  │                                │                                    │
  │                                │   Para cada fila:                  │
  │                                │   a) JSON.parse(paquete_hibrido)   │
  │                                │   b) RSA-OAEP(llave_privada_cache) │
  │                                │      ──► llave_aes_rol             │
  │                                │   c) AES-EAX(llave_aes_rol)        │
  │                                │      ──► llave_privada_rol_PEM     │
  │                                │   → sesión: _llaves_rol_cache[rol] │
  │                                │                                    │
  │                                ├─ [5] Registrar en BitacoraEvento:  │
  │                                │   tipo=LOGIN, hash=SHA256(prev|...) │
  │                                │                                    │
  │◄── redirect dashboard ─────────│                                    │
  │                                │                                    │
```

**Datos en sesión tras login exitoso:**

| Clave de sesión         | Contenido                                   | Cuándo se limpia    |
| ----------------------- | ------------------------------------------- | ------------------- |
| `_llave_privada_cache`  | Llave privada RSA-2048 PEM del usuario      | Logout              |
| `_llaves_rol_cache`     | Dict `{rol: llave_privada_PEM}`             | Logout              |
| `llave_privada_firma`   | Llave privada del archivo `.key` (SAT)      | Logout o 15 min     |
| `tiempo_firma_reciente` | Timestamp UNIX de cuando se subió el `.key` | Logout o expiración |

---

## 5. Flujo de Certificados por Rol

### 5.1 ¿Quién tiene certificado?

| Rol                        |      Tiene X.509       |             Puede firmar             | Puede subir `.key` |
| -------------------------- | :--------------------: | :----------------------------------: | :----------------: |
| Administrador              |   Sí (Auto-firmado)    | Sí (Gestión y firma de certificados) |         Sí         |
| Coordinador_Administracion | Sí (Firmado por Admin) |   Sí (Operaciones de expedientes)    |         Sí         |
| Coordinador_Legal          | Sí (Firmado por Admin) |   Sí (Operaciones de expedientes)    |         Sí         |
| Coordinador_Psicosocial    | Sí (Firmado por Admin) |   Sí (Operaciones de expedientes)    |         Sí         |
| Coordinador_Humanitario    | Sí (Firmado por Admin) |   Sí (Operaciones de expedientes)    |         Sí         |
| Coordinador_Comunicacion   | Sí (Firmado por Admin) |   Sí (Operaciones de expedientes)    |         Sí         |
| Operativo                  |           No           |     No (Autorización vía Login)      |         No         |
| Usuario                    |           No           |     No (Autorización vía Login)      |         No         |

> **Jerarquía "Doble Llave":** Los roles Operativo y Usuario operan exclusivamente con la llave de acceso básica descifrada automáticamente en el login. Los roles Coordinador y Administrador usan certificados. El Administrador usa su `.key` para firmar digitalmente los certificados de los Coordinadores que crea, estableciendo una cadena de confianza estricta.

### 5.2 Ciclo de vida del certificado

```
CREACIÓN DE USUARIO (Admin)
        │
        ├─ [1] Generar salt_login = secrets.token_hex(32)
        │
        ├─ [2] Generar par RSA-2048:
        │       llave_privada_PEM, llave_publica_PEM
        │
        ├─ [3] Cifrar llave_privada para BD:
        │       clave = Scrypt(password_temp, salt_login)
        │       llave_privada_cifrada = AES-EAX(clave, llave_privada_PEM)
        │       → almacena en llave_privada (EncryptedTextField)
        │
        ├─ [4] Generar certificado X.509 (Jerárquico):
        │       cert = X509()
        │       cert.subject = CN=username, O=CasaMonarca
        │       cert.valid_from = hoy
        │       cert.valid_to  = hoy + 365 días
        │       Si creador es Admin (con .key activo):
        │           cert.issuer = CN=username_admin
        │           cert.sign(llave_privada_firma_admin, SHA256)
        │       Si es root/autogenerado:
        │           cert.issuer = CN=username
        │           cert.sign(llave_privada_PEM, SHA256)
        │       → almacena en certificado_digital (PEM)
        │       → almacena en fecha_expiracion_certificado
        │
        ├─ [5] Generar llave_firma (passphrase para .key):
        │       llave_firma = secrets.token_hex(32)  [64 chars hex]
        │       → mostrada UNA SOLA VEZ al admin creador
        │
        ├─ [6] Exportar .key (PKCS#8 DER cifrado):
        │       key_bytes = PKCS8_DER(llave_privada_PEM, passphrase=llave_firma)
        │       → generado on-the-fly al descargar
        │
        └─ [7] Generar ZIP descargable (una sola vez):
                ├─ usuario.cer  (certificado X.509 DER/PEM)
                └─ usuario.key  (PKCS#8 DER cifrado con llave_firma)
```

### 5.3 Flujo de Ingreso de Firma (operación crítica)

```
USUARIO (Admin/Coordinador)     SERVIDOR
     │                             │
     │── POST /ingresar-firma/ ───►│
     │   body: {archivo .key,      │
     │           passphrase}       │
     │                             ├─ [1] Leer bytes del .key subido
     │                             │
     │                             ├─ [2] Descifrar PKCS#8:
     │                             │   importar_llave_privada_der(bytes, passphrase)
     │                             │   → llave_privada_firma_PEM
     │                             │
     │                             ├─ [3] Verificar correspondencia con certificado:
     │                             │   modulus(.key) == modulus(certificado_digital)
     │                             │   Si no coincide → error "llave no corresponde"
     │                             │
     │                             ├─ [4] Guardar en sesión:
     │                             │   sesión['llave_privada_firma'] = PEM
     │                             │   sesión['tiempo_firma_reciente'] = time.time()
     │                             │
     │◄── redirect (válido 15 min) ─│
     │                             │
     │── POST operación crítica ──►│
     │                             │
     │                             ├─ @firma_requerida verifica:
     │                             │   time.time() - tiempo_firma_reciente < 900s
     │                             │   Si expiró → redirect a ingresar_firma
     │                             │
     │                             └─ Ejecutar operación con llave_privada_firma
```

### 5.4 Flujo de Renovación de Certificado

```
MIDDLEWARE (cada request)
     │
     └─ CertificadoExpiracionMiddleware
            │
            ├─ ¿fecha_expiracion_certificado < ahora?
            │     No ──► continúa normal
            │     Sí ──► redirect a /regenerar-identidad/
            │
/regenerar-identidad/ (view)
     │
     ├─ [1] Generar nuevo par RSA-2048
     ├─ [2] Generar nuevo X.509 (1 año, firmado por Admin usando sesión.llave_privada_firma)
     ├─ [3] Re-cifrar llave_privada con Scrypt(password) + AES-EAX
     ├─ [4] Re-distribuir llaves de rol (AccesoLlaveRol) con nueva llave pública
     ├─ [5] Generar nuevo .key exportable
     └─ [6] Actualizar BD: llave_publica, llave_privada, certificado_digital, fecha_expiracion
```

---

## 6. Flujo de Creación de Expediente

```
USUARIO (cualquier rol con puede_crear_expediente)
     │
     ├─ [1] Llenar formulario con datos del migrante
     │
     ├─ [2] Backend genera llave_aes = os.urandom(32)  [256 bits]
     │
     ├─ [3] Cifrar datos:
     │       cipher = AES-EAX(llave_aes)
     │       datos_cifrados, nonce, tag = cipher.encrypt(JSON(formulario))
     │
     ├─ [4] Calcular hash:
     │       hash_expediente = SHA256(datos_cifrados)
     │
     ├─ [5] Distribuir acceso (una entrada por entidad):
     │       Para el CREADOR:
     │         llave_aes_cifrada = RSA-OAEP(llave_publica_usuario, llave_aes)
     │         AccesoExpediente(tipo='Creador', usuario=creador, ...)
     │
     │       Para cada ROL con acceso:
     │         llave_aes_cifrada = RSA-OAEP(llave_publica_rol, llave_aes)
     │         AccesoExpediente(tipo=nombre_rol, usuario=None, ...)
     │
     ├─ [6] Guardar Expediente en BD:
     │       datos_cifrados (base64), nonce (base64), tag (base64),
     │       hash_expediente, verificado=False, firma_digital=""
     │
     └─ [7] Registrar en BitacoraEvento: tipo=CREACION
```

### 6.1 Flujo de Lectura de Expediente

```
USUARIO (con acceso al expediente)
     │
     ├─ [1] Recuperar AccesoExpediente WHERE expediente=X AND usuario=yo
     │       → llave_aes_cifrada (base64 RSA)
     │
     ├─ [2] Descifrar llave AES:
     │       a) Si acceso de tipo 'Creador':
     │           llave_aes = RSA-OAEP(sesión._llave_privada_cache, llave_aes_cifrada)
     │       b) Si acceso de tipo rol:
     │           llave_priv_rol = sesión._llaves_rol_cache[tipo_acceso]
     │           llave_aes = RSA-OAEP(llave_priv_rol, llave_aes_cifrada)
     │
     ├─ [3] Descifrar datos:
     │       plaintext = AES-EAX(llave_aes, nonce, tag).decrypt(datos_cifrados)
     │       datos = JSON.parse(plaintext)
     │
     └─ [4] Verificar integridad:
             SHA256(datos_cifrados) == hash_expediente  →  OK / ALERTA
```

---

### 6.2 Acceso del Migrante por Folio (Portal público)

El migrante recibe un folio único (formato `CM-YYYYMMDD-XXXX`) al ser registrado por un Operativo. Con ese folio **más su nombre completo** puede acceder a un portal público (`/mi-expediente/`) y ver sus datos en modo solo lectura, sin necesidad de cuenta. La criptografía es simétrica y derivada del par (folio, nombre).

**Al crear el expediente (en [expediente/views.py](expediente/views.py)):**

```
Backend:
  ├─ folio = generar_folio()                # CM-YYYYMMDD-XXXX único
  ├─ datos['folio'] = folio                 # se cifra dentro de datos_cifrados
  ├─ folio_hash = SHA-256(folio)            # columna folio_hash, indexada
  ├─ nombre_completo = "{nombre_pila} {primer_apellido} {segundo_apellido}"
  ├─ clave_folio = Scrypt(folio + ":" + nombre_completo,
  │                       salt=SHA-256(folio),
  │                       N=16384, r=8, p=1, dklen=32)
  ├─ llave_aes_migrante = AES-256-EAX(clave_folio).encrypt(llave_aes_expediente)
  └─ AccesoExpediente(
         tipo_acceso='Migrante',
         usuario=None,
         llave_aes_cifrada=llave_aes_migrante
     )
```

**Al ingresar el migrante (en [portal_migrante/views.py](portal_migrante/views.py)):**

```
Migrante                          Servidor
  │                                 │
  │── POST nombre + folio ─────────►│
  │                                 ├─ [1] Rate-limit: max 5 intentos/15min por IP
  │                                 │      (sesión: _arco_intentos_fallidos)
  │                                 │
  │                                 ├─ [2] folio_hash = SHA-256(folio)
  │                                 │      Expediente.objects.filter(folio_hash=...)
  │                                 │
  │                                 ├─ [3] AccesoExpediente WHERE
  │                                 │      tipo_acceso='Migrante' AND expediente=X
  │                                 │      → llave_aes_cifrada
  │                                 │
  │                                 ├─ [4] clave_folio = Scrypt(folio:nombre, salt=SHA-256(folio))
  │                                 │      llave_aes = AES-EAX(clave_folio).decrypt(llave_aes_cifrada)
  │                                 │
  │                                 │      Si falla → "Folio o nombre incorrecto"
  │                                 │      (mismo mensaje siempre; no filtra info)
  │                                 │
  │                                 ├─ [5] datos = AES-EAX(llave_aes, nonce, tag).decrypt(datos_cifrados)
  │                                 │
  │                                 ├─ [6] Sesión (15 min sliding):
  │                                 │      _migrante_expediente_id, _migrante_datos,
  │                                 │      _migrante_ts, _migrante_folio_hash
  │                                 │
  │◄── redirect dashboard ──────────│      → BitacoraEvento(tipo='acceso_migrante')
```

**Por qué Scrypt(folio:nombre):**
- Doble factor "algo que tiene" (folio) + "algo que es" (nombre) sin password.
- El folio aleatorio (~16 bits de entropía visible + timestamp) garantiza unicidad y dificulta enumeración masiva.
- El salt = SHA-256(folio) hace cada derivación independiente: comprometer una clave no revela ninguna otra.
- Scrypt N=16384 hace que un atacante con la BD necesite ~10ms/intento para probar combinaciones (folio, nombre) — combinado con el rate limit, infeasible a escala.
- La organización **no puede** descifrar como migrante: ese acceso solo existe con el nombre real del migrante, no almacenado en claro.

---

## 7. Flujo de Operación Crítica (Firma)

Requerida por el decorador `@firma_requerida` para: **Editar Expediente**, **Eliminar Expediente**, **Verificar** y la gestión en el **Panel de Administración**.

> **Recifrado Dinámico (Edición/Eliminación):** El sistema recifra dinámicamente usando las llaves AES del expediente en curso y actualiza el Hash de integridad sin necesidad de llaves externas, para después validar y asentar la firma final usando el `.key` de SAT subido en sesión.

```
COORDINADOR (con .key cargado en sesión, válido 15 min)
     │
     ├─ [1] @firma_requerida verifica timestamp en sesión
     │
     ├─ [2] Calcular hash del expediente:
     │       hash_exp = SHA256(datos_cifrados)
     │
     ├─ [3] Firmar con llave privada de firma:
     │       firma = RSA-2048-PKCS1v15(sesión.llave_privada_firma, SHA256(hash_exp))
     │       → firma en Base64
     │
     ├─ [4] Guardar firma en BD:
     │       Expediente.firma_digital = firma_b64
     │       Expediente.verificado = True
     │
     └─ [5] Verificación posterior (cualquier usuario):
             RSA-verify(firma_b64, hash_exp, llave_publica_usuario)
             → True / False (tampering detectado si False)
```

---

## 8. Cadena de Auditoría

Cada evento en `BitacoraEvento` es un eslabón de una cadena hash que detecta manipulación retroactiva.

```
Evento N-1:
    hash_registro[N-1] = SHA256(
        hash_registro[N-2] | usuario_id | tipo | descripcion | fecha
    )

Evento N:
    hash_registro[N] = SHA256(
        hash_registro[N-1] | usuario_id | tipo | descripcion | fecha
    )

Para verificar integridad:
    Recalcular hash_registro[i] para i = 0..N
    Si alguno no coincide con el almacenado → REGISTRO MANIPULADO
```

**Eventos registrados:**

| Tipo                                  | Cuándo se registra                                                       |
| ------------------------------------- | ------------------------------------------------------------------------ |
| `LOGIN`                               | Inicio de sesión exitoso                                                 |
| `LOGOUT`                              | Cierre de sesión                                                         |
| `CREACION`                            | Creación de expediente                                                   |
| `EDICION`                             | Modificación de expediente                                               |
| `ELIMINACION`                         | Eliminación de expediente                                                |
| `FIRMA`                               | Firma digital de expediente                                              |
| `EXPORTACION`                         | Exportación de expediente                                                |
| `CAMBIO_ROL`                          | Cambio de rol de usuario                                                 |
| `CREACION_USUARIO`                    | Alta de nuevo usuario                                                    |
| `REVOCACION_CERT`                     | Revocación de certificado                                                |
| `acceso_migrante`                     | Migrante autenticado correctamente en el portal público                  |
| `acceso_migrante_fallido`             | Intento fallido en el portal (folio/nombre/IP bloqueada)                 |
| `solicitud_arco_creada`               | Solicitud ARCO enviada por el migrante                                   |
| `solicitud_arco_aprobada`             | Operativo aprobó / pre-aprobó                                            |
| `solicitud_arco_rechazada`            | Cualquier actor rechazó la solicitud                                     |
| `solicitud_arco_firmada_cancelacion`  | Coordinador firmó una cancelación (queda pendiente del Admin)            |
| `solicitud_arco_ejecutada`            | Rectificación u oposición aplicada por Coordinador                       |
| `solicitud_arco_cancelacion_rechazada`| Admin rechazó la ejecución final de una cancelación                      |
| `expediente_cancelado_arco`           | Admin ejecutó la cancelación: expediente eliminado físicamente           |

---

## 9. Diagrama General del Sistema

```
╔══════════════════════════════════════════════════════════════════════╗
║                        CAPAS DE SEGURIDAD                           ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  [USUARIO FINAL]                                                     ║
║       │  password  ──► PBKDF2 (Django auth) ──► usuarios_usuario    ║
║       │  password  ──► Scrypt + AES-EAX ──► llave_privada (cifrada) ║
║       │                                                              ║
║  [SESIÓN EN MEMORIA — NUNCA PERSISTIDA EN BD]                        ║
║       ├── _llave_privada_cache    (RSA-2048 PEM del usuario)        ║
║       ├── _llaves_rol_cache       (RSA-2048 PEM de cada rol)        ║
║       └── llave_privada_firma     (RSA-2048 PEM del .key subido)    ║
║                                                                      ║
║  [BASE DE DATOS — TODO DATO SENSIBLE CIFRADO]                        ║
║                                                                      ║
║  ┌─────────────────────────────────────────────────────────────┐    ║
║  │  usuarios_usuario                                           │    ║
║  │    llave_privada ◄─── AES-EAX(SECRET_KEY)                  │    ║
║  │                  ◄─── AES-EAX(Scrypt(password, salt))      │    ║
║  │    telefono      ◄─── AES-EAX(SECRET_KEY)                  │    ║
║  └───────────────────────────┬─────────────────────────────────┘    ║
║                              │ RSA-2048 llave_publica               ║
║  ┌───────────────────────────▼─────────────────────────────────┐    ║
║  │  usuarios_accesollaverol                                    │    ║
║  │    llave_privada_rol_cifrada ◄─── RSA-OAEP(llave_publica   │    ║
║  │                                       _usuario)             │    ║
║  └───────────────────────────┬─────────────────────────────────┘    ║
║                              │ llave_privada_rol (en sesión)        ║
║  ┌───────────────────────────▼─────────────────────────────────┐    ║
║  │  expediente_accesoexpediente                                │    ║
║  │    llave_aes_cifrada ◄─── RSA-OAEP(llave_publica_rol /     │    ║
║  │                                    llave_publica_usuario)   │    ║
║  └───────────────────────────┬─────────────────────────────────┘    ║
║                              │ llave_aes (32 bytes, en memoria)     ║
║  ┌───────────────────────────▼─────────────────────────────────┐    ║
║  │  expediente_expediente                                      │    ║
║  │    datos_cifrados ◄──── AES-256-EAX(llave_aes)             │    ║
║  │    nonce, tag     ──── parámetros AES-EAX                   │    ║
║  │    hash_expediente ◄── SHA-256(datos_cifrados)              │    ║
║  │    firma_digital  ◄─── RSA-2048-PKCS1(llave_firma)         │    ║
║  └─────────────────────────────────────────────────────────────┘    ║
║                                                                      ║
║  ┌─────────────────────────────────────────────────────────────┐    ║
║  │  auditoria_bitacoraevento                                   │    ║
║  │    hash_registro ◄── SHA-256(hash_anterior | evento)        │    ║
║  └─────────────────────────────────────────────────────────────┘    ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

## 10. Portal del Migrante y Flujo ARCO

El módulo [`portal_migrante/`](portal_migrante/) implementa el ejercicio de los **Derechos ARCO** (Acceso, Rectificación, Cancelación, Oposición) garantizados al migrante por la legislación de protección de datos. El acceso al portal se documenta en [§ 6.2](#62-acceso-del-migrante-por-folio-portal-público); esta sección detalla los tres sub-flujos de solicitud y la cadena criptográfica de cada uno.

### 10.1 Estados de una `SolicitudARCO`

```
                                ┌───────────────────────────┐
                                │     ┌─► rechazada         │
                                │     │   (terminal)        │
   pendiente ──► aprobada_operativo ──► ejecutada (rect./op.)
                                │
                                └─► firmada_coordinador ──► ejecutada (cancel.)
                                                          └─► rechazada
```

- **pendiente**: creada por el migrante; espera al Operativo.
- **aprobada_operativo**: el Operativo aprobó (y, según el tipo, propuso cambios concretos o escribió la etiqueta de oposición).
- **firmada_coordinador**: estado intermedio usado **solo en cancelación**; el Coordinador firmó pero la ejecución física requiere al Admin.
- **ejecutada**: efecto aplicado al expediente (rectificación/oposición) o expediente borrado (cancelación).
- **rechazada**: terminal en cualquier paso.

### 10.2 Quién hace qué

| Acción                              | Migrante | Operativo                       | Coordinador                                | Administrador                              |
| ----------------------------------- | :------: | ------------------------------- | ------------------------------------------ | ------------------------------------------ |
| Crear solicitud                     |    ✅    |                                 |                                            |                                            |
| Aprobar Rectificación + proponer diff |          | ✅ (formulario del expediente)  |                                            |                                            |
| Aprobar Oposición + escribir etiqueta |          | ✅                              |                                            |                                            |
| Pre-aprobar Cancelación             |          | ✅                              |                                            |                                            |
| Firmar Rectificación (aplica diff)  |          |                                 | ✅ (con `.key`)                            | ✅                                         |
| Firmar Oposición (anexa etiqueta)   |          |                                 | ✅ (con `.key`)                            | ✅                                         |
| Firmar validación de Cancelación    |          |                                 | ✅ (con `.key`)                            | ✅                                         |
| **Ejecutar Cancelación** (borrar exp.) |       |                                 |                                            | ✅ (solo Admin, con `.key`)                |

> **Principio de doble control:** ninguna modificación a un expediente ocurre sin la firma criptográfica de un Coordinador (`@firma_requerida`). La eliminación física requiere además la firma de un Administrador, garantizando el principio de mínimo privilegio.

### 10.3 Flujo de Rectificación

```
[1] MIGRANTE (portal público)
     │   POST /mi-expediente/arco/
     │   tipo='rectificacion', descripcion, campos_solicitados
     │
     │   campos_solicitados se cifra con AES-EAX(SECRET_KEY) → BD
     ▼
[2] OPERATIVO
     │   GET /expediente/arco/responder/<pk>/
     │   Sistema: descifra Expediente con _llaves_rol_cache['Operativo']
     │   UI: muestra formulario del expediente PRELLENADO + solicitud
     │   POST aprobar:
     │     diff = {k: v for k, v in nuevos.items()
     │             if str(actuales.get(k)) != str(v)}
     │     solicitud.cambios_propuestos = AES-EAX(SECRET_KEY).encrypt(JSON(diff))
     │     solicitud.estado = 'aprobada_operativo'
     ▼
[3] COORDINADOR (con .key cargado)
     │   GET /expediente/arco/firmar/<pk>/
     │   UI: muestra cambios_dict legible (tabla campo → valor nuevo)
     │   POST firmar:
     │     [a] firma_b64 = RSA-PKCS1v15(llave_privada_firma,
     │                                  f"ARCO-{pk}-rectificacion-{hash}-{ts}")
     │     [b] llave_aes = RSA-OAEP(llaves_rol[rol], AccesoExpediente.llave_aes_cifrada)
     │     [c] datos = AES-EAX(llave_aes).decrypt(expediente.datos_cifrados)
     │     [d] datos.update(cambios_propuestos_dict)
     │     [e] nuevo_paquete = AES-EAX(llave_aes).encrypt(JSON(datos))
     │     [f] expediente.{datos_cifrados, nonce, tag} = nuevo_paquete
     │         expediente.hash_expediente = SHA-256(nuevo_paquete.datos_cifrados)
     │         expediente.firma_digital = RSA-PKCS1v15(llave_privada_firma, hash)
     │         expediente.verificado = True
     │     [g] solicitud.estado = 'ejecutada'
     ▼
   EXPEDIENTE ACTUALIZADO Y FIRMADO
```

### 10.4 Flujo de Cancelación (5 estados)

```
[1] MIGRANTE: POST tipo='cancelacion' → solicitud.estado='pendiente'
     ▼
[2] OPERATIVO: pre-aprueba (sin formulario adicional)
              → solicitud.estado='aprobada_operativo'
     ▼
[3] COORDINADOR (con .key):
       firma_b64 = RSA-PKCS1v15(llave_privada_firma,
                                f"ARCO-{pk}-cancelacion-{hash}-{ts}")
       solicitud.firma_digital = firma_b64
       solicitud.estado = 'firmada_coordinador'   ← Estado intermedio
       (NO se elimina el expediente)
     ▼
[4] ADMINISTRADOR (con .key):
       GET /expediente/arco/ejecutar/<pk>/
       Muestra timeline completo (migrante → operativo → coord → admin)
       POST ejecutar:
         firma_admin = RSA-PKCS1v15(llave_privada_firma,
                                    f"ARCO-CANCEL-{pk}-{exp_id}-{exp_hash}-{ts}")
         solicitud.firma_digital_admin = firma_admin
         solicitud.estado = 'ejecutada'
         BitacoraEvento(tipo='expediente_cancelado_arco',
                        descripcion=f'Expediente #{exp_id} (hash={exp_hash}) eliminado...')
         SolicitudARCO.objects.filter(expediente=exp).update(expediente=None)
         expediente.delete()
     ▼
[5] EXPEDIENTE BORRADO FÍSICAMENTE
   (Las solicitudes ARCO previas conservan registro histórico con expediente=NULL)
```

> **Auditoría tras borrado:** antes del `delete()` se registra el `hash_expediente` previo en la bitácora, junto con la firma RSA del Admin. Esto permite demostrar, sin guardar PII, que la eliminación se realizó conforme al procedimiento ARCO firmado.

### 10.5 Flujo de Oposición

```
[1] MIGRANTE: POST tipo='oposicion'
     ▼
[2] OPERATIVO: escribe etiqueta_oposicion (texto libre)
              → cifrada con AES-EAX(SECRET_KEY) en BD
              → solicitud.estado='aprobada_operativo'
     ▼
[3] COORDINADOR (con .key):
       firma_b64 = RSA-PKCS1v15(...)
       expediente.etiquetas_oposicion (JSON cifrado en BD):
         append({fecha, etiqueta, coordinador, solicitud_arco_id})
       solicitud.estado='ejecutada'
     ▼
   EXPEDIENTE CON ETIQUETA VISIBLE A ROLES DE LECTURA
```

### 10.6 Resumen criptográfico del flujo ARCO

| Pieza                              | Algoritmo                | Llave                                     |
| ---------------------------------- | ------------------------ | ----------------------------------------- |
| `descripcion_cifrada` (BD)         | AES-256-EAX              | SHA-256(`SECRET_KEY`)                     |
| `campos_solicitados` (BD)          | AES-256-EAX              | SHA-256(`SECRET_KEY`)                     |
| `cambios_propuestos` (BD)          | AES-256-EAX              | SHA-256(`SECRET_KEY`)                     |
| `etiqueta_oposicion` (BD)          | AES-256-EAX              | SHA-256(`SECRET_KEY`)                     |
| `expediente.etiquetas_oposicion`   | AES-256-EAX              | SHA-256(`SECRET_KEY`)                     |
| `solicitud.firma_digital` (coord.) | RSA-2048 + SHA-256 PKCS1 | `llave_privada_firma` (`.key` SAT, sesión)|
| `solicitud.firma_digital_admin`    | RSA-2048 + SHA-256 PKCS1 | `llave_privada_firma` (`.key` SAT, sesión)|
| Re-cifrado del expediente (rect.)  | AES-256-EAX              | Llave AES original del expediente (reutilizada) |
| Nueva `expediente.firma_digital`   | RSA-2048 + SHA-256 PKCS1 | `llave_privada_firma` del Coordinador     |

---

## Notas de Seguridad

- **La llave AES del expediente nunca se almacena en claro.** Se genera en RAM, se usa para cifrar y se descarta; sólo persiste su forma cifrada por RSA en `AccesoExpediente`.
- **La llave privada del usuario nunca sale de la sesión en claro.** El campo en BD siempre está doblemente cifrado (SECRET_KEY + password).
- **El archivo `.key` es descargable una sola vez** en el momento de creación del usuario. No hay mecanismo de recuperación si se pierde; sólo regenerar identidad.
- **El middleware `CertificadoExpiracionMiddleware` es la última línea de defensa:** bloquea cada request si el certificado del usuario autenticado está vencido.
- **La bitácora es append-only por diseño:** el encadenamiento SHA-256 hace que cualquier eliminación o modificación de registros sea detectable al recalcular la cadena.
- **`SECRET_KEY` de Django es crítica:** si se compromete, todos los `EncryptedTextField`/`EncryptedCharField` de la BD quedan expuestos. Debe rotarse con re-cifrado de todos los campos.
