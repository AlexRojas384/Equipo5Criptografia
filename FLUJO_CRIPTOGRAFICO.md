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

---

## 1. Primitivas Criptográficas

| Algoritmo | Parámetros | Uso en el sistema |
|-----------|-----------|-------------------|
| **RSA-2048** | PKCS1-OAEP / PKCS#1 v1.5 | Par de llaves por usuario, par de llaves por rol, certificados X.509 |
| **AES-256-EAX** | Nonce 16B, Tag 16B | Cifrado de datos de expedientes y llaves privadas en reposo |
| **Scrypt** | N=16384, r=8, p=1, dklen=32 | Derivación de clave desde la contraseña del usuario (login) |
| **SHA-256** | Hex 64 chars | Hash de expedientes, encadenamiento de bitácora, firma digital |
| **X.509** | Self-signed, 1 año | Certificado digital por usuario (estilo SAT) |
| **PKCS#8** | Cifrado con AES-256-CBC + Scrypt | Exportación de llave privada al archivo `.key` descargable |
| **AES-EAX (DB)** | Derivada de `SECRET_KEY` via SHA-256 | Cifrado transparente de campos sensibles en base de datos |

---

## 2. Esquema de Base de Datos

### 2.1 `usuarios_usuario`

Modelo de usuario extendido de Django `AbstractUser`.

| Columna | Tipo | Cifrado | Descripción |
|---------|------|---------|-------------|
| `id` | INT | No | Identificador primario |
| `username` | VARCHAR | No | Nombre de usuario único |
| `password` | VARCHAR | Django PBKDF2 | Hash de contraseña gestionado por Django Auth |
| `rol` | VARCHAR | No | Rol RBAC asignado (uno de los 8 roles del sistema) |
| `telefono` | TEXT | **AES-EAX (SECRET_KEY)** | Teléfono cifrado transparentemente con `EncryptedCharField` |
| `activo` | BOOL | No | Indica si la cuenta está habilitada |
| `llave_publica` | LONGTEXT | No | Llave pública RSA-2048 en formato PEM — accesible públicamente |
| `llave_privada` | LONGTEXT | **AES-EAX (SECRET_KEY)** | Llave privada RSA-2048 PEM protegida con `EncryptedTextField` (cifrado transparente de BD) + internamente re-cifrada con Scrypt(password) + AES-EAX |
| `salt_login` | VARCHAR(64) | No | Salt hexadecimal de 32 bytes para Scrypt; único por usuario |
| `certificado_digital` | LONGTEXT | No | Certificado X.509 PEM (self-signed, 1 año de vigencia) |
| `fecha_expiracion_certificado` | DATETIME | No | Fecha de expiración del certificado; el middleware bloquea el acceso si expiró |

> **Doble cifrado en `llave_privada`:** el campo en la BD siempre está envuelto por `EncryptedTextField` (AES-EAX derivado de `SECRET_KEY`). El valor descifrado de BD es, a su vez, la llave privada RSA-2048 re-cifrada con `Scrypt(password) + AES-EAX`. Sólo el usuario que conoce su contraseña puede descifrar su llave privada.

---

### 2.2 `usuarios_llaverol`

Una fila por cada rol del sistema. Almacena el par RSA-2048 **del rol**, no del usuario.

| Columna | Tipo | Cifrado | Descripción |
|---------|------|---------|-------------|
| `id` | INT | No | Identificador primario |
| `rol` | VARCHAR(50) | No | Nombre del rol (`Administrador`, `Coordinador_Legal`, etc.) — único |
| `llave_publica` | LONGTEXT | No | Llave pública RSA-2048 PEM del rol; usada para cifrar las llaves AES de expedientes accesibles por ese rol |

---

### 2.3 `usuarios_accesollaverol`

Tabla de unión que entrega la llave **privada** de cada rol a cada usuario autorizado.

| Columna | Tipo | Cifrado | Descripción |
|---------|------|---------|-------------|
| `id` | INT | No | Identificador primario |
| `llave_rol_id` | INT (FK → LlaveRol) | No | Referencia al rol cuya llave privada se está distribuyendo |
| `usuario_id` | INT (FK → Usuario) | No | Referencia al usuario receptor |
| `llave_privada_rol_cifrada` | LONGTEXT | **RSA-2048 + AES-256-EAX** | JSON con paquete híbrido: `{nonce, tag, llave_aes_cifrada, datos_cifrados}`. La llave AES se cifra con la llave pública del usuario; los datos (llave privada del rol) con AES-EAX |

> **Principio:** cada usuario sólo puede desempaquetar la llave privada de su rol usando su propia llave privada RSA. Sin ella, la llave privada del rol es ilegible.

---

### 2.4 `usuarios_solicitudrol`

Solicitudes de cambio de rol enviadas por usuarios y respondidas por administradores.

| Columna | Tipo | Cifrado | Descripción |
|---------|------|---------|-------------|
| `id` | INT | No | Identificador primario |
| `solicitante_id` | INT (FK → Usuario) | No | Usuario que solicita el cambio |
| `rol_actual` | VARCHAR | No | Rol vigente al momento de la solicitud |
| `rol_solicitado` | VARCHAR | No | Rol al que se desea cambiar |
| `estado` | VARCHAR | No | `pendiente`, `aprobada` o `rechazada` |
| `respondido_por_id` | INT (FK → Usuario) | No | Administrador que respondió (nullable) |
| `fecha_solicitud` | DATETIME | No | Marca temporal de la solicitud |

---

### 2.5 `expediente_expediente`

Expedientes de personas atendidas. **Ningún dato personal es legible en reposo.**

| Columna | Tipo | Cifrado | Descripción |
|---------|------|---------|-------------|
| `id` | INT | No | Identificador primario |
| `creado_por_id` | INT (FK → Usuario) | No | Usuario que creó el expediente |
| `fecha_creacion` | DATETIME | No | Timestamp de creación (auto) |
| `fecha_atencion` | DATE | No | Fecha de atención al caso |
| `datos_cifrados` | LONGTEXT | **AES-256-EAX** | Ciphertext Base64 con todos los datos personales del expediente |
| `nonce` | TEXT | No | Nonce AES-EAX en Base64 (16 bytes); único por expediente |
| `tag` | TEXT | No | Tag de autenticación AES-EAX en Base64; permite detectar manipulación |
| `verificado` | BOOL | No | Indica si el expediente fue verificado/firmado por un rol autorizado |
| `firma_digital` | LONGTEXT | No | Firma RSA-2048 + SHA-256 (PKCS#1 v1.5) en Base64 del hash del expediente |
| `hash_expediente` | VARCHAR(64) | No | SHA-256 del ciphertext; parte de lo firmado digitalmente |

---

### 2.6 `expediente_accesoexpediente`

Control de acceso granular: una fila por cada entidad (usuario o rol) que puede descifrar un expediente.

| Columna | Tipo | Cifrado | Descripción |
|---------|------|---------|-------------|
| `id` | INT | No | Identificador primario |
| `expediente_id` | INT (FK → Expediente) | No | Expediente al que da acceso |
| `tipo_acceso` | VARCHAR | No | `'Creador'` o nombre del rol (ej. `'Coordinador_Legal'`) |
| `usuario_id` | INT (FK → Usuario) | No | Usuario concreto (nullable para accesos de rol genérico) |
| `llave_aes_cifrada` | LONGTEXT | **RSA-2048 (PKCS1-OAEP)** | La llave AES-256 del expediente, cifrada con la llave pública del usuario o del rol. Sólo quien tenga la llave privada correspondiente puede recuperar la llave AES |

> **Cifrado sobre-enumerado:** si un expediente tiene 3 roles con acceso, existirán 3 filas `AccesoExpediente`, cada una con la misma llave AES-256 cifrada con una llave pública diferente. Los datos cifrados (`datos_cifrados`) son únicos y compartidos.

---

### 2.7 `auditoria_bitacoraevento`

Registro de auditoría con integridad garantizada por encadenamiento de hashes.

| Columna | Tipo | Cifrado | Descripción |
|---------|------|---------|-------------|
| `id` | INT | No | Identificador primario |
| `usuario_id` | INT (FK → Usuario) | No | Usuario que generó el evento (nullable si es del sistema) |
| `tipo` | VARCHAR | No | Tipo de evento (login, creación, edición, firma, etc.) |
| `descripcion` | TEXT | No | Descripción legible del evento |
| `fecha` | DATETIME | No | Timestamp del evento |
| `ip` | VARCHAR | No | Dirección IP del cliente |
| `hash_registro` | VARCHAR(64) | No | SHA-256 del registro actual encadenado con el anterior |

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
    └─ [RSA-2048 + SHA-256 PKCS#1 v1.5] ───────────────► firma_digital (Expediente)

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

| Clave de sesión | Contenido | Cuándo se limpia |
|-----------------|-----------|-----------------|
| `_llave_privada_cache` | Llave privada RSA-2048 PEM del usuario | Logout |
| `_llaves_rol_cache` | Dict `{rol: llave_privada_PEM}` | Logout |
| `llave_privada_firma` | Llave privada del archivo `.key` (SAT) | Logout o 15 min |
| `tiempo_firma_reciente` | Timestamp UNIX de cuando se subió el `.key` | Logout o expiración |

---

## 5. Flujo de Certificados por Rol

### 5.1 ¿Quién tiene certificado?

| Rol | Tiene X.509 | Puede firmar expedientes | Puede subir `.key` |
|-----|:-----------:|:-----------------------:|:------------------:|
| Administrador | Sí | No (gestión) | No |
| Coordinador_Administracion | Sí | Sí | Sí |
| Coordinador_Legal | Sí | Sí | Sí |
| Coordinador_Psicosocial | Sí | Sí | Sí |
| Coordinador_Humanitario | Sí | Sí | Sí |
| Coordinador_Comunicacion | Sí | Sí | Sí |
| Operativo | Sí | No | No |
| Usuario | Sí | No | No |

> Todos los usuarios tienen un certificado X.509 generado al crear la cuenta. La distinción es quién puede usar el `.key` para operaciones críticas (decorador `@firma_requerida`).

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
        ├─ [4] Generar certificado X.509:
        │       cert = X509()
        │       cert.subject = CN=username, O=CasaMonarca
        │       cert.valid_from = hoy
        │       cert.valid_to  = hoy + 365 días
        │       cert.sign(llave_privada_PEM, SHA256)
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
USUARIO (Coordinador)           SERVIDOR
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
     ├─ [2] Generar nuevo X.509 (1 año)
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

## 7. Flujo de Operación Crítica (Firma)

Requerida para: editar expediente, verificar expediente, operaciones administrativas sensibles.

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

| Tipo | Cuándo se registra |
|------|-------------------|
| `LOGIN` | Inicio de sesión exitoso |
| `LOGOUT` | Cierre de sesión |
| `CREACION` | Creación de expediente |
| `EDICION` | Modificación de expediente |
| `ELIMINACION` | Eliminación de expediente |
| `FIRMA` | Firma digital de expediente |
| `EXPORTACION` | Exportación de expediente |
| `CAMBIO_ROL` | Cambio de rol de usuario |
| `CREACION_USUARIO` | Alta de nuevo usuario |
| `REVOCACION_CERT` | Revocación de certificado |

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

## Notas de Seguridad

- **La llave AES del expediente nunca se almacena en claro.** Se genera en RAM, se usa para cifrar y se descarta; sólo persiste su forma cifrada por RSA en `AccesoExpediente`.
- **La llave privada del usuario nunca sale de la sesión en claro.** El campo en BD siempre está doblemente cifrado (SECRET_KEY + password).
- **El archivo `.key` es descargable una sola vez** en el momento de creación del usuario. No hay mecanismo de recuperación si se pierde; sólo regenerar identidad.
- **El middleware `CertificadoExpiracionMiddleware` es la última línea de defensa:** bloquea cada request si el certificado del usuario autenticado está vencido.
- **La bitácora es append-only por diseño:** el encadenamiento SHA-256 hace que cualquier eliminación o modificación de registros sea detectable al recalcular la cadena.
- **`SECRET_KEY` de Django es crítica:** si se compromete, todos los `EncryptedTextField`/`EncryptedCharField` de la BD quedan expuestos. Debe rotarse con re-cifrado de todos los campos.
