# Casa Monarca — Plataforma de Gestión de Expedientes

Sistema de gestión segura para el manejo de expedientes, con cifrado híbrido y control de acceso basado en roles (RBAC).

---

## Requisitos previos

Asegúrate de tener instalado en tu máquina local:

- **Python 3.9** o superior
- **MySQL 8.0**
- **MySQL Workbench** (opcional pero recomendado)
- **Git**

---

## Pasos de Instalación

### 1. Clonar el repositorio

```bash
git clone [https://github.com/tu-usuario/tu-repo.git](https://github.com/tu-usuario/tu-repo.git)
cd tu-repo
```

### 2. Crear y activar el entorno virtual

```bash
python -m venv venv
```

- **Windows:**
  ```bash
  venv\Scripts\activate
  ```
- **Mac/Linux:**
  ```bash
  source venv/bin/activate
  ```

### 3. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 4. Configurar variables de entorno

Crea el siguiente archivo de ejemplo y llena tus credenciales:

> **IMPORTANTE:** Crea el archivo `.env` y completa los valores. **Nunca** subas este archivo al repositorio.

```env
SECRET_KEY=django-insecure-pon-aqui-una-clave-larga-y-aleatoria
DEBUG=True
DB_NAME=casa_monarca
DB_USER=monarca_user
DB_PASSWORD=TuPasswordSeguro
DB_HOST=localhost
DB_PORT=3306
```

### 5. Configurar la base de datos (MySQL)

Ejecuta el siguiente script en tu consola de MySQL o Workbench:

```sql
CREATE DATABASE casa_monarca CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'monarca_user'@'localhost' IDENTIFIED BY 'TuPasswordSeguro';
GRANT ALL PRIVILEGES ON casa_monarca.* TO 'monarca_user'@'localhost';
FLUSH PRIVILEGES;
```

### 6. Ejecutar migraciones

```bash
python manage.py makemigrations
python manage.py migrate
```

### 7. Inicializar llaves de rol

Genera un par de llaves RSA-4096 para cada uno de los 8 roles del sistema:

```bash
python manage.py inicializar_llaves_rol
```

### 8. Crear cuentas de Administrador base

Crea automaticamente las dos cuentas de administrador (produccion y contingencias) y les otorga acceso a **todas** las llaves de rol del sistema:

```bash
python manage.py crear_admins_base
```

> **IMPORTANTE:** Este comando genera las cuentas maestras de acceso. Debido a la arquitectura de "Doble Llave", estos administradores ya podrán iniciar sesión y ver expedientes de inmediato.
>
> Sin embargo, para realizar **operaciones críticas** (como editar, borrar o gestionar usuarios), el sistema te pedirá tu firma digital. El comando crea automáticamente una carpeta llamada `certs_iniciales/` en la raíz del proyecto.
> 1. Copia la **Llave de firma SAT (64 chars)** que aparece en la consola.
> 2. Usa el archivo `.key` que se encuentra en `certs_iniciales/` cuando el sistema te lo solicite.
> 3. Una vez dentro, se recomienda regenerar tu identidad para descargar un nuevo paquete ZIP personal y borrar la carpeta `certs_iniciales/`.

### 9. Levantar el servidor

```bash
python manage.py runserver
```

Accede en: [http://127.0.0.1:8000/usuarios/login/](http://127.0.0.1:8000/usuarios/login/)

Credenciales por defecto:
- **admin_prod** / `CasaMonarca2026!`
- **admin_contingencia** / `CasaMonarca2026!`

---

## Casos Especiales y Solucion de Problemas

### Sesion bloqueada o reenvio constante al Login?

Si tu usuario fue creado sin llaves o hubo un problema, el sistema te cerrara la sesion automaticamente por seguridad.

**Solucion:** Pide a un Administrador que regenere tu identidad criptografica desde el Panel de Admin.

### Cambio de SECRET_KEY

El `SECRET_KEY` en el archivo `.env` se usa como base para el cifrado transparente de la base de datos.

- **Importante:** Si cambias esta clave despues de haber guardado registros (usuarios, expedientes, etc.), no podras descifrar los datos anteriores. Manten la misma clave durante toda la vida del proyecto en el mismo entorno.

---

## Estructura del Proyecto

```text
casa_monarca/
├── config/          # Configuracion de Django
├── usuarios/        # Autenticacion y RBAC con llaves de rol
├── expediente/      # Gestion de expedientes cifrados
├── auditoria/       # Bitacora con chain hash
├── cripto/          # Motor AES-256 + RSA-4096 + X.509
├── templates/       # HTML templates
├── .env.example     # Plantilla de variables
├── requirements.txt # Dependencias
└── manage.py        # Orquestador
```

---

## Roles del Sistema

| Rol                           | Nivel         | Permisos | Descripcion                                    |
| :---------------------------- | :------------ | :------- | :--------------------------------------------- |
| **Administrador**             | Administrador | CRUD     | Control total del sistema. 2 cuentas base.     |
| **Coordinador_Administracion**| Coordinador   | CRU      | Coordinador de Administracion.                 |
| **Coordinador_Legal**         | Coordinador   | CRU      | Coordinador Legal.                             |
| **Coordinador_Psicosocial**   | Coordinador   | CRU      | Coordinador Psicosocial.                       |
| **Coordinador_Humanitario**   | Coordinador   | CRU      | Coordinador Humanitario.                       |
| **Coordinador_Comunicacion**  | Coordinador   | CRU      | Coordinador de Comunicacion.                   |
| **Operativo**                 | Operativo     | CR       | Revisa datos y canaliza a coordinadores.       |
| **Usuario**                   | Usuario       | C        | Solo crea expedientes (becarios, voluntarios). |

---

## Notas de Seguridad

- **Doble Llave:** Llave de Login (derivada con `scrypt` + AES) para descifrado de roles transparente, y Llave de Firma (SAT) para operaciones críticas.
- **Certificados SAT:** Los roles Coordinador y Administrador usan un certificado X.509 (`.cer`) y una llave privada PKCS#8 (`.key`) que se entrega de forma segura en un `.ZIP` no persistente en el servidor.
- **Integridad:** Bitácora protegida por encadenamiento de hashes (SHA-256).
- **Transparencia:** Cifrado a nivel de campo en base de datos para datos sensibles.
- **Zero-Trust en Edición:** La edición y validación de expedientes requiere subir el archivo `.key` a la plataforma.

---

_Cualquier duda contactar al Equipo 5_
