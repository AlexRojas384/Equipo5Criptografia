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

> **IMPORTANTE:** Este comando imprime las **llaves de firma de 64 caracteres** para cada administrador. Copia y guarda estas llaves de forma segura, ya que se muestran **una sola vez**. Son necesarias para desbloquear la sesion criptografica en el sistema.

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

Si tu usuario fue creado sin llaves, el sistema te cerrara la sesion automaticamente por seguridad.

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

- **Cifrado Híbrido:** AES-256 para datos y RSA-4096 para intercambio de llaves.
- **Certificados:** Cumplimiento con estándar X.509 para identidad de usuarios.
- **Integridad:** Bitácora protegida por encadenamiento de hashes (SHA-256).
- **Transparencia:** Cifrado a nivel de campo en base de datos para datos sensibles.

---

_Cualquier duda contactar al Equipo 5_
