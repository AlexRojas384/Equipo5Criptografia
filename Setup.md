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

### 7. Crear superusuario

```bash
python manage.py createsuperuser
```

### 8. Asignar rol Admin y generar identidad criptográfica

El sistema utiliza un middleware que bloquea a usuarios sin una identidad digital válida (Llaves RSA + Certificado). Sigue estos pasos para activar tu usuario administrador:

**A. Asignar rol de Admin:**

```bash
python manage.py shell
```

Dentro del shell de Django:

```python
from usuarios.models import Usuario
u = Usuario.objects.get(username='admin') # Cambia 'admin' por tu usuario si es otro
u.rol = 'Admin'
u.save()
exit()
```

**B. Generar Llaves y Certificado:**
Ejecuta el comando especial para crear la identidad criptográfica:

```bash
python manage.py regenerar_admin admin
```

### 9. Levantar el servidor

```bash
python manage.py runserver
```

Accede en: [http://127.0.0.1:8000/usuarios/login/](http://127.0.0.1:8000/usuarios/login/)

---

## Casos Especiales y Solución de Problemas

### "¿Sesión bloqueada" o reenvío constante al Login?

Si ya corriste el servidor anteriormente, o si tu usuario fue creado sin llaves, el sistema te cerrará la sesión automáticamente por seguridad.

**Solución:** Debes regenerar tu identidad criptográfica ejecutando:

```bash
python manage.py regenerar_admin <tu_usuario>
```

### Cambio de SECRET_KEY

El `SECRET_KEY` en el archivo `.env` se usa como base para el cifrado transparente de la base de datos.

- **Importante:** Si cambias esta clave después de haber guardado registros (usuarios, expedientes, etc.), no podrás descifrar los datos anteriores. Mantén la misma clave durante toda la vida del proyecto en el mismo entorno.

---

## Estructura del Proyecto

```text
casa_monarca/
├── config/          # Configuración de Django
├── usuarios/        # Autenticación y RBAC
├── expediente/      # Gestión de expedientes cifrados
├── auditoria/       # Bitácora con chain hash
├── cripto/          # Motor AES-256 + RSA-4096 + X.509
├── templates/       # HTML templates
├── .env.example     # Plantilla de variables
├── requirements.txt # Dependencias
└── manage.py        # Orquestador
```

---

## Roles del Sistema

| Rol            | Descripción                             |
| :------------- | :-------------------------------------- |
| **Admin**      | Control total y gestión de llaves.      |
| **Voluntario** | Crea, ve y edita expedientes.           |
| **Junior**     | Solo crea y ve sus propios expedientes. |
| **Auditor**    | Solo lectura de bitácora de auditoría.  |

---

## Notas de Seguridad

- **Cifrado Híbrido:** AES-256 para datos y RSA-4096 para intercambio de llaves.
- **Certificados:** Cumplimiento con estándar X.509 para identidad de usuarios.
- **Integridad:** Bitácora protegida por encadenamiento de hashes (SHA-256).
- **Transparencia:** Cifrado a nivel de campo en base de datos para datos sensibles.

---

_Cualquier duda contactar al Equipo 5_
