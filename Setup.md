# Casa Monarca — Plataforma de Gestión de Expedientes

Sistema de gestión segura para el manejo de expedientes, con cifrado híbrido y control de acceso basado en roles (RBAC).

---

## Requisitos previos

Asegúrate de tener instalado en tu máquina local:

* **Python 3.9** o superior
* **MySQL 8.0**
* **MySQL Workbench** (opcional pero recomendado)
* **Git**

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

* **Windows:**
    ```bash
    venv\Scripts\activate
    ```
* **Mac/Linux:**
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

### 8. Asignar rol Admin y generar llaves RSA
```bash
python manage.py shell
```

Dentro del shell de Python:
```python
from cripto.crypto import generar_par_llaves
from usuarios.models import Usuario

u = Usuario.objects.get(username='admin') # Cambia 'admin' por tu usuario
u.rol = 'Admin'

print("Generando llaves RSA-4096 (esto tarda unos segundos)...")
priv, pub = generar_par_llaves()

u.llave_privada = priv
u.llave_publica = pub
u.save()

print("Configuración de administrador completada")
exit()
```

### 9. Levantar el servidor
```bash
python manage.py runserver
```

Accede en: [http://127.0.0.1:8000/usuarios/login/](http://127.0.0.1:8000/usuarios/login/)

---

## Estructura del Proyecto

```text
casa_monarca/
├── config/          # Configuración de Django
├── usuarios/        # Autenticación y RBAC
├── expediente/      # Gestión de expedientes cifrados
├── auditoria/       # Bitácora con chain hash
├── cripto/          # Motor AES-256 + RSA-4096
├── templates/       # HTML templates
├── .env.example     # Plantilla de variables
├── requirements.txt # Dependencias
└── manage.py        # Orquestador
```

---

## Roles del Sistema

| Rol | Descripción |
| :--- | :--- |
| **Admin** | Control total y gestión de llaves. |
| **Voluntario** | Crea, ve y edita expedientes. |
| **Junior** | Solo crea y ve sus propios expedientes. |
| **Auditor** | Solo lectura de bitácora de auditoría. |

---

## Notas de Seguridad
* **Cifrado:** Esquema híbrido **AES-256** + **RSA-4096**.
* **Integridad:** Bitácora protegida por encadenamiento de hashes.
* **Privacidad:** El archivo `.env` está ignorado en Git para seguridad.

---
*Cualquier duda contactar al Equipo 5*
