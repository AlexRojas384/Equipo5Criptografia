import os
import glob
import shutil

# 1. Eliminar archivos de migración
apps = ['usuarios', 'expediente', 'auditoria']
for app in apps:
    mig_dir = os.path.join(app, 'migrations')
    if os.path.exists(mig_dir):
        for file in os.listdir(mig_dir):
            if file != '__init__.py' and file.endswith('.py'):
                os.remove(os.path.join(mig_dir, file))
        print(f"Borradas migraciones de {app}")

# 2. Leer .env para saber cómo conectarnos
from environ import Env
env = Env()
env.read_env('.env')

db_name = env('DB_NAME')
db_user = env('DB_USER')
db_password = env('DB_PASSWORD')
db_host = env('DB_HOST', default='127.0.0.1')
db_port = env('DB_PORT', default='3306')

print("Recreando base de datos MySQL...")
import pymysql
try:
    conn = pymysql.connect(
        host=db_host,
        port=int(db_port),
        user=db_user,
        password=db_password
    )
    cursor = conn.cursor()
    cursor.execute(f"DROP DATABASE IF EXISTS {db_name}")
    cursor.execute(f"CREATE DATABASE {db_name} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
    cursor.close()
    conn.close()
    print("Base de datos recreada con éxito.")
except Exception as e:
    print(f"Error al recrear base de datos: {e}")

