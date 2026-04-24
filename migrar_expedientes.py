import os
import django
import sys

# Configurar el entorno de Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

from expediente.models import Expediente, AccesoExpediente
from usuarios.models import LlaveRol
from cripto.crypto import descifrar_llave_aes, cifrar_llave_aes

def migrar_expedientes():
    print("Iniciando migración de llaves AES a la arquitectura multi-copia...")

    expedientes = Expediente.objects.all()
    if not expedientes.exists():
        print("No hay expedientes para migrar.")
        return

    # Obtener llaves públicas de los roles
    try:
        pub_admin = LlaveRol.objects.get(rol='Admin').llave_publica
    except LlaveRol.DoesNotExist:
        pub_admin = None
        print("⚠️ No existe LlaveRol para 'Admin'.")

    try:
        pub_voluntario = LlaveRol.objects.get(rol='Voluntario').llave_publica
    except LlaveRol.DoesNotExist:
        pub_voluntario = None
        print("⚠️ No existe LlaveRol para 'Voluntario'.")

    migrados = 0
    errores = 0

    for exp in expedientes:
        if AccesoExpediente.objects.filter(expediente=exp).exists():
            print(f"Expediente #{exp.id} ya tiene accesos migrados. Saltando...")
            continue

        try:
            # 1. Crear copia para el CREADOR usando la llave_aes_cifrada legacy
            # En la versión antigua, la llave AES estaba cifrada con la pública del creador
            AccesoExpediente.objects.create(
                expediente=exp,
                tipo_acceso='Creador',
                usuario=exp.creado_por,
                llave_aes_cifrada=exp.llave_aes_cifrada
            )
            
            # Para re-cifrar para Admin y Voluntario, necesitaríamos descifrarla primero, 
            # lo cual requiere la llave privada del creador, que no tenemos.
            # Por lo tanto, los expedientes legacy SOLO podrán ser vistos por su creador 
            # hasta que se re-cifren, o podemos dejarlos así y que los Admins los vean 
            # cuando el creador acceda? No, el esquema es Zero-Knowledge.
            # Los expedientes existentes NO se pueden re-cifrar sin la llave privada de su creador.
            # Así que simplemente les creamos el Acceso de Creador.
            
            migrados += 1
            print(f"Migrado expediente #{exp.id} (Solo acceso de Creador)")

        except Exception as e:
            print(f"Error al migrar expediente #{exp.id}: {e}")
            errores += 1

    print(f"\nMigración completada. Migrados: {migrados}, Errores: {errores}")
    print("Nota: Los expedientes legacy solo tienen acceso para el 'Creador' porque no podemos descifrar su llave AES sin la contraseña del usuario.")

if __name__ == '__main__':
    migrar_expedientes()
