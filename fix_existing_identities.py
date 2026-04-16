import os
import django

# Configurar Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from usuarios.models import Usuario
from cripto.crypto import generar_par_llaves, generar_certificado

def fix_users():
    users_to_fix = Usuario.objects.filter(certificado_digital__isnull=True)
    count = users_to_fix.count()
    print(f"Encontrados {count} usuarios sin identidad criptográfica...")
    
    for u in users_to_fix:
        print(f"  -> Generando para {u.username}...", end=" ", flush=True)
        priv, pub = generar_par_llaves()
        cert, exp = generar_certificado(priv, pub, u.username)
        u.llave_privada = priv
        u.llave_publica = pub
        u.certificado_digital = cert
        u.fecha_expiracion_certificado = exp
        u.save()
        print("OK")
    
    print("\nProceso terminado exitosamente.")

if __name__ == "__main__":
    fix_users()
