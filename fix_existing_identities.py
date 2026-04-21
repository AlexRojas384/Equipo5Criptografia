import os
import django

# Configurar Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from usuarios.models import Usuario
from cripto.crypto import generar_llave_firma, generar_par_llaves, generar_certificado

def fix_users():
    users_to_fix = Usuario.objects.filter(certificado_digital__isnull=True)
    count = users_to_fix.count()
    print(f"Encontrados {count} usuarios sin identidad criptográfica...")
    
    llaves_generadas = []
    
    for u in users_to_fix:
        print(f"  -> Generando para {u.username}...", end=" ", flush=True)
        llave_firma = generar_llave_firma()
        priv, pub = generar_par_llaves(passphrase=llave_firma)
        cert, exp = generar_certificado(priv, pub, u.username, passphrase=llave_firma)
        u.llave_privada = priv
        u.llave_publica = pub
        u.certificado_digital = cert
        u.fecha_expiracion_certificado = exp
        u.save()
        llaves_generadas.append((u.username, llave_firma))
        print("OK")
    
    if llaves_generadas:
        print("\n" + "═" * 60)
        print("  🔑 LLAVES DE FIRMA GENERADAS")
        print("═" * 60)
        for username, llave in llaves_generadas:
            print(f"  {username}: {llave}")
        print("═" * 60)
        print("  ⚠️  Estas llaves NO se almacenan. Cópielas AHORA.")
        print("═" * 60)
    
    print("\nProceso terminado exitosamente.")

if __name__ == "__main__":
    fix_users()

