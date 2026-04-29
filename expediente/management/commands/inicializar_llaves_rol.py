"""
Inicializa las llaves RSA de rol para todos los roles del sistema.

Genera un par RSA-2048 para cada rol y cifra la llave privada del rol
con la llave pública de cada usuario que pertenezca a ese rol.
Adicionalmente, le da acceso a TODAS las llaves de rol a los usuarios 'Administrador'.

Este comando es idempotente: no regenera llaves si ya existen.
"""
from django.core.management.base import BaseCommand
from usuarios.models import Usuario, LlaveRol, AccesoLlaveRol
from cripto.crypto import generar_par_llaves, cifrar_datos
import json

ROLES_SISTEMA = [
    'Administrador',
    'Coordinador_Administracion',
    'Coordinador_Legal',
    'Coordinador_Psicosocial',
    'Coordinador_Humanitario',
    'Coordinador_Comunicacion',
    'Operativo',
    'Usuario',
]

class Command(BaseCommand):
    help = 'Genera llaves RSA de rol y distribuye acceso a usuarios existentes.'

    def handle(self, *args, **options):
        for rol_name in ROLES_SISTEMA:
            llave_rol, created = LlaveRol.objects.get_or_create(
                rol=rol_name,
                defaults={'llave_publica': ''}
            )

            privada_pem = None
            if created or not llave_rol.llave_publica:
                # Generar par de llaves RSA-2048 sin passphrase
                privada_pem, publica_pem = generar_par_llaves(passphrase=None)
                llave_rol.llave_publica = publica_pem
                llave_rol.save()
                self.stdout.write(self.style.SUCCESS(
                    f'OK: Generadas llaves RSA para rol "{rol_name}"'
                ))
            else:
                self.stdout.write(self.style.WARNING(
                    f'INFO: Llaves de rol "{rol_name}" ya existen. Verificando accesos...'
                ))

            # Distribuir la llave privada del rol a:
            # 1. Usuarios con este rol
            # 2. Usuarios con rol Administrador (tienen acceso a todas)
            usuarios_destino = Usuario.objects.filter(
                llave_publica__isnull=False,
            ).exclude(llave_publica='')
            
            for usuario in usuarios_destino:
                # Solo dar acceso si es de este rol, o si es Administrador
                if usuario.rol != rol_name and usuario.rol != 'Administrador':
                    continue

                ya_tiene = AccesoLlaveRol.objects.filter(
                    llave_rol=llave_rol,
                    usuario=usuario,
                ).exists()

                if ya_tiene:
                    self.stdout.write(f'   -> {usuario.username} ya tiene acceso a {rol_name}.')
                    continue

                if privada_pem is None:
                    self.stdout.write(self.style.ERROR(
                        f'   X No se puede distribuir a {usuario.username}: '
                        f'no se dispone de la llave privada del rol en texto claro. '
                    ))
                    continue

                # Cifrar híbrido
                paquete_cifrado = cifrar_datos({'key': privada_pem}, usuario.llave_publica)
                AccesoLlaveRol.objects.create(
                    llave_rol=llave_rol,
                    usuario=usuario,
                    llave_privada_rol_cifrada=json.dumps(paquete_cifrado),
                )
                self.stdout.write(self.style.SUCCESS(
                    f'   -> Acceso a {rol_name} creado para {usuario.username}'
                ))

        self.stdout.write(self.style.SUCCESS('\nOK: Inicialización de llaves de rol completada.'))
