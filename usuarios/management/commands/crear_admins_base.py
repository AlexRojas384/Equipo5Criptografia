"""
Crea las dos cuentas de Administrador base del sistema:
- admin_prod: Administrador de producción
- admin_contingencia: Administrador de contingencias

Debe ejecutarse DESPUÉS de inicializar_llaves_rol.

Este comando es idempotente: no recrea usuarios que ya existen.
"""
from django.core.management.base import BaseCommand
from usuarios.models import Usuario, LlaveRol, AccesoLlaveRol
from cripto.crypto import generar_llave_firma, generar_par_llaves, generar_certificado, cifrar_datos, derivar_clave_login, exportar_llave_privada_der
import json
import secrets
import os


ADMINS_BASE = [
    {
        'username': 'admin_prod',
        'first_name': 'Administrador',
        'last_name': 'Produccion',
        'password': 'CasaMonarca2026!',
    },
    {
        'username': 'admin_contingencia',
        'first_name': 'Administrador',
        'last_name': 'Contingencias',
        'password': 'CasaMonarca2026!',
    },
]


class Command(BaseCommand):
    help = 'Crea las dos cuentas base de Administrador con llaves RSA y acceso a todas las llaves de rol.'

    def handle(self, *args, **options):
        llaves_rol = list(LlaveRol.objects.all())
        if not llaves_rol:
            self.stdout.write(self.style.ERROR(
                'ERROR: No existen llaves de rol en la BD. '
                'Ejecuta primero: python manage.py inicializar_llaves_rol'
            ))
            return

        for admin_info in ADMINS_BASE:
            username = admin_info['username']

            if Usuario.objects.filter(username=username).exists():
                self.stdout.write(self.style.WARNING(
                    f'INFO: El usuario "{username}" ya existe. Saltando...'
                ))
                continue

            # 1. Generar par de llaves de Login
            from cripto.crypto import cifrar_llave_con_password
            salt_login = secrets.token_hex(32)
            llave_privada_login, llave_publica_login = generar_par_llaves()
            llave_privada_cifrada = cifrar_llave_con_password(llave_privada_login, admin_info['password'], salt_login)

            # 2. Generar identidad criptografica de Firma (SAT)
            llave_firma = generar_llave_firma()
            llave_privada_sat, llave_publica_sat = generar_par_llaves()
            certificado_pem, certificado_der, expiracion = generar_certificado(
                llave_privada_sat, llave_publica_sat, username,
                auto_firmado=True
            )

            # Crear usuario
            usuario = Usuario.objects.create_user(
                username=username,
                password=admin_info['password'],
                first_name=admin_info['first_name'],
                last_name=admin_info['last_name'],
                rol='Administrador',
                activo=True,
                salt_login=salt_login,
                llave_publica=llave_publica_login,
                llave_privada=llave_privada_cifrada,
                certificado_digital=certificado_pem,
                fecha_expiracion_certificado=expiracion,
            )
            usuario.is_staff = True
            usuario.is_superuser = True
            usuario.save()
            usuario.asignar_rol()

            # 3. Exportar archivos a disco (Necesarios para el primer acceso)
            llave_privada_der = exportar_llave_privada_der(llave_privada_sat, llave_firma)
            
            os.makedirs('certs_iniciales', exist_ok=True)
            with open(f'certs_iniciales/{username}.key', 'wb') as f:
                f.write(llave_privada_der)
            with open(f'certs_iniciales/{username}.cer', 'wb') as f:
                f.write(certificado_der)

            self.stdout.write(self.style.SUCCESS(
                f'OK: Usuario "{username}" creado con rol Administrador.'
            ))
            self.stdout.write(self.style.SUCCESS(
                f'   Password de login: {admin_info["password"]}'
            ))
            self.stdout.write(self.style.SUCCESS(
                f'   Llave de firma SAT (64 chars): {llave_firma}'
            ))
            self.stdout.write(self.style.SUCCESS(
                f'   ARCHIVOS GENERADOS en certs_iniciales/: {username}.key, {username}.cer'
            ))
            self.stdout.write(self.style.SUCCESS(
                f'   -> Úsalos para autorizar tus acciones en el panel administrativo.'
            ))
            self.stdout.write('')

            # Distribuir acceso a TODAS las llaves de rol
            for llave_rol_obj in llaves_rol:
                ya_tiene = AccesoLlaveRol.objects.filter(
                    llave_rol=llave_rol_obj, usuario=usuario
                ).exists()
                if ya_tiene:
                    continue

                # Las llaves de rol fueron generadas por inicializar_llaves_rol
                # pero no tenemos la privada en texto claro aqui.
                # Necesitamos leerla de un acceso existente de otro admin, o
                # el inicializar_llaves_rol ya debio haberla cifrado para este usuario.
                # Como este es un fresh start, inicializar_llaves_rol se ejecuta
                # ANTES de que existan los admins, asi que no les habra dado acceso.
                # Solucion: regeneramos las llaves de rol que no tengan acceso
                # para este admin.
                self.stdout.write(self.style.WARNING(
                    f'   AVISO: El usuario {username} no tiene acceso a la llave de rol "{llave_rol_obj.rol}". '
                    f'Se regenerara esta llave de rol para incluirlo.'
                ))

        # Ahora, regenerar las llaves de rol que no estan distribuidas a los admins
        self._redistribuir_llaves_rol()

        self.stdout.write(self.style.SUCCESS(
            '\nOK: Creacion de administradores base completada.'
        ))
        self.stdout.write(self.style.WARNING(
            '\nIMPORTANTE: Guarda las llaves de firma de forma segura. '
            'Se muestran UNA SOLA VEZ.'
        ))

    def _redistribuir_llaves_rol(self):
        """
        Para cada llave de rol, verifica que todos los Administradores
        tengan acceso. Si no, regenera la llave de rol.
        """
        from cripto.crypto import generar_par_llaves as gen_par

        admins = Usuario.objects.filter(
            rol='Administrador',
            llave_publica__isnull=False,
        ).exclude(llave_publica='')

        for llave_rol_obj in LlaveRol.objects.all():
            # Verificar si ALGUN admin ya tiene acceso
            acceso_existente = AccesoLlaveRol.objects.filter(
                llave_rol=llave_rol_obj,
                usuario__rol='Administrador',
            ).first()

            if acceso_existente:
                # Al menos un admin tiene acceso, distribuir a los que no tengan
                # Pero no podemos descifrar sin la sesion del admin...
                # En un fresh start, no hay sesion activa.
                # Necesitamos regenerar la llave de rol.
                pass

            # Regenerar la llave de rol para distribuirla a todos los admins
            privada_pem, publica_pem = gen_par(passphrase=None)
            llave_rol_obj.llave_publica = publica_pem
            llave_rol_obj.save()

            # Borrar accesos viejos (si los hay)
            AccesoLlaveRol.objects.filter(llave_rol=llave_rol_obj).delete()

            # Cifrar la privada para cada admin
            for admin in admins:
                paquete = cifrar_datos({'key': privada_pem}, admin.llave_publica)
                AccesoLlaveRol.objects.create(
                    llave_rol=llave_rol_obj,
                    usuario=admin,
                    llave_privada_rol_cifrada=json.dumps(paquete),
                )
                self.stdout.write(self.style.SUCCESS(
                    f'   -> Acceso a "{llave_rol_obj.rol}" creado para {admin.username}'
                ))
