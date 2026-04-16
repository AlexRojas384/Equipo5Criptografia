from django.core.management.base import BaseCommand, CommandError
from usuarios.models import Usuario
from cripto.crypto import generar_par_llaves, generar_certificado
from auditoria.models import BitacoraEvento
from django.utils import timezone

class Command(BaseCommand):
    help = 'Regenera la identidad criptográfica (Llaves RSA y Certificado X.509) para un usuario ignorando restricciones de middleware.'

    def add_arguments(self, parser):
        parser.add_argument('username', type=str, help='Nombre de usuario a regenerar (ej. admin)')

    def handle(self, *args, **options):
        username = options['username']
        try:
            usuario = Usuario.objects.get(username=username)
        except Usuario.DoesNotExist:
            raise CommandError(f'El usuario "{username}" no existe.')

        self.stdout.write(self.style.WARNING(f'Regenerando llaves y certificado para "{username}"...'))

        priv, pub = generar_par_llaves()
        cert, exp = generar_certificado(priv, pub, usuario.username)

        usuario.llave_privada = priv
        usuario.llave_publica = pub
        usuario.certificado_digital = cert
        usuario.fecha_expiracion_certificado = exp
        usuario.save()

        # Registrar el evento saltándonos _registrar_evento ya que no hay request
        BitacoraEvento.objects.create(
            usuario=usuario,
            tipo='cambio_rol',
            descripcion=f'Identidad criptográfica regenerada vía consola para {username}',
            fecha=timezone.now(),
            ip='127.0.0.1',
        )

        self.stdout.write(self.style.SUCCESS(f'¡Éxito! Identidad de "{username}" restablecida. Expira: {exp.strftime("%Y-%m-%d")}'))
