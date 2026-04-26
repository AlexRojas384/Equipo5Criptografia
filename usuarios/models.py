from django.contrib.auth.models import AbstractUser
from django.db import models
from cripto.crypto import encriptar_valor_db, desencriptar_valor_db

class EncryptedCharField(models.CharField):
    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        return encriptar_valor_db(value)

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return desencriptar_valor_db(value)

    def to_python(self, value):
        return super().to_python(value)

class EncryptedTextField(models.TextField):
    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        return encriptar_valor_db(value)

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return desencriptar_valor_db(value)

    def to_python(self, value):
        return super().to_python(value)


class Usuario(AbstractUser):
    ROLES = [
        ('Administrador',              'Administrador'),
        ('Coordinador_Administracion', 'Coordinador de Administración'),
        ('Coordinador_Legal',          'Coordinador Legal'),
        ('Coordinador_Psicosocial',    'Coordinador Psicosocial'),
        ('Coordinador_Humanitario',    'Coordinador Humanitario'),
        ('Coordinador_Comunicacion',   'Coordinador de Comunicación'),
        ('Operativo',                  'Operativo'),
        ('Usuario',                    'Usuario'),
    ]

    rol           = models.CharField(max_length=50, choices=ROLES, default='Usuario')
    telefono      = EncryptedCharField(max_length=200, blank=True, null=True)
    activo        = models.BooleanField(default=True)
    llave_publica = models.TextField(blank=True, null=True)  # RSA pública
    llave_privada = EncryptedTextField(blank=True, null=True)  # RSA privada encriptada transparente (Solo login)
    salt_login    = models.CharField(max_length=64, blank=True, null=True) # Salt para derivar clave de login
    certificado_digital = models.TextField(blank=True, null=True)  # Certificado X.509 (DER en Base64)
    fecha_expiracion_certificado = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return f"{self.username} ({self.rol})"

    def asignar_rol(self):
        from django.contrib.auth.models import Group
        self.groups.clear()
        if self.rol:
            try:
                grupo = Group.objects.get(name=self.rol)
                self.groups.add(grupo)
            except Group.DoesNotExist:
                pass

    class Meta:
        verbose_name        = 'Usuario'
        verbose_name_plural = 'Usuarios'


class SolicitudRol(models.Model):
    """Solicitud de un usuario para cambiar de rol."""

    ESTADOS = [
        ('pendiente',  'Pendiente'),
        ('aprobada',   'Aprobada'),
        ('rechazada',  'Rechazada'),
    ]

    solicitante = models.ForeignKey(
        Usuario,
        on_delete=models.CASCADE,
        related_name='solicitudes_rol',
    )
    rol_actual = models.CharField(max_length=50)
    rol_solicitado = models.CharField(max_length=50, choices=Usuario.ROLES)
    mensaje = models.TextField(
        blank=True,
        help_text='Explica por qué necesitas este cambio de rol',
    )
    estado = models.CharField(max_length=15, choices=ESTADOS, default='pendiente')
    respondido_por = models.ForeignKey(
        Usuario,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='solicitudes_respondidas',
    )
    respuesta_admin = models.TextField(blank=True)
    fecha_solicitud = models.DateTimeField(auto_now_add=True)
    fecha_respuesta = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.solicitante.username}: {self.rol_actual} → {self.rol_solicitado} ({self.estado})"

    class Meta:
        verbose_name = 'Solicitud de rol'
        verbose_name_plural = 'Solicitudes de rol'
        ordering = ['-fecha_solicitud']


class LlaveRol(models.Model):
    """Almacena la llave pública RSA de un rol del sistema (Admin, Voluntario)."""
    rol = models.CharField(max_length=50, unique=True)
    llave_publica = models.TextField()

    def __str__(self):
        return f"LlaveRol: {self.rol}"

    class Meta:
        verbose_name = 'Llave de rol'
        verbose_name_plural = 'Llaves de rol'


class AccesoLlaveRol(models.Model):
    """Llave privada de rol cifrada con la llave pública RSA de un usuario individual."""
    llave_rol = models.ForeignKey(LlaveRol, on_delete=models.CASCADE, related_name='accesos')
    usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE, related_name='accesos_rol')
    llave_privada_rol_cifrada = models.TextField()

    def __str__(self):
        return f"Acceso {self.llave_rol.rol} → {self.usuario.username}"

    class Meta:
        unique_together = ('llave_rol', 'usuario')
        verbose_name = 'Acceso a llave de rol'
        verbose_name_plural = 'Accesos a llave de rol'