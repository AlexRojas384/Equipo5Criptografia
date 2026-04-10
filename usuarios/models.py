from django.contrib.auth.models import AbstractUser
from django.db import models


class Usuario(AbstractUser):
    ROLES = [
        ('Admin',      'Administrador'),
        ('Voluntario', 'Voluntario'),
        ('Junior',     'Junior'),
        ('Auditor',    'Auditor'),
    ]

    rol           = models.CharField(max_length=20, choices=ROLES, default='Junior')
    telefono      = models.CharField(max_length=20, blank=True, null=True)
    activo        = models.BooleanField(default=True)
    llave_publica = models.TextField(blank=True, null=True)  # RSA pública
    llave_privada = models.TextField(blank=True, null=True)  # RSA privada (cifrada)

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
    rol_actual = models.CharField(max_length=20)
    rol_solicitado = models.CharField(max_length=20, choices=Usuario.ROLES)
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