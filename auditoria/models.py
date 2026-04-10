from django.db import models
from django.conf import settings


class BitacoraEvento(models.Model):
    """Registra cada acción relevante del sistema para auditoría."""

    TIPOS_EVENTO = [
        ('cambio_rol',          'Cambio de rol'),
        ('toggle_permiso',      'Toggle de permiso'),
        ('toggle_activo',       'Activar/desactivar usuario'),
        ('solicitud_creada',    'Solicitud de rol creada'),
        ('solicitud_aprobada',  'Solicitud de rol aprobada'),
        ('solicitud_rechazada', 'Solicitud de rol rechazada'),
        ('login',               'Inicio de sesión'),
        ('logout',              'Cierre de sesión'),
    ]

    usuario = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='eventos_auditoria',
    )
    tipo = models.CharField(max_length=30, choices=TIPOS_EVENTO)
    descripcion = models.TextField()
    fecha = models.DateTimeField(auto_now_add=True)
    ip = models.GenericIPAddressField(blank=True, null=True)

    def __str__(self):
        return f"[{self.fecha:%Y-%m-%d %H:%M}] {self.tipo} — {self.usuario}"

    class Meta:
        verbose_name = 'Evento de bitácora'
        verbose_name_plural = 'Eventos de bitácora'
        ordering = ['-fecha']
