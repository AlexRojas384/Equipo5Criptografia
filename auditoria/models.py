from django.db import models
from django.conf import settings
from django.utils import timezone
from cripto.crypto import calcular_hash


class BitacoraEvento(models.Model):
    """Registra cada acción relevante del sistema para auditoría."""

    TIPOS_EVENTO = [
        ('cambio_rol',              'Cambio de rol'),
        ('toggle_permiso',          'Toggle de permiso'),
        ('toggle_activo',           'Activar/desactivar usuario'),
        ('solicitud_creada',        'Solicitud de rol creada'),
        ('solicitud_aprobada',      'Solicitud de rol aprobada'),
        ('solicitud_rechazada',     'Solicitud de rol rechazada'),
        ('login',                   'Inicio de sesion'),
        ('logout',                  'Cierre de sesion'),
        ('verificacion_expediente', 'Verificacion / edicion de expediente'),
        ('eliminar_expediente',     'Eliminacion de expediente'),
        # Eventos del portal de migrantes
        ('acceso_migrante',         'Acceso de migrante al portal'),
        ('acceso_migrante_fallido', 'Intento fallido de acceso al portal'),
        ('solicitud_arco_creada',   'Solicitud ARCO creada'),
        ('solicitud_arco_aprobada', 'Solicitud ARCO aprobada por Operativo'),
        ('solicitud_arco_firmada',  'Solicitud ARCO firmada por Coordinador'),
        ('solicitud_arco_rechazada','Solicitud ARCO rechazada'),
        ('solicitud_arco_ejecutada','Solicitud ARCO ejecutada'),
        ('solicitud_arco_firmada_cancelacion',   'Cancelacion ARCO firmada por Coordinador (pendiente Admin)'),
        ('solicitud_arco_cancelacion_rechazada', 'Cancelacion ARCO rechazada por Admin en paso final'),
        ('expediente_cancelado_arco',            'Expediente eliminado por ejecucion ARCO de cancelacion'),
        ('aviso_privacidad_aceptado',            'Aceptacion de Aviso de Privacidad de Casa Monarca'),
    ]


    usuario = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='eventos_auditoria',
    )
    tipo = models.CharField(max_length=60, choices=TIPOS_EVENTO)
    descripcion = models.TextField()
    fecha = models.DateTimeField(auto_now_add=True)
    ip = models.GenericIPAddressField(blank=True, null=True)
    hash_registro = models.CharField(max_length=64, blank=True, null=True)

    def save(self, *args, **kwargs):
        is_new = self.pk is None
        if not self.fecha:
            self.fecha = timezone.now()
            
        if is_new and not self.hash_registro:
            ultimo_evento = BitacoraEvento.objects.order_by('-pk').first()
            prev_hash = ultimo_evento.hash_registro if ultimo_evento and ultimo_evento.hash_registro else 'GENESIS'
            user_id = str(self.usuario_id) if self.usuario_id else 'System'
            datos_raw = f"{prev_hash}|{user_id}|{self.tipo}|{self.descripcion}|{self.fecha.isoformat()}"
            self.hash_registro = calcular_hash(datos_raw)
            
        super().save(*args, **kwargs)

    def __str__(self):
        return f"[{self.fecha:%Y-%m-%d %H:%M}] {self.tipo} — {self.usuario}"

    class Meta:
        verbose_name = 'Evento de bitácora'
        verbose_name_plural = 'Eventos de bitácora'
        ordering = ['-fecha']
