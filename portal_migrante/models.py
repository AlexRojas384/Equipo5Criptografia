from django.db import models
from django.conf import settings
from cripto.crypto import encriptar_valor_db, desencriptar_valor_db


class EncryptedTextFieldArco(models.TextField):
    """Campo de texto cifrado con la SECRET_KEY del servidor (igual que EncryptedTextField en usuarios)."""

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        return encriptar_valor_db(value)

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return desencriptar_valor_db(value)

    def to_python(self, value):
        return super().to_python(value)


class SolicitudARCO(models.Model):
    """
    Solicitud de ejercicio de derechos ARCO enviada por un migrante desde el portal.

    Flujo de estados:
      pendiente → aprobada_operativo → firmada_coordinador → ejecutada
                                     → rechazada (en cualquier punto)

    La descripcion y los campos solicitados se almacenan cifrados con la SECRET_KEY
    del servidor (cifrado transparente de BD, igual que el campo telefono de Usuario).
    No se usa RSA aqui porque la solicitud no necesita ser descifrada por el migrante
    fuera del servidor; es un canal de comunicacion interna.
    """

    TIPOS = [
        ('rectificacion', 'Rectificacion'),
        ('cancelacion',   'Cancelacion'),
        ('oposicion',     'Oposicion'),
    ]

    ESTADOS = [
        ('pendiente',             'Pendiente de revision'),
        ('aprobada_operativo',    'Aprobada por Operativo — esperando firma'),
        ('rechazada',             'Rechazada'),
        ('firmada_coordinador',   'Firmada por Coordinador — pendiente de ejecucion'),
        ('ejecutada',             'Ejecutada'),
    ]

    # Referencia al expediente. Permite null para conservar la solicitud
    # como registro historico despues de una cancelacion ejecutada
    # (el expediente fisico se borra, pero la solicitud queda en auditoria).
    expediente = models.ForeignKey(
        'expediente.Expediente',
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='solicitudes_arco',
    )

    tipo    = models.CharField(max_length=20, choices=TIPOS)
    estado  = models.CharField(max_length=25, choices=ESTADOS, default='pendiente')

    # Contenido de la solicitud (cifrado en BD)
    descripcion_cifrada   = EncryptedTextFieldArco(
        help_text='Descripcion libre del cambio solicitado por el migrante.'
    )
    campos_solicitados    = EncryptedTextFieldArco(
        blank=True,
        help_text='JSON con campo:valor_nuevo para solicitudes de rectificacion.'
    )

    # Hash de la descripcion para integridad (antes de cifrar)
    hash_solicitud = models.CharField(max_length=64)

    # Hash del folio usado al crear la solicitud (para verificar titularidad)
    folio_hash_verificacion = models.CharField(max_length=64)

    # Revision del Operativo
    operativo             = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='solicitudes_arco_revisadas',
    )
    respuesta_operativo        = models.TextField(blank=True)
    fecha_respuesta_operativo  = models.DateTimeField(null=True, blank=True)

    # Rectificacion: JSON {campo: nuevo_valor} propuesto por el Operativo,
    # cifrado en BD. Lo aplica automaticamente el Coordinador al firmar.
    cambios_propuestos    = EncryptedTextFieldArco(
        blank=True, default='',
        help_text='JSON de cambios concretos propuestos por el Operativo (rectificacion).'
    )

    # Oposicion: etiqueta libre escrita por el Operativo, cifrada en BD.
    # Al firmar el Coordinador, se anexa a expediente.etiquetas_oposicion.
    etiqueta_oposicion    = EncryptedTextFieldArco(
        blank=True, default='',
        help_text='Etiqueta de restriccion escrita por el Operativo (oposicion).'
    )

    # Firma del Coordinador
    coordinador               = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='solicitudes_arco_firmadas',
    )
    respuesta_coordinador      = models.TextField(blank=True)
    fecha_firma_coordinador    = models.DateTimeField(null=True, blank=True)
    firma_digital              = models.TextField(blank=True)

    # Ejecucion final por Admin (solo cancelaciones)
    admin                      = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='solicitudes_arco_ejecutadas',
    )
    respuesta_admin            = models.TextField(blank=True)
    fecha_ejecucion_admin      = models.DateTimeField(null=True, blank=True)
    firma_digital_admin        = models.TextField(blank=True)

    fecha_creacion = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"ARCO #{self.pk} [{self.tipo}] Exp.{self.expediente_id} — {self.estado}"

    class Meta:
        verbose_name        = 'Solicitud ARCO'
        verbose_name_plural = 'Solicitudes ARCO'
        ordering            = ['-fecha_creacion']
