from django.db import models
from django.conf import settings
from cripto.crypto import encriptar_valor_db, desencriptar_valor_db


class EncryptedTextFieldExpediente(models.TextField):
    """Campo de texto cifrado con la SECRET_KEY del servidor (mismo patron que EncryptedTextFieldArco)."""

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        return encriptar_valor_db(value)

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return desencriptar_valor_db(value)

    def to_python(self, value):
        return super().to_python(value)


class Expediente(models.Model):
    # Quién lo creó
    creado_por = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='expedientes'
    )
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    fecha_atencion = models.DateField()

    # Datos cifrados (AES-256)
    datos_cifrados    = models.TextField()  # base64
    nonce             = models.TextField()  # base64
    tag               = models.TextField()  # base64


    # Estado de verificación
    verificado = models.BooleanField(default=False)

    # Firma digital del colaborador
    firma_digital = models.TextField(blank=True, null=True)

    # Hash del expediente para auditoría
    hash_expediente = models.CharField(max_length=64)

    # Hash del folio del migrante para búsqueda segura desde el portal.
    # El folio en texto claro vive dentro de datos_cifrados.
    folio_hash = models.CharField(max_length=64, blank=True, null=True, db_index=True)

    # Etiquetas de oposición ARCO aplicadas por Coordinadores.
    # JSON con lista de {"fecha", "etiqueta", "coordinador"}. Cifrado en BD
    # con SECRET_KEY (metadato administrativo, no PII del migrante).
    etiquetas_oposicion = EncryptedTextFieldExpediente(blank=True, default='')

    def __str__(self):
        return f"Expediente #{self.pk} — {self.fecha_atencion} — {self.creado_por}"

    class Meta:
        verbose_name        = 'Expediente'
        verbose_name_plural = 'Expedientes'
        ordering            = ['-fecha_creacion']


class AccesoExpediente(models.Model):
    expediente = models.ForeignKey(Expediente, on_delete=models.CASCADE, related_name='accesos')
    tipo_acceso = models.CharField(max_length=50, help_text='Creador o Nombre del Rol Destinatario')
    usuario = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        help_text='Solo para tipo Creador'
    )
    llave_aes_cifrada = models.TextField()

    def __str__(self):
        return f"Acceso {self.tipo_acceso} → Expediente #{self.expediente_id}"

    class Meta:
        verbose_name = 'Acceso a expediente'
        verbose_name_plural = 'Accesos a expediente'