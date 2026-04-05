from django.db import models
from django.conf import settings


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
    llave_aes_cifrada = models.TextField()  # AES key cifrada con RSA

    # Firma digital del colaborador
    firma_digital = models.TextField(blank=True, null=True)

    # Hash del expediente para auditoría
    hash_expediente = models.CharField(max_length=64)

    def __str__(self):
        return f"Expediente #{self.pk} — {self.fecha_atencion} — {self.creado_por}"

    class Meta:
        verbose_name        = 'Expediente'
        verbose_name_plural = 'Expedientes'
        ordering            = ['-fecha_creacion']