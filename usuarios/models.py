from django.contrib.auth.models import AbstractUser
from django.db import models

class Usuario(AbstractUser):
    ROLES = [
        ('Admin',      'Administrador'),
        ('Voluntario', 'Voluntario'),
        ('Junior',     'Junior'),
        ('Auditor',    'Auditor'),
    ]

    rol = models.CharField(
        max_length=20,
        choices=ROLES,
        default='Junior'
    )
    telefono = models.CharField(max_length=20, blank=True, null=True)
    activo    = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.username} ({self.rol})"

    def asignar_rol(self):
        """Sincroniza el campo rol con el grupo de Django (RBAC)"""
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