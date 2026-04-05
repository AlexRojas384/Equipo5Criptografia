from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from .roles import ROLES
from .permissions import TODOS_LOS_PERMISOS

def crear_roles():
    # 1. Crear content type genérico para nuestros permisos custom
    from django.contrib.auth.models import User
    content_type = ContentType.objects.get_for_model(User)

    # 2. Registrar todos los permisos si no existen
    for codename, nombre in TODOS_LOS_PERMISOS:
        Permission.objects.get_or_create(
            codename=codename,
            content_type=content_type,
            defaults={"name": nombre}
        )

    # 3. Crear grupos y asignarles sus permisos
    for nombre_rol, config in ROLES.items():
        grupo, _ = Group.objects.get_or_create(name=nombre_rol)
        grupo.permissions.clear()  # Limpia permisos anteriores

        for codename in config["permisos"]:
            try:
                permiso = Permission.objects.get(codename=codename)
                grupo.permissions.add(permiso)
            except Permission.DoesNotExist:
                pass