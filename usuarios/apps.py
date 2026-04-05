from django.apps import AppConfig

class UsuariosConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'usuarios'

    def ready(self):
        # Crea los grupos y asigna permisos automáticamente al iniciar
        from .setup_roles import crear_roles
        try:
            crear_roles()
        except Exception:
            pass  # Evita errores en migraciones iniciales