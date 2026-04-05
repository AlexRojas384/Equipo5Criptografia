from .permissions import (
    PERMISOS_EXPEDIENTES,
    PERMISOS_AUDITORIA,
    PERMISOS_USUARIOS
)

ROLES = {
    "Admin": {
        "descripcion": "Control total del sistema",
        "permisos": [
            "puede_crear_expediente",
            "puede_ver_expediente",
            "puede_editar_expediente",
            "puede_eliminar_expediente",
            "puede_exportar_expediente",
            "puede_ver_bitacora",
            "puede_gestionar_usuarios",
        ]
    },
    "Voluntario": {
        "descripcion": "Puede crear, ver y editar expedientes",
        "permisos": [
            "puede_crear_expediente",
            "puede_ver_expediente",
            "puede_editar_expediente",
            "puede_exportar_expediente",
        ]
    },
    "Junior": {
        "descripcion": "Solo puede crear y ver sus propios expedientes",
        "permisos": [
            "puede_crear_expediente",
            "puede_ver_propio_expediente",
        ]
    },
    "Auditor": {
        "descripcion": "Solo puede ver la bitácora de auditoría",
        "permisos": [
            "puede_ver_bitacora",
        ]
    },
}