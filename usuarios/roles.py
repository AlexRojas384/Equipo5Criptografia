from .permissions import (
    PERMISOS_EXPEDIENTES,
    PERMISOS_AUDITORIA,
    PERMISOS_USUARIOS
)

ROLES = {
    "Administrador": {
        "descripcion": "Control total del sistema (Producción o Contingencias)",
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
    "Coordinador_Administracion": {
        "descripcion": "Coordinador de Administración (C, R, U)",
        "permisos": [
            "puede_crear_expediente",
            "puede_ver_expediente",
            "puede_editar_expediente",
            "puede_exportar_expediente",
        ]
    },
    "Coordinador_Legal": {
        "descripcion": "Coordinador Legal (C, R, U)",
        "permisos": [
            "puede_crear_expediente",
            "puede_ver_expediente",
            "puede_editar_expediente",
            "puede_exportar_expediente",
        ]
    },
    "Coordinador_Psicosocial": {
        "descripcion": "Coordinador Psicosocial (C, R, U)",
        "permisos": [
            "puede_crear_expediente",
            "puede_ver_expediente",
            "puede_editar_expediente",
            "puede_exportar_expediente",
        ]
    },
    "Coordinador_Humanitario": {
        "descripcion": "Coordinador Humanitario (C, R, U)",
        "permisos": [
            "puede_crear_expediente",
            "puede_ver_expediente",
            "puede_editar_expediente",
            "puede_exportar_expediente",
        ]
    },
    "Coordinador_Comunicacion": {
        "descripcion": "Coordinador de Comunicación (C, R, U)",
        "permisos": [
            "puede_crear_expediente",
            "puede_ver_expediente",
            "puede_editar_expediente",
            "puede_exportar_expediente",
        ]
    },
    "Operativo": {
        "descripcion": "Nivel Operativo (C, R)",
        "permisos": [
            "puede_crear_expediente",
            "puede_ver_expediente",
        ]
    },
    "Usuario": {
        "descripcion": "Nivel Usuario (C) - Solo registro",
        "permisos": [
            "puede_crear_expediente",
        ]
    },
}