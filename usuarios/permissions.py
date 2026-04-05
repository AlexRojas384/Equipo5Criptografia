# Cada permiso es independiente y reutilizable
PERMISOS_EXPEDIENTES = [
    ("puede_crear_expediente",    "Puede crear expedientes"),
    ("puede_ver_expediente",      "Puede ver expedientes"),
    ("puede_ver_propio_expediente","Puede ver solo sus propios expedientes"),
    ("puede_editar_expediente",   "Puede editar expedientes"),
    ("puede_eliminar_expediente", "Puede eliminar expedientes"),
    ("puede_exportar_expediente", "Puede exportar expedientes"),
]

PERMISOS_AUDITORIA = [
    ("puede_ver_bitacora",        "Puede ver bitácora de auditoría"),
]

PERMISOS_USUARIOS = [
    ("puede_gestionar_usuarios",  "Puede gestionar usuarios y roles"),
]

# Todos juntos para registrarlos fácilmente
TODOS_LOS_PERMISOS = (
    PERMISOS_EXPEDIENTES +
    PERMISOS_AUDITORIA +
    PERMISOS_USUARIOS
)