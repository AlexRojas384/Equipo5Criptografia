from django.contrib import messages
from django.shortcuts import redirect
from functools import wraps


# Roles que tienen acceso a funciones de lectura de expedientes
# (de Operativo para arriba)
ROLES_CON_LECTURA = [
    'Administrador',
    'Coordinador_Administracion',
    'Coordinador_Legal',
    'Coordinador_Psicosocial',
    'Coordinador_Humanitario',
    'Coordinador_Comunicacion',
    'Operativo',
]


def rol_requerido(*roles):
    """
    Decorador que verifica que el usuario tenga uno de los roles indicados
    Y que posea la llave criptografica correspondiente en su sesion.
    
    Si alguien altera la BD para cambiar su rol, el acceso se denegara
    porque no tendra la llave descifrada en su sesion.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('usuarios:login')
            
            usuario_rol = request.user.rol
            
            # Verificar que el rol del usuario esta entre los permitidos
            if usuario_rol not in roles:
                messages.error(request, 'No tienes permisos para acceder a esta seccion.')
                return redirect('expediente:dashboard')
            
            # Verificar que la sesion tiene la llave de rol descifrada
            llaves_cache = request.session.get('_llaves_rol_cache', {})
            if usuario_rol not in llaves_cache:
                messages.error(
                    request,
                    'Tu sesion criptografica no esta desbloqueada o no tienes '
                    'acceso a la llave de tu rol. Desbloquea tu identidad primero.'
                )
                return redirect('expediente:desbloquear_sesion')
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def certificado_requerido(view_func):
    """
    Verifica que el usuario tenga un certificado digital activo y no expirado.
    """
    from django.utils import timezone
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        u = request.user
        if not u.is_authenticated:
            return redirect('usuarios:login')
        
        tiene_todo = u.llave_privada and u.llave_publica and u.certificado_digital
        expirado = u.fecha_expiracion_certificado < timezone.now() if u.fecha_expiracion_certificado else True
        
        if not tiene_todo or expirado:
            messages.error(request, 'Identidad criptografica no valida o expirada. Contacta al administrador para renovar tu certificado.')
            return redirect('expediente:dashboard')
            
        return view_func(request, *args, **kwargs)
    return _wrapped_view
