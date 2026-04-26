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
            if usuario_rol != 'Usuario':
                llaves_cache = request.session.get('_llaves_rol_cache', {})
                if usuario_rol not in llaves_cache:
                    messages.error(
                        request,
                        'Tu sesión criptográfica no fue desbloqueada correctamente. '
                        'Cierra sesión y vuelve a entrar.'
                    )
                    from django.contrib.auth import logout
                    logout(request)
                    return redirect('usuarios:login')
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def firma_requerida(view_func):
    """
    Decorador para operaciones críticas. Requiere que el usuario valide su identidad
    subiendo su archivo .key (SAT style) y proporcionando su contraseña.
    Si la validación fue exitosa, dura 15 minutos en la sesión.
    """
    import time
    import urllib.parse

    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('usuarios:login')

        u = request.user
        if u.rol in ['Usuario', 'Operativo']:
            messages.error(request, 'Tu rol no tiene permisos para realizar esta acción crítica (requiere firma).')
            return redirect('expediente:dashboard')

        # Verificar si tiene certificado
        from django.utils import timezone
        tiene_cert = bool(u.certificado_digital)
        expirado = u.fecha_expiracion_certificado < timezone.now() if u.fecha_expiracion_certificado else True
        if not tiene_cert or expirado:
            messages.error(request, 'No tienes un certificado de firma válido o ha expirado. Contacta al administrador.')
            return redirect('expediente:dashboard')

        tiempo_firma = request.session.get('tiempo_firma_reciente', 0)
        tiempo_actual = time.time()

        # Si no ha firmado o pasaron más de 15 minutos (900 seg)
        if (tiempo_actual - tiempo_firma) > 900:
            path = request.get_full_path()
            url_next = urllib.parse.quote(path)
            messages.info(request, 'Operación crítica protegida. Por favor, sube tu llave de firma (.key).')
            return redirect(f'/usuarios/ingresar-firma/?next={url_next}')

        return view_func(request, *args, **kwargs)
    return _wrapped_view
