from django.contrib import messages
from django.shortcuts import redirect
from functools import wraps

def rol_requerido(*roles):
    """
    Decorador para verificar que el usuario autenticado tiene alguno de los roles permitidos.
    En caso contrario, muestra un mensaje y redirige al dashboard.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('usuarios:login')
            if request.user.rol in roles:
                return view_func(request, *args, **kwargs)
            messages.error(request, 'No tienes permisos para acceder a esta sección.')
            return redirect('expediente:dashboard')
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
            messages.error(request, 'Identidad criptográfica no válida o expirada. Contacta al administrador para renovar tu certificado.')
            return redirect('expediente:dashboard')
            
        return view_func(request, *args, **kwargs)
    return _wrapped_view
