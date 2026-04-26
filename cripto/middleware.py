from django.shortcuts import redirect
from django.contrib.auth import logout
from django.contrib import messages
from django.utils import timezone
from django.urls import reverse

class CertificadoExpiracionMiddleware:
    """
    Bloquea las cuentas autenticadas cuyo certificado haya expirado o no tengan llaves,
    forzando un logout y notificando al usuario.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            rutas_excluidas = [
                reverse('usuarios:login'),
                reverse('usuarios:logout'),
            ]

            if request.path not in rutas_excluidas:
                u = request.user
                # Solo bloquear si el rol requiere firma (Admin y Coordinadores)
                # Los roles Usuario y Operativo NO requieren certificado digital.
                rol_actual = getattr(u, 'rol', 'Usuario')
                if rol_actual not in ['Usuario', 'Operativo']:
                    tiene_todo = u.llave_privada and u.llave_publica and u.certificado_digital
                    # Si no tiene fecha, lo consideramos expirado por seguridad (debe tener identidad)
                    expirado = (u.fecha_expiracion_certificado < timezone.now()) if u.fecha_expiracion_certificado else True
                    
                    if not tiene_todo or expirado:
                        logout(request)
                        messages.error(
                            request, 
                            'Tu sesión ha sido bloqueada porque tu identidad criptográfica expiró o es inválida. Contacta al Administrador.'
                        )
                        return redirect('usuarios:login')
                    
        response = self.get_response(request)
        return response
