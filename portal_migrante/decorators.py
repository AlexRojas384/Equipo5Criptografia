from django.shortcuts import redirect
from django.contrib import messages
from functools import wraps


def _limpiar_sesion_migrante(request):
    """Borra todas las claves de sesion asociadas al portal del migrante."""
    for clave in ['_migrante_expediente_id', '_migrante_datos',
                  '_migrante_ts', '_migrante_folio_hash']:
        request.session.pop(clave, None)


def sesion_migrante_requerida(view_func):
    """
    Decorador para las vistas del portal de migrantes.
    Verifica que exista una sesion de migrante valida (no la de Django auth).

    La sesion del migrante se almacena con las claves:
      _migrante_expediente_id  — ID del expediente descifrado
      _migrante_datos          — dict con los datos descifrados del expediente
      _migrante_ts             — timestamp UNIX de cuando se autentico
      _migrante_folio_hash     — hash del folio (para verificar titularidad)

    La sesion expira a los 15 minutos de inactividad (igual que la firma).
    Tambien se invalida si el expediente fue eliminado (Cancelacion ARCO ejecutada).
    """
    import time

    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        exp_id = request.session.get('_migrante_expediente_id')
        ts     = request.session.get('_migrante_ts', 0)

        if not exp_id or (time.time() - ts) > 900:
            _limpiar_sesion_migrante(request)
            messages.info(request, 'Tu sesion ha expirado. Ingresa tu folio nuevamente.')
            return redirect('portal_migrante:acceso')

        # Verificar que el expediente siga existiendo (puede haber sido cancelado
        # mediante el flujo ARCO mientras el migrante tenia la sesion abierta).
        from expediente.models import Expediente
        if not Expediente.objects.filter(pk=exp_id).exists():
            _limpiar_sesion_migrante(request)
            messages.info(
                request,
                'Tu expediente ya no existe en nuestros sistemas. '
                'Si solicitaste la Cancelacion de tus datos (derecho ARCO), '
                'tu solicitud fue ejecutada y todos tus datos fueron eliminados. '
                'No es necesario que vuelvas a ingresar.'
            )
            return redirect('portal_migrante:acceso')

        # Renovar timestamp en cada request (ventana deslizante de 15 min)
        request.session['_migrante_ts'] = time.time()
        return view_func(request, *args, **kwargs)

    return _wrapped_view
