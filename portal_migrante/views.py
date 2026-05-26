from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils import timezone
import time
import json

from expediente.models import Expediente, AccesoExpediente
from auditoria.models import BitacoraEvento
from .models import SolicitudARCO
from .decorators import sesion_migrante_requerida
from cripto.crypto import (
    derivar_clave_folio,
    descifrar_llave_aes_simetrica,
    calcular_hash,
)
from Crypto.Cipher import AES
import base64


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _get_client_ip(request):
    x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded:
        return x_forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def _registrar_evento_anonimo(tipo, descripcion, ip):
    """Registra un evento en la bitacora sin usuario (accesos del portal publico)."""
    BitacoraEvento.objects.create(
        usuario=None,
        tipo=tipo,
        descripcion=descripcion,
        ip=ip,
    )


def _verificar_rate_limit(request):
    """
    Limita a 5 intentos fallidos por IP en 15 minutos.
    Retorna True si se permite el intento, False si esta bloqueado.
    Usa la sesion de Django como almacen temporal (sin dependencia de cache externo).
    """
    ip = _get_client_ip(request)
    ahora = time.time()
    ventana = 900  # 15 minutos

    intentos = request.session.get('_arco_intentos_fallidos', [])
    # Depurar intentos fuera de la ventana
    intentos = [t for t in intentos if (ahora - t) < ventana]

    if len(intentos) >= 5:
        return False

    request.session['_arco_intentos_fallidos'] = intentos
    return True


def _registrar_intento_fallido(request):
    ahora = time.time()
    intentos = request.session.get('_arco_intentos_fallidos', [])
    intentos.append(ahora)
    request.session['_arco_intentos_fallidos'] = intentos


def _limpiar_intentos(request):
    request.session.pop('_arco_intentos_fallidos', None)


# ─── Acceso del migrante ──────────────────────────────────────────────────────

def acceso_migrante(request):
    """
    Pagina de acceso del portal de migrantes.
    El migrante ingresa su nombre completo y su folio (CM-YYYYMMDD-XXXX).
    El sistema:
      1. Calcula SHA-256(folio) y busca el expediente por folio_hash.
      2. Deriva la clave Scrypt(folio:nombre) y la usa para descifrar
         la llave AES almacenada en AccesoExpediente tipo='Migrante'.
      3. Descifra los datos del expediente con la llave AES recuperada.
      4. Si todo es correcto, guarda los datos descifrados en sesion (15 min).
    """
    # Si ya tiene sesion activa, redirigir al dashboard
    if request.session.get('_migrante_expediente_id'):
        ts = request.session.get('_migrante_ts', 0)
        if (time.time() - ts) < 900:
            return redirect('portal_migrante:dashboard')

    if request.method == 'POST':
        nombre  = request.POST.get('nombre', '').strip()
        folio   = request.POST.get('folio', '').strip().upper()
        ip      = _get_client_ip(request)

        if not nombre or not folio:
            messages.error(request, 'Ingresa tu nombre completo y tu folio.')
            return render(request, 'portal_migrante/acceso_migrante.html')

        # Rate limiting
        if not _verificar_rate_limit(request):
            _registrar_evento_anonimo(
                'acceso_migrante_fallido',
                f'IP {ip} bloqueada por exceso de intentos en portal migrante.',
                ip,
            )
            messages.error(
                request,
                'Has superado el numero de intentos permitidos. '
                'Espera 15 minutos antes de intentar de nuevo.'
            )
            return render(request, 'portal_migrante/acceso_migrante.html')

        # Buscar expediente por hash del folio
        folio_hash = calcular_hash(folio)
        expediente = Expediente.objects.filter(folio_hash=folio_hash).first()

        if not expediente:
            _registrar_intento_fallido(request)
            _registrar_evento_anonimo(
                'acceso_migrante_fallido',
                f'Folio no encontrado: {folio_hash[:8]}... desde IP {ip}',
                ip,
            )
            messages.error(request, 'Folio o nombre incorrecto. Verifica tus datos.')
            return render(request, 'portal_migrante/acceso_migrante.html')

        # Buscar el AccesoExpediente tipo Migrante
        acceso = AccesoExpediente.objects.filter(
            expediente=expediente,
            tipo_acceso='Migrante'
        ).first()

        if not acceso:
            _registrar_intento_fallido(request)
            messages.error(request, 'Folio o nombre incorrecto. Verifica tus datos.')
            return render(request, 'portal_migrante/acceso_migrante.html')

        # Intentar descifrar con la clave derivada del folio + nombre
        try:
            clave_derivada = derivar_clave_folio(folio, nombre)
            llave_aes = descifrar_llave_aes_simetrica(acceso.llave_aes_cifrada, clave_derivada)

            # Descifrar los datos del expediente
            datos_cifrados = base64.b64decode(expediente.datos_cifrados)
            nonce          = base64.b64decode(expediente.nonce)
            tag            = base64.b64decode(expediente.tag)
            cipher         = AES.new(llave_aes, AES.MODE_EAX, nonce=nonce)
            datos_json     = cipher.decrypt_and_verify(datos_cifrados, tag)
            datos          = json.loads(datos_json.decode('utf-8'))

        except (ValueError, Exception):
            # Nombre incorrecto o datos corruptos — mismo mensaje para no filtrar informacion
            _registrar_intento_fallido(request)
            _registrar_evento_anonimo(
                'acceso_migrante_fallido',
                f'Nombre incorrecto para folio {folio_hash[:8]}... desde IP {ip}',
                ip,
            )
            messages.error(request, 'Folio o nombre incorrecto. Verifica tus datos.')
            return render(request, 'portal_migrante/acceso_migrante.html')

        # Acceso exitoso — guardar en sesion
        _limpiar_intentos(request)
        request.session['_migrante_expediente_id'] = expediente.pk
        request.session['_migrante_datos']         = datos
        request.session['_migrante_ts']            = time.time()
        request.session['_migrante_folio_hash']    = folio_hash

        _registrar_evento_anonimo(
            'acceso_migrante',
            f'Migrante accedio al portal. Expediente #{expediente.pk}. IP {ip}',
            ip,
        )
        return redirect('portal_migrante:dashboard')

    return render(request, 'portal_migrante/acceso_migrante.html')


# ─── Dashboard del migrante ───────────────────────────────────────────────────

@sesion_migrante_requerida
def dashboard_migrante(request):
    """
    Muestra los datos del expediente en modo solo lectura.
    Incluye accesos a Aviso de Privacidad y derechos ARCO.
    """
    datos       = request.session.get('_migrante_datos', {})
    exp_id      = request.session.get('_migrante_expediente_id')
    folio_hash  = request.session.get('_migrante_folio_hash')

    # Contar solicitudes previas de este expediente
    solicitudes = SolicitudARCO.objects.filter(
        expediente_id=exp_id,
        folio_hash_verificacion=folio_hash,
    ).order_by('-fecha_creacion')

    return render(request, 'portal_migrante/dashboard_migrante.html', {
        'datos':       datos,
        'solicitudes': solicitudes,
        'exp_id':      exp_id,
    })


# ─── Aviso de privacidad ──────────────────────────────────────────────────────

def aviso_privacidad(request):
    """Pagina estatica con el aviso de privacidad de Casa Monarca."""
    return render(request, 'portal_migrante/aviso_privacidad.html')


# ─── Solicitar derecho ARCO ───────────────────────────────────────────────────

@sesion_migrante_requerida
def solicitar_arco(request):
    """
    El migrante elige el tipo de derecho ARCO y describe su solicitud.
    Para rectificacion puede especificar los campos a corregir.
    La solicitud queda en estado 'pendiente' hasta que el Operativo la atienda.
    """
    exp_id     = request.session.get('_migrante_expediente_id')
    folio_hash = request.session.get('_migrante_folio_hash')

    if request.method == 'POST':
        tipo        = request.POST.get('tipo', '').strip()
        descripcion = request.POST.get('descripcion', '').strip()
        campos_raw  = request.POST.get('campos_solicitados', '').strip()

        tipos_validos = ['rectificacion', 'cancelacion', 'oposicion']
        if tipo not in tipos_validos:
            messages.error(request, 'Tipo de solicitud no valido.')
            return redirect('portal_migrante:solicitar_arco')

        if not descripcion:
            messages.error(request, 'Describe el cambio que solicitas.')
            return redirect('portal_migrante:solicitar_arco')

        # Validar JSON de campos si se proporcionaron
        campos_json = ''
        if campos_raw:
            try:
                campos_dict = json.loads(campos_raw)
                campos_json = json.dumps(campos_dict, ensure_ascii=False)
            except json.JSONDecodeError:
                campos_json = json.dumps({'descripcion_libre': campos_raw}, ensure_ascii=False)

        hash_solicitud = calcular_hash(descripcion + tipo + str(exp_id))

        SolicitudARCO.objects.create(
            expediente_id          = exp_id,
            tipo                   = tipo,
            descripcion_cifrada    = descripcion,
            campos_solicitados     = campos_json,
            hash_solicitud         = hash_solicitud,
            folio_hash_verificacion= folio_hash,
        )

        _registrar_evento_anonimo(
            'solicitud_arco_creada',
            f'Solicitud ARCO tipo "{tipo}" creada para expediente #{exp_id}.',
            _get_client_ip(request),
        )

        messages.success(
            request,
            'Tu solicitud ha sido enviada. Puedes consultar su estado en "Mis solicitudes".'
        )
        return redirect('portal_migrante:mis_solicitudes')

    return render(request, 'portal_migrante/solicitar_arco.html')


# ─── Historial de solicitudes ─────────────────────────────────────────────────

@sesion_migrante_requerida
def mis_solicitudes(request):
    """Lista las solicitudes ARCO del expediente activo en sesion."""
    exp_id     = request.session.get('_migrante_expediente_id')
    folio_hash = request.session.get('_migrante_folio_hash')

    solicitudes = SolicitudARCO.objects.filter(
        expediente_id=exp_id,
        folio_hash_verificacion=folio_hash,
    ).order_by('-fecha_creacion')

    return render(request, 'portal_migrante/mis_solicitudes.html', {
        'solicitudes': solicitudes,
    })


# ─── Cerrar sesion del migrante ───────────────────────────────────────────────

def cerrar_sesion_migrante(request):
    """Limpia la sesion temporal del migrante."""
    for clave in ['_migrante_expediente_id', '_migrante_datos',
                  '_migrante_ts', '_migrante_folio_hash',
                  '_arco_intentos_fallidos']:
        request.session.pop(clave, None)
    return redirect('portal_migrante:acceso')
