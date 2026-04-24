from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import EntrevistaForm
from .models import Expediente, AccesoExpediente
from cripto.crypto import (
    cifrar_datos_sin_rsa, cifrar_llave_aes, descifrar_llave_aes,
    calcular_hash, firmar, desbloquear_llave_privada,
    descifrar_datos,
)
from usuarios.decorators import certificado_requerido, ROLES_CON_LECTURA
from usuarios.models import LlaveRol, AccesoLlaveRol
import json, base64
from Crypto.Cipher import AES


# Roles que reciben copia de la llave AES al crear un expediente
ROLES_DESTINO_EXPEDIENTE = [
    'Administrador',
    'Coordinador_Administracion',
    'Coordinador_Legal',
    'Coordinador_Psicosocial',
    'Coordinador_Humanitario',
    'Coordinador_Comunicacion',
    'Operativo',
]


# ─── Helpers ────────────────────────────────────────────────────────────────

def _obtener_llave_rol_publica(rol_name):
    """Obtiene la llave publica RSA de un rol, o None si no existe."""
    try:
        return LlaveRol.objects.get(rol=rol_name).llave_publica
    except LlaveRol.DoesNotExist:
        return None


def _crear_accesos_expediente(expediente, llave_aes_bytes, usuario):
    """Crea las copias de la llave AES cifrada para el creador y todos los roles de Operativo para arriba."""
    # 1. Copia para el creador (personal)
    AccesoExpediente.objects.create(
        expediente=expediente,
        tipo_acceso='Creador',
        usuario=usuario,
        llave_aes_cifrada=cifrar_llave_aes(llave_aes_bytes, usuario.llave_publica),
    )

    # 2. Copia para cada rol que debe tener acceso de lectura
    for rol_name in ROLES_DESTINO_EXPEDIENTE:
        pub_rol = _obtener_llave_rol_publica(rol_name)
        if pub_rol:
            AccesoExpediente.objects.create(
                expediente=expediente,
                tipo_acceso=rol_name,
                llave_aes_cifrada=cifrar_llave_aes(llave_aes_bytes, pub_rol),
            )


def _descifrar_expediente(expediente, llave_privada_pem, tipo_acceso, usuario=None):
    """
    Descifra un expediente usando un AccesoExpediente especifico.
    Retorna dict con los datos descifrados o None si falla.
    """
    try:
        filtro = {'expediente': expediente, 'tipo_acceso': tipo_acceso}
        if tipo_acceso == 'Creador' and usuario:
            filtro['usuario'] = usuario
        acceso = AccesoExpediente.objects.filter(**filtro).first()
        if not acceso:
            return None

        # Descifrar la llave AES
        llave_aes = descifrar_llave_aes(acceso.llave_aes_cifrada, llave_privada_pem)

        # Descifrar los datos del expediente
        datos_cifrados = base64.b64decode(expediente.datos_cifrados)
        nonce = base64.b64decode(expediente.nonce)
        tag = base64.b64decode(expediente.tag)

        cipher = AES.new(llave_aes, AES.MODE_EAX, nonce=nonce)
        datos_json = cipher.decrypt_and_verify(datos_cifrados, tag)
        return json.loads(datos_json.decode('utf-8'))
    except Exception:
        return None


# ─── Dashboard ──────────────────────────────────────────────────────────────

@login_required(login_url='usuarios:login')
def dashboard(request):
    from django.contrib.auth.models import Permission
    from django.utils import timezone
    from usuarios.roles import ROLES
    
    context = {
        'usuario': request.user,
        'rol': request.user.rol,
    }
    
    # Calcular permisos desde el diccionario de roles
    rol_config = ROLES.get(request.user.rol, {})
    permisos_rol = rol_config.get('permisos', [])
    
    nombres_amigables = {
        'puede_crear_expediente': 'Registrar expedientes nuevos',
        'puede_ver_expediente': 'Visualizar expedientes',
        'puede_editar_expediente': 'Editar expedientes',
        'puede_eliminar_expediente': 'Eliminar expedientes',
        'puede_exportar_expediente': 'Exportar expedientes',
        'puede_ver_bitacora': 'Ver bitacora de auditoria',
        'puede_gestionar_usuarios': 'Gestionar usuarios',
    }
    
    permisos_amigables = [nombres_amigables.get(p, p) for p in permisos_rol]
    context['permisos_amigables'] = sorted(permisos_amigables)
    context['permisos_rol'] = permisos_rol
    
    # Status de llaves y certificados
    context['tiene_llaves'] = bool(request.user.llave_privada and request.user.llave_publica)
    context['tiene_cert'] = bool(request.user.certificado_digital)
    context['cert_expirado'] = (
        request.user.fecha_expiracion_certificado < timezone.now() 
        if context['tiene_cert'] and request.user.fecha_expiracion_certificado 
        else False
    )

    # Si es Administrador, contar solicitudes pendientes para mostrar badge
    if request.user.rol == 'Administrador':
        from usuarios.models import SolicitudRol
        context['solicitudes_pendientes'] = SolicitudRol.objects.filter(estado='pendiente').count()
    return render(request, 'expediente/dashboard.html', context)


# ─── Registrar migrante ─────────────────────────────────────────────────────

@certificado_requerido
def registrar_migrante(request):
    rol = request.user.rol
    # Los roles de Coordinador y Admin requieren firma obligatoria
    requiere_firma = rol in (
        'Administrador',
        'Coordinador_Administracion', 'Coordinador_Legal',
        'Coordinador_Psicosocial', 'Coordinador_Humanitario',
        'Coordinador_Comunicacion',
    )

    if request.method == 'POST':
        form = EntrevistaForm(request.POST)
        if form.is_valid():
            usuario = request.user

            llave_privada_descifrada = None
            firma = None

            if requiere_firma:
                llave_firma = request.POST.get('llave_firma', '')
                if not llave_firma:
                    messages.error(request, 'Debes ingresar tu llave de firma para autorizar el expediente.')
                    return render(request, 'expediente/formulario.html', {'form': form, 'rol': rol})

                try:
                    llave_privada_descifrada = desbloquear_llave_privada(usuario.llave_privada, llave_firma)
                except ValueError:
                    messages.error(request, 'Llave de firma incorrecta. Verifica e intenta de nuevo.')
                    return render(request, 'expediente/formulario.html', {'form': form, 'rol': rol})

            # Recopilar datos del formulario
            datos = form.cleaned_data
            datos['fecha_atencion']   = str(datos['fecha_atencion'])
            datos['fecha_nacimiento'] = str(datos['fecha_nacimiento'])

            # Cifrar con AES-256 (sin envolver la llave AES aun)
            paquete = cifrar_datos_sin_rsa(datos)
            llave_aes = paquete['llave_aes']

            # Calcular hash del expediente cifrado
            hash_exp = calcular_hash(paquete['datos_cifrados'])

            # Firma digital (solo para Coordinador+ / Admin)
            if requiere_firma and llave_privada_descifrada:
                firma = firmar(hash_exp, llave_privada_descifrada)

            # Guardar en BD
            expediente = Expediente.objects.create(
                creado_por        = usuario,
                fecha_atencion    = datos['fecha_atencion'],
                datos_cifrados    = paquete['datos_cifrados'],
                nonce             = paquete['nonce'],
                tag               = paquete['tag'],
                verificado        = requiere_firma,
                firma_digital     = firma,
                hash_expediente   = hash_exp,
            )

            # Crear accesos de llave AES para el creador y los roles
            _crear_accesos_expediente(expediente, llave_aes, usuario)

            if requiere_firma:
                messages.success(request, 'Expediente registrado, cifrado y firmado correctamente.')
            else:
                messages.success(request, 'Expediente registrado y cifrado. Pendiente de verificacion.')
            return redirect('expediente:dashboard')
    else:
        form = EntrevistaForm()

    return render(request, 'expediente/formulario.html', {'form': form, 'rol': rol})


# ─── Desbloquear sesion ─────────────────────────────────────────────────────

@certificado_requerido
def desbloquear_sesion(request):
    """
    Pide la llave_firma una sola vez, desbloquea la llave privada del usuario
    y TODAS las llaves de rol a las que tenga acceso, almacenandolas en la sesion.
    """
    # Si ya esta desbloqueado, redirigir directo
    if request.session.get('_llave_privada_cache'):
        return redirect('expediente:lista_expedientes')

    if request.method == 'POST':
        llave_firma = request.POST.get('llave_firma', '')
        usuario = request.user

        if not llave_firma:
            messages.error(request, 'Debes ingresar tu llave de firma.')
            return render(request, 'expediente/desbloquear_sesion.html', {'rol': usuario.rol})

        try:
            llave_privada = desbloquear_llave_privada(usuario.llave_privada, llave_firma)
        except ValueError:
            messages.error(request, 'Llave de firma incorrecta. Verifica e intenta de nuevo.')
            return render(request, 'expediente/desbloquear_sesion.html', {'rol': usuario.rol})

        # Guardar la llave privada personal en sesion
        request.session['_llave_privada_cache'] = llave_privada

        # Desbloquear TODAS las llaves de rol a las que tenga acceso
        llaves_rol_cache = {}
        accesos_rol = AccesoLlaveRol.objects.select_related('llave_rol').filter(usuario=usuario)
        
        for acceso in accesos_rol:
            try:
                paquete = json.loads(acceso.llave_privada_rol_cifrada)
                datos_descifrados = descifrar_datos(paquete, llave_privada)
                llave_rol_pem = datos_descifrados['key']
                llaves_rol_cache[acceso.llave_rol.rol] = llave_rol_pem
            except Exception:
                pass  # Silenciar errores individuales

        request.session['_llaves_rol_cache'] = llaves_rol_cache
        
        if llaves_rol_cache:
            roles_desbloqueados = ', '.join(llaves_rol_cache.keys())
            messages.success(request, f'Sesion desbloqueada. Acceso a roles: {roles_desbloqueados}')
        else:
            messages.info(request, 'Sesion desbloqueada (solo acceso personal).')

        return redirect('expediente:lista_expedientes')

    return render(request, 'expediente/desbloquear_sesion.html', {'rol': request.user.rol})


# ─── Lista de expedientes ───────────────────────────────────────────────────

@certificado_requerido
def lista_expedientes(request):
    """
    Muestra todos los expedientes descifrados en una tabla.
    Requiere que la sesion este desbloqueada.
    """
    # Verificar que haya llave en sesion
    llave_privada = request.session.get('_llave_privada_cache')
    if not llave_privada:
        return redirect('expediente:desbloquear_sesion')

    usuario = request.user
    rol = usuario.rol
    llaves_rol_cache = request.session.get('_llaves_rol_cache', {})

    # Obtener expedientes segun el rol
    if rol in ROLES_CON_LECTURA:
        # Operativo para arriba: todos los expedientes
        expedientes = Expediente.objects.all().select_related('creado_por')
    else:
        # Usuario: solo los suyos
        expedientes = Expediente.objects.filter(creado_por=usuario).select_related('creado_por')

    # Filtros desde GET params
    filtro_verificado = request.GET.get('verificado', '')
    filtro_creador = request.GET.get('creador', '')
    filtro_fecha_desde = request.GET.get('fecha_desde', '')
    filtro_fecha_hasta = request.GET.get('fecha_hasta', '')

    if filtro_verificado == 'si':
        expedientes = expedientes.filter(verificado=True)
    elif filtro_verificado == 'no':
        expedientes = expedientes.filter(verificado=False)

    if filtro_creador:
        expedientes = expedientes.filter(creado_por__username__icontains=filtro_creador)

    if filtro_fecha_desde:
        expedientes = expedientes.filter(fecha_atencion__gte=filtro_fecha_desde)
    if filtro_fecha_hasta:
        expedientes = expedientes.filter(fecha_atencion__lte=filtro_fecha_hasta)

    # Descifrar cada expediente
    expedientes_data = []
    for exp in expedientes:
        datos = None

        # Intentar con la llave de rol del usuario
        if rol in llaves_rol_cache:
            datos = _descifrar_expediente(exp, llaves_rol_cache[rol], rol)

        # Si no funciono con la del rol, intentar con cualquier otra llave de rol
        if datos is None:
            for rol_name, llave_rol_pem in llaves_rol_cache.items():
                if rol_name != rol:
                    datos = _descifrar_expediente(exp, llave_rol_pem, rol_name)
                    if datos:
                        break

        # Fallback: intentar como creador
        if datos is None:
            datos = _descifrar_expediente(exp, llave_privada, 'Creador', usuario)

        expedientes_data.append({
            'expediente': exp,
            'datos': datos,  # None si no se pudo descifrar
        })

    # Obtener lista de creadores para el filtro
    from usuarios.models import Usuario
    if rol in ROLES_CON_LECTURA:
        creadores = Usuario.objects.filter(expedientes__isnull=False).distinct().values_list('username', flat=True)
    else:
        creadores = []

    # Determinar permisos para la vista
    from usuarios.roles import ROLES as ROLES_CONFIG
    permisos_rol = ROLES_CONFIG.get(rol, {}).get('permisos', [])

    return render(request, 'expediente/lista_expedientes.html', {
        'expedientes_data': expedientes_data,
        'rol': rol,
        'filtro_verificado': filtro_verificado,
        'filtro_creador': filtro_creador,
        'filtro_fecha_desde': filtro_fecha_desde,
        'filtro_fecha_hasta': filtro_fecha_hasta,
        'creadores': creadores,
        'puede_verificar': 'puede_editar_expediente' in permisos_rol or 'puede_eliminar_expediente' in permisos_rol,
    })


# ─── Verificar expedientes ──────────────────────────────────────────────────

@certificado_requerido
def verificar_expedientes(request):
    """
    POST: Recibe IDs de expedientes a verificar + llave_firma.
    Requiere reingresar la llave como confirmacion explicita.
    """
    if request.method != 'POST':
        return redirect('expediente:lista_expedientes')

    usuario = request.user
    # Solo Coordinadores y Admin pueden verificar
    from usuarios.roles import ROLES as ROLES_CONFIG
    permisos_rol = ROLES_CONFIG.get(usuario.rol, {}).get('permisos', [])
    if 'puede_editar_expediente' not in permisos_rol and 'puede_eliminar_expediente' not in permisos_rol:
        messages.error(request, 'No tienes permisos para verificar expedientes.')
        return redirect('expediente:lista_expedientes')

    llave_firma = request.POST.get('llave_firma', '')
    ids_verificar = request.POST.getlist('expedientes_verificar')

    if not llave_firma:
        messages.error(request, 'Debes ingresar tu llave de firma para verificar expedientes.')
        return redirect('expediente:lista_expedientes')

    if not ids_verificar:
        messages.warning(request, 'No seleccionaste ningun expediente para verificar.')
        return redirect('expediente:lista_expedientes')

    # Validar la llave de firma
    try:
        llave_privada = desbloquear_llave_privada(usuario.llave_privada, llave_firma)
    except ValueError:
        messages.error(request, 'Llave de firma incorrecta.')
        return redirect('expediente:lista_expedientes')

    # Verificar y firmar cada expediente
    verificados = 0
    for exp_id in ids_verificar:
        try:
            expediente = Expediente.objects.get(pk=exp_id)
            if not expediente.verificado:
                # Recalcular hash y firmar
                hash_exp = calcular_hash(expediente.datos_cifrados)
                firma = firmar(hash_exp, llave_privada)
                expediente.verificado = True
                expediente.firma_digital = firma
                expediente.hash_expediente = hash_exp
                expediente.save()
                verificados += 1
        except Expediente.DoesNotExist:
            continue

    # Registrar en bitacora
    from auditoria.models import BitacoraEvento
    BitacoraEvento.objects.create(
        usuario=usuario,
        tipo='verificacion_expediente',
        descripcion=f'{usuario.username} verifico {verificados} expediente(s)',
        ip=request.META.get('REMOTE_ADDR', ''),
    )

    messages.success(request, f'{verificados} expediente(s) verificado(s) y firmado(s) correctamente.')
    return redirect('expediente:lista_expedientes')