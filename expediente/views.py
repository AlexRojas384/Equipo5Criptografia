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
from usuarios.decorators import rol_requerido, ROLES_CON_LECTURA, firma_requerida
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

@login_required(login_url='usuarios:login')
def registrar_migrante(request):
    rol = request.user.rol

    if request.method == 'POST':
        form = EntrevistaForm(request.POST)
        if form.is_valid():
            usuario = request.user

            # Recopilar datos del formulario
            datos = form.cleaned_data
            datos['fecha_atencion']   = str(datos['fecha_atencion'])
            datos['fecha_nacimiento'] = str(datos['fecha_nacimiento'])

            # Cifrar con AES-256 (sin envolver la llave AES aun)
            paquete = cifrar_datos_sin_rsa(datos)
            llave_aes = paquete['llave_aes']

            # Calcular hash del expediente cifrado
            hash_exp = calcular_hash(paquete['datos_cifrados'])

            # No se firma al crear. Queda pendiente de validación si fue creado por Operativo/Usuario,
            # o incluso por admin, pero el estado verificado puede depender del rol, o simplemente False por defecto.
            verificado = False
            firma = None

            # Guardar en BD
            expediente = Expediente.objects.create(
                creado_por        = usuario,
                fecha_atencion    = datos['fecha_atencion'],
                datos_cifrados    = paquete['datos_cifrados'],
                nonce             = paquete['nonce'],
                tag               = paquete['tag'],
                verificado        = verificado,
                firma_digital     = firma,
                hash_expediente   = hash_exp,
            )

            # Crear accesos de llave AES para el creador y los roles
            _crear_accesos_expediente(expediente, llave_aes, usuario)

            messages.success(request, 'Expediente registrado y cifrado. Pendiente de verificacion.')
            return redirect('expediente:dashboard')
    else:
        form = EntrevistaForm()

    return render(request, 'expediente/formulario.html', {'form': form, 'rol': rol})




@login_required(login_url='usuarios:login')
def lista_expedientes(request):
    """
    Muestra todos los expedientes descifrados en una tabla.
    Requiere que la sesion este desbloqueada.
    """
    # Verificar que haya llave en sesion
    llave_privada = request.session.get('_llave_privada_cache')
    if not llave_privada:
        messages.error(request, 'Tu sesión no fue desbloqueada correctamente. Vuelve a iniciar sesión.')
        from django.contrib.auth import logout
        logout(request)
        return redirect('usuarios:login')

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
        'puede_editar': 'puede_editar_expediente' in permisos_rol,
        'puede_eliminar': 'puede_eliminar_expediente' in permisos_rol,
    })


# ─── Verificar expedientes ──────────────────────────────────────────────────

@firma_requerida
def verificar_expedientes(request):
    """
    Recibe IDs de expedientes a verificar. 
    Si viene de un redirect de firma, recupera los datos de la sesión.
    """
    ids_verificar = []
    
    if request.method == 'POST':
        ids_verificar = request.POST.getlist('expedientes_verificar')
    else:
        # Intentar recuperar de la sesión (tras firmar)
        pending_data = request.session.pop('pending_post_data', None)
        pending_url = request.session.pop('pending_post_url', None)
        if pending_data and pending_url == request.path:
            ids_verificar = pending_data.get('expedientes_verificar', [])

    if not ids_verificar and request.method != 'POST':
        return redirect('expediente:lista_expedientes')

    usuario = request.user
    # Solo Coordinadores y Admin pueden verificar
    from usuarios.roles import ROLES as ROLES_CONFIG
    permisos_rol = ROLES_CONFIG.get(usuario.rol, {}).get('permisos', [])
    if 'puede_editar_expediente' not in permisos_rol and 'puede_eliminar_expediente' not in permisos_rol:
        messages.error(request, 'No tienes permisos para verificar expedientes.')
        return redirect('expediente:lista_expedientes')

    ids_verificar = request.POST.getlist('expedientes_verificar')

    if not ids_verificar:
        messages.warning(request, 'No seleccionaste ningun expediente para verificar.')
        return redirect('expediente:lista_expedientes')

    # Obtener llave SAT desde la sesión (validada por el decorador)
    llave_privada = request.session.get('llave_privada_firma')
    if not llave_privada:
        messages.error(request, 'No se encontró tu llave de firma en la sesión. Vuelve a validarla.')
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


# ─── Editar Expediente ──────────────────────────────────────────────────────

@rol_requerido('Administrador', 'Coordinador_Legal', 'Coordinador_Administracion', 'Coordinador_Psicosocial', 'Coordinador_Humanitario', 'Coordinador_Comunicacion')
@firma_requerida
def editar_expediente(request, pk):
    from django.shortcuts import get_object_or_404
    expediente = get_object_or_404(Expediente, pk=pk)
    
    # Obtener llave AES para descifrar los datos y prellenar el form
    usuario = request.user
    llave_privada = request.session.get('_llave_privada_cache')
    llaves_rol = request.session.get('_llaves_rol_cache', {})
    
    acceso = AccesoExpediente.objects.filter(expediente=expediente, usuario=usuario).first()
    llave_aes = None
    
    if acceso:
        try:
            llave_aes = descifrar_llave_aes(acceso.llave_aes_cifrada, llave_privada)
        except Exception:
            pass
            
    if not llave_aes and usuario.rol in llaves_rol:
        acceso_rol = AccesoExpediente.objects.filter(expediente=expediente, tipo_acceso=usuario.rol).first()
        if acceso_rol:
            try:
                llave_rol = llaves_rol[usuario.rol]
                llave_aes = descifrar_llave_aes(acceso_rol.llave_aes_cifrada, llave_rol)
            except Exception:
                pass
                
    if not llave_aes:
        messages.error(request, 'No tienes la llave criptográfica necesaria para editar este expediente.')
        return redirect('expediente:lista_expedientes')
        
    try:
        paquete = {
            'datos_cifrados': expediente.datos_cifrados,
            'nonce': expediente.nonce,
            'tag': expediente.tag
        }
        from cripto.crypto import descifrar_datos_con_aes_existente
        datos_originales = descifrar_datos_con_aes_existente(paquete, llave_aes)
    except Exception:
        messages.error(request, 'Error al descifrar el expediente para su edición.')
        return redirect('expediente:lista_expedientes')

    # Determinar si debemos procesar un POST (directo o recuperado de la sesión tras firmar)
    pending_data = request.session.pop('pending_post_data', None)
    pending_url = request.session.pop('pending_post_url', None)
    
    post_data = None
    if request.method == 'POST':
        post_data = request.POST
    elif pending_data and pending_url == request.path:
        # Convertir el dict de listas de vuelta a algo que Form entienda (QueryDict style)
        from django.utils.datastructures import MultiValueDict
        post_data = MultiValueDict(pending_data)

    if post_data:
        form = EntrevistaForm(post_data)
        if form.is_valid():
            datos_nuevos = form.cleaned_data
            datos_nuevos['fecha_atencion'] = str(datos_nuevos['fecha_atencion'])
            datos_nuevos['fecha_nacimiento'] = str(datos_nuevos['fecha_nacimiento'])
            
            # Cifrar con la misma llave AES (reutilizar)
            from cripto.crypto import cifrar_datos_con_aes_existente
            paquete_nuevo = cifrar_datos_con_aes_existente(datos_nuevos, llave_aes)
            
            # Hash
            hash_exp = calcular_hash(paquete_nuevo['datos_cifrados'])
            
            # Firmar
            llave_privada_sat = request.session.get('llave_privada_firma')
            firma = firmar(hash_exp, llave_privada_sat)
            
            # Actualizar
            expediente.datos_cifrados = paquete_nuevo['datos_cifrados']
            expediente.nonce = paquete_nuevo['nonce']
            expediente.tag = paquete_nuevo['tag']
            expediente.hash_expediente = hash_exp
            expediente.firma_digital = firma
            expediente.verificado = True
            expediente.save()
            
            # Bitacora
            from auditoria.models import BitacoraEvento
            BitacoraEvento.objects.create(
                usuario=usuario,
                tipo='verificacion_expediente',
                descripcion=f'{usuario.username} editó el expediente #{expediente.pk}',
                ip=request.META.get('REMOTE_ADDR', ''),
            )
            
            messages.success(request, f'Expediente #{expediente.pk} actualizado y firmado correctamente.')
            return redirect('expediente:lista_expedientes')
    else:
        # Prellenar form
        if 'fecha_atencion' in datos_originales:
            from datetime import datetime
            try:
                datos_originales['fecha_atencion'] = datetime.strptime(datos_originales['fecha_atencion'], '%Y-%m-%d').date()
            except ValueError:
                pass
        if 'fecha_nacimiento' in datos_originales:
            from datetime import datetime
            try:
                datos_originales['fecha_nacimiento'] = datetime.strptime(datos_originales['fecha_nacimiento'], '%Y-%m-%d').date()
            except ValueError:
                pass
        form = EntrevistaForm(initial=datos_originales)
        
    return render(request, 'expediente/editar_expediente.html', {'form': form, 'expediente': expediente})


# ─── Eliminar Expediente ────────────────────────────────────────────────────

@rol_requerido('Administrador')
@firma_requerida
def eliminar_expediente(request, pk):
    from django.shortcuts import get_object_or_404
    expediente = get_object_or_404(Expediente, pk=pk)
    
    # Permitir eliminación si es POST o si venimos de un redirect de firma exitoso
    is_signed_redirect = request.session.pop('pending_post_url', None) == request.path
    if request.method == 'POST' or is_signed_redirect:
        # La llave de firma ya fue validada por el decorador
        from auditoria.models import BitacoraEvento
        BitacoraEvento.objects.create(
            usuario=request.user,
            tipo='eliminar_expediente',
            descripcion=f'Eliminó expediente #{expediente.pk}',
            ip=request.META.get('REMOTE_ADDR', ''),
        )
        expediente.delete()
        messages.success(request, f'Expediente #{pk} eliminado correctamente.')
        return redirect('expediente:lista_expedientes')
        
    return render(request, 'expediente/confirmar_eliminar.html', {'expediente': expediente})