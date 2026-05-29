from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import EntrevistaForm
from .models import Expediente, AccesoExpediente
from cripto.crypto import (
    cifrar_datos_sin_rsa, cifrar_llave_aes, descifrar_llave_aes,
    calcular_hash, firmar, desbloquear_llave_privada,
    descifrar_datos,
    generar_folio, derivar_clave_folio, cifrar_llave_aes_simetrica,
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
        
    # Contar solicitudes ARCO para badge (coincide con filtros de lista_solicitudes_arco)
    if request.user.rol in ['Operativo', 'Coordinador_Administracion', 'Coordinador_Acompanamiento', 'Administrador']:
        from portal_migrante.models import SolicitudARCO
        from django.db.models import Q
        if request.user.rol == 'Operativo':
            context['solicitudes_arco_pendientes'] = SolicitudARCO.objects.filter(estado='pendiente').count()
        elif request.user.rol == 'Administrador':
            context['solicitudes_arco_pendientes'] = SolicitudARCO.objects.filter(
                Q(estado='aprobada_operativo') |
                Q(estado='firmada_coordinador', tipo='cancelacion')
            ).count()
        else:
            context['solicitudes_arco_pendientes'] = SolicitudARCO.objects.filter(estado='aprobada_operativo').count()

    return render(request, 'expediente/dashboard.html', context)


# ─── Registrar migrante ─────────────────────────────────────────────────────

@login_required(login_url='usuarios:login')
def registrar_migrante(request):
    rol = request.user.rol

    if request.method == 'POST':
        form = EntrevistaForm(request.POST)
        if not request.POST.get('aviso_privacidad'):
            form.add_error(None, "Debe mostrar el Aviso de Privacidad al migrante y marcar la casilla de aceptación.")
            
        if form.is_valid():
            usuario = request.user

            # Recopilar datos del formulario
            datos = form.cleaned_data
            datos['fecha_atencion']   = str(datos['fecha_atencion'])
            datos['fecha_nacimiento'] = str(datos['fecha_nacimiento'])

            # ── Folio del migrante ──────────────────────────────────────────
            folio = generar_folio()
            datos['folio'] = folio
            # ───────────────────────────────────────────────────────────────

            # Cifrar con AES-256 (sin envolver la llave AES aun)
            paquete = cifrar_datos_sin_rsa(datos)
            llave_aes = paquete['llave_aes']

            # Calcular hash del expediente cifrado
            hash_exp = calcular_hash(paquete['datos_cifrados'])

            # Hash del folio para busqueda segura
            folio_hash = calcular_hash(folio)

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
                folio_hash        = folio_hash,
            )

            # Crear accesos de llave AES para el creador y los roles
            _crear_accesos_expediente(expediente, llave_aes, usuario)

            # ── Acceso del migrante (cifrado simetrico con Scrypt(folio:nombre)) ─
            nombre_completo = f"{datos.get('nombre_pila', '')} {datos.get('primer_apellido', '')} {datos.get('segundo_apellido', '')}".strip()
            clave_folio = derivar_clave_folio(folio, nombre_completo)
            llave_aes_migrante = cifrar_llave_aes_simetrica(llave_aes, clave_folio)
            AccesoExpediente.objects.create(
                expediente   = expediente,
                tipo_acceso  = 'Migrante',
                usuario      = None,
                llave_aes_cifrada = llave_aes_migrante,
            )
            # ──────────────────────────────────────────────────────────────────

            # Registrar aceptación del aviso de privacidad en bitácora
            from auditoria.models import BitacoraEvento
            BitacoraEvento.objects.create(
                usuario=usuario,
                tipo='aviso_privacidad_aceptado',
                descripcion=f'El migrante con folio {folio} aceptó el Aviso de Privacidad de Casa Monarca.',
                ip=request.META.get('REMOTE_ADDR', ''),
            )

            # Guardar folio en sesion para mostrar UNA SOLA VEZ en el modal
            request.session['folio_generado'] = folio
            request.session['folio_expediente_id'] = expediente.pk

            messages.success(request, 'Expediente registrado y cifrado. Pendiente de verificacion.')
            return redirect('expediente:registrar')

    else:
        form = EntrevistaForm()

    # Extraer folio de la sesion para mostrarlo en el modal (se borra al mostrarse)
    folio_mostrar = request.session.pop('folio_generado', None)
    folio_exp_id  = request.session.pop('folio_expediente_id', None)

    return render(request, 'expediente/formulario.html', {
        'form': form,
        'rol': rol,
        'folio_mostrar': folio_mostrar,
        'folio_exp_id':  folio_exp_id,
    })




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
        # Las fechas vienen como strings 'YYYY-MM-DD' del JSON descifrado.
        # El widget DateInput (format='%Y-%m-%d') las renderiza directamente
        # en el atributo value, compatible con <input type="date">.
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


# ─── GESTION ARCO (INTERNA) ────────────────────────────────────────────────

@login_required
@rol_requerido('Operativo', 'Coordinador_Administracion', 'Coordinador_Acompanamiento', 'Administrador')
def lista_solicitudes_arco(request):
    """
    Lista las solicitudes ARCO segun rol y estado:
      - Operativo:     'pendiente' (todos los tipos) → debe aprobar/rechazar.
      - Coordinadores: 'aprobada_operativo' → debe firmar (rectificacion/oposicion ejecutan;
                       cancelacion solo se valida y pasa al Admin).
      - Administrador: 'aprobada_operativo' (puede actuar como coordinador) +
                       'firmada_coordinador' tipo='cancelacion' (firma final que ejecuta el borrado).
    """
    from portal_migrante.models import SolicitudARCO
    from django.db.models import Q
    rol = request.user.rol

    if rol == 'Operativo':
        solicitudes = SolicitudARCO.objects.filter(estado='pendiente')
    elif rol == 'Administrador':
        solicitudes = SolicitudARCO.objects.filter(
            Q(estado='aprobada_operativo') |
            Q(estado='firmada_coordinador', tipo='cancelacion')
        )
    else:
        # Coordinador_Administracion / Coordinador_Acompanamiento
        solicitudes = SolicitudARCO.objects.filter(estado='aprobada_operativo')

    return render(request, 'expediente/lista_arco.html', {'solicitudes': solicitudes, 'rol': rol})


@login_required
@rol_requerido('Operativo')
def responder_solicitud_arco(request, pk):
    """
    Operativo evalua una solicitud ARCO. Comportamiento por tipo:
      - rectificacion: muestra el expediente prellenado para que el Operativo
        proponga los nuevos valores; el diff se cifra y guarda en cambios_propuestos.
      - oposicion: Operativo escribe una etiqueta que quedara asociada al expediente.
      - cancelacion: pre-aprobacion simple (sin formulario), pasa a Coordinador.
    """
    from portal_migrante.models import SolicitudARCO
    from auditoria.models import BitacoraEvento
    from django.utils import timezone

    solicitud = get_object_or_404(SolicitudARCO, pk=pk)

    # Parsear campos solicitados (string JSON cifrado-en-BD) a dict legible.
    campos_dict = {}
    if solicitud.campos_solicitados:
        try:
            campos_dict = json.loads(solicitud.campos_solicitados)
        except (json.JSONDecodeError, TypeError):
            campos_dict = {'_': solicitud.campos_solicitados}

    # Descifrar el expediente (solo si es rectificacion) para mostrar y prellenar form.
    datos_actuales = None
    if solicitud.tipo == 'rectificacion':
        llaves_rol = request.session.get('_llaves_rol_cache', {})
        if 'Operativo' in llaves_rol:
            datos_actuales = _descifrar_expediente(
                solicitud.expediente, llaves_rol['Operativo'], 'Operativo'
            )
        if datos_actuales is None:
            messages.error(request, 'No se pudo descifrar el expediente asociado.')
            return redirect('expediente:lista_arco')

    if request.method == 'POST':
        accion = request.POST.get('accion')
        respuesta = request.POST.get('respuesta_operativo', '').strip()

        if accion == 'rechazar':
            solicitud.estado = 'rechazada'
            msg = 'Solicitud rechazada.'
            evento = 'solicitud_arco_rechazada'
        elif accion == 'aprobar':
            solicitud.estado = 'aprobada_operativo'
            evento = 'solicitud_arco_aprobada'

            if solicitud.tipo == 'rectificacion':
                # Validar el formulario con los nuevos valores propuestos.
                form = EntrevistaForm(request.POST)
                if not form.is_valid():
                    return render(request, 'expediente/responder_arco.html', {
                        'solicitud': solicitud,
                        'campos_dict': campos_dict,
                        'datos_actuales': datos_actuales,
                        'form': form,
                    })
                nuevos = form.cleaned_data
                nuevos['fecha_atencion'] = str(nuevos['fecha_atencion'])
                nuevos['fecha_nacimiento'] = str(nuevos['fecha_nacimiento'])
                # Calcular diff: solo campos que cambian.
                diff = {k: v for k, v in nuevos.items()
                        if str(datos_actuales.get(k, '')) != str(v)}
                if not diff:
                    messages.error(request, 'No propusiste ningun cambio. Modifica al menos un campo o rechaza la solicitud.')
                    return render(request, 'expediente/responder_arco.html', {
                        'solicitud': solicitud,
                        'campos_dict': campos_dict,
                        'datos_actuales': datos_actuales,
                        'form': form,
                    })
                solicitud.cambios_propuestos = json.dumps(diff, ensure_ascii=False)
                msg = f'Rectificacion aprobada con {len(diff)} cambio(s). Enviada a Coordinacion para firma.'

            elif solicitud.tipo == 'oposicion':
                etiqueta = request.POST.get('etiqueta_oposicion', '').strip()
                if not etiqueta:
                    messages.error(request, 'La etiqueta de oposicion no puede estar vacia.')
                    return render(request, 'expediente/responder_arco.html', {
                        'solicitud': solicitud,
                        'campos_dict': campos_dict,
                    })
                solicitud.etiqueta_oposicion = etiqueta
                msg = 'Oposicion aprobada. Enviada a Coordinacion para firma.'

            else:  # cancelacion
                msg = 'Cancelacion pre-aprobada. Enviada a Coordinacion.'
        else:
            messages.error(request, 'Accion no valida.')
            return redirect('expediente:responder_arco', pk=pk)

        solicitud.operativo = request.user
        solicitud.respuesta_operativo = respuesta
        solicitud.fecha_respuesta_operativo = timezone.now()
        solicitud.save()

        BitacoraEvento.objects.create(
            usuario=request.user,
            tipo=evento,
            descripcion=f'{evento} para ARCO #{solicitud.pk} (tipo={solicitud.tipo})',
            ip=request.META.get('REMOTE_ADDR', '')
        )
        messages.success(request, msg)
        return redirect('expediente:lista_arco')

    # GET
    context = {
        'solicitud': solicitud,
        'campos_dict': campos_dict,
        'datos_actuales': datos_actuales,
    }
    if solicitud.tipo == 'rectificacion' and datos_actuales:
        # Prellenar form con datos actuales del expediente.
        context['form'] = EntrevistaForm(initial=datos_actuales)
    return render(request, 'expediente/responder_arco.html', context)


@login_required
@rol_requerido('Coordinador_Administracion', 'Coordinador_Acompanamiento', 'Administrador')
@firma_requerida
def firmar_solicitud_arco(request, pk):
    """
    Coordinador firma una solicitud ARCO aprobada por el Operativo.
    Comportamiento por tipo al firmar:
      - rectificacion: aplica los cambios propuestos al expediente (descifra,
        actualiza, re-cifra con la misma llave AES, recalcula hash y firma).
        Estado -> ejecutada.
      - oposicion: anexa la etiqueta al expediente (lista JSON cifrada).
        Estado -> ejecutada.
      - cancelacion: solo valida con su firma. Estado -> firmada_coordinador
        (queda pendiente de la firma final del Admin).
    """
    from portal_migrante.models import SolicitudARCO
    from auditoria.models import BitacoraEvento
    from django.utils import timezone
    from cripto.crypto import calcular_hash, firmar, cifrar_datos_con_aes_existente, descifrar_datos_con_aes_existente

    solicitud = get_object_or_404(SolicitudARCO, pk=pk)

    # Patron unificado: recuperar POST original tras redirect del @firma_requerida.
    pending_data = request.session.pop('pending_post_data', None)
    pending_url = request.session.pop('pending_post_url', None)
    post_data = None
    if request.method == 'POST':
        post_data = request.POST
    elif pending_data and pending_url == request.path:
        from django.utils.datastructures import MultiValueDict
        post_data = MultiValueDict(pending_data)

    # Parsear payloads JSON para mostrar legible.
    campos_dict = {}
    if solicitud.campos_solicitados:
        try:
            campos_dict = json.loads(solicitud.campos_solicitados)
        except (json.JSONDecodeError, TypeError):
            campos_dict = {'_': solicitud.campos_solicitados}
    cambios_dict = {}
    if solicitud.cambios_propuestos:
        try:
            cambios_dict = json.loads(solicitud.cambios_propuestos)
        except (json.JSONDecodeError, TypeError):
            cambios_dict = {}

    if post_data:
        accion = post_data.get('accion')
        respuesta = post_data.get('respuesta_coordinador', '').strip()

        if accion == 'rechazar':
            solicitud.estado = 'rechazada'
            solicitud.coordinador = request.user
            solicitud.respuesta_coordinador = respuesta
            solicitud.fecha_firma_coordinador = timezone.now()
            solicitud.save()
            BitacoraEvento.objects.create(
                usuario=request.user,
                tipo='solicitud_arco_rechazada',
                descripcion=f'ARCO #{solicitud.pk} rechazada por Coordinador',
                ip=request.META.get('REMOTE_ADDR', '')
            )
            messages.success(request, 'Solicitud rechazada.')
            return redirect('expediente:lista_arco')

        if accion != 'firmar':
            messages.error(request, 'Accion no valida.')
            return redirect('expediente:firmar_arco', pk=pk)

        # === Firma criptografica ===
        llave_privada_firma = request.session.get('llave_privada_firma')
        if not llave_privada_firma:
            messages.error(request, 'No se encontro tu llave de firma. Vuelve a validarla.')
            return redirect('expediente:lista_arco')

        datos_a_firmar = f"ARCO-{solicitud.pk}-{solicitud.tipo}-{solicitud.hash_solicitud}-{timezone.now().timestamp()}"
        firma_b64 = firmar(datos_a_firmar, llave_privada_firma)
        solicitud.firma_digital = firma_b64
        solicitud.coordinador = request.user
        solicitud.respuesta_coordinador = respuesta
        solicitud.fecha_firma_coordinador = timezone.now()

        # === Aplicar efecto sobre el expediente ===
        if solicitud.tipo == 'rectificacion':
            # Descifrar expediente, aplicar diff, re-cifrar y firmar el expediente.
            expediente = solicitud.expediente
            llaves_rol = request.session.get('_llaves_rol_cache', {})
            rol_user = request.user.rol
            llave_aes = None
            if rol_user in llaves_rol:
                acceso_rol = AccesoExpediente.objects.filter(
                    expediente=expediente, tipo_acceso=rol_user
                ).first()
                if acceso_rol:
                    try:
                        llave_aes = descifrar_llave_aes(acceso_rol.llave_aes_cifrada, llaves_rol[rol_user])
                    except Exception:
                        llave_aes = None
            if llave_aes is None:
                messages.error(request, 'No se pudo descifrar el expediente para aplicar la rectificacion.')
                return redirect('expediente:lista_arco')

            paquete = {
                'datos_cifrados': expediente.datos_cifrados,
                'nonce': expediente.nonce,
                'tag': expediente.tag,
            }
            datos = descifrar_datos_con_aes_existente(paquete, llave_aes)
            datos.update(cambios_dict)
            paquete_nuevo = cifrar_datos_con_aes_existente(datos, llave_aes)
            hash_exp = calcular_hash(paquete_nuevo['datos_cifrados'])
            firma_exp = firmar(hash_exp, llave_privada_firma)
            expediente.datos_cifrados = paquete_nuevo['datos_cifrados']
            expediente.nonce = paquete_nuevo['nonce']
            expediente.tag = paquete_nuevo['tag']
            expediente.hash_expediente = hash_exp
            expediente.firma_digital = firma_exp
            expediente.verificado = True
            expediente.save()

            # Si el nombre cambia, re-cifrar la llave AES para el acceso del migrante con las nuevas credenciales
            campos_nombre = {'nombre_pila', 'primer_apellido', 'segundo_apellido'}
            if campos_nombre & set(cambios_dict.keys()):
                nombre_nuevo = f"{datos.get('nombre_pila', '')} {datos.get('primer_apellido', '')} {datos.get('segundo_apellido', '')}".strip()
                folio = datos.get('folio', '')
                
                clave_nueva = derivar_clave_folio(folio, nombre_nuevo)
                llave_aes_migrante_nueva = cifrar_llave_aes_simetrica(llave_aes, clave_nueva)
                
                acceso_migrante = AccesoExpediente.objects.filter(
                    expediente=expediente, tipo_acceso='Migrante'
                ).first()
                if acceso_migrante:
                    acceso_migrante.llave_aes_cifrada = llave_aes_migrante_nueva
                    acceso_migrante.save()

            solicitud.estado = 'ejecutada'
            msg = f'Rectificacion firmada y aplicada al expediente #{expediente.pk}. Las credenciales del portal del migrante se actualizaron con el nuevo nombre.'
            evento = 'solicitud_arco_ejecutada'

        elif solicitud.tipo == 'oposicion':
            expediente = solicitud.expediente
            try:
                etiquetas = json.loads(expediente.etiquetas_oposicion) if expediente.etiquetas_oposicion else []
            except (json.JSONDecodeError, TypeError):
                etiquetas = []
            etiquetas.append({
                'fecha': timezone.now().isoformat(),
                'etiqueta': solicitud.etiqueta_oposicion,
                'coordinador': request.user.username,
                'solicitud_arco_id': solicitud.pk,
            })
            expediente.etiquetas_oposicion = json.dumps(etiquetas, ensure_ascii=False)
            expediente.save()

            solicitud.estado = 'ejecutada'
            msg = f'Oposicion firmada. Etiqueta aplicada al expediente #{expediente.pk}.'
            evento = 'solicitud_arco_ejecutada'

        else:  # cancelacion
            solicitud.estado = 'firmada_coordinador'
            msg = 'Cancelacion firmada. Pendiente de ejecucion final por un Administrador.'
            evento = 'solicitud_arco_firmada_cancelacion'

        solicitud.save()
        BitacoraEvento.objects.create(
            usuario=request.user,
            tipo=evento,
            descripcion=f'{evento} para ARCO #{solicitud.pk} (tipo={solicitud.tipo})',
            ip=request.META.get('REMOTE_ADDR', '')
        )
        messages.success(request, msg)
        return redirect('expediente:lista_arco')

    campos_nombre = {'nombre_pila', 'primer_apellido', 'segundo_apellido'}
    nombre_cambia = bool(campos_nombre & set(cambios_dict.keys()))

    return render(request, 'expediente/firmar_arco.html', {
        'solicitud': solicitud,
        'campos_dict': campos_dict,
        'cambios_dict': cambios_dict,
        'nombre_cambia': nombre_cambia,
    })



@login_required
@rol_requerido('Administrador')
@firma_requerida
def ejecutar_cancelacion_arco_admin(request, pk):
    """
    Ejecucion final de una solicitud ARCO de cancelacion.
    Solo el Administrador puede borrar fisicamente el expediente, despues de
    que la solicitud paso por Operativo (pre-aprobacion) y Coordinador (firma).
    Es el paso 5 del flujo de cancelacion.
    """
    from portal_migrante.models import SolicitudARCO
    from auditoria.models import BitacoraEvento
    from django.utils import timezone
    from cripto.crypto import firmar

    solicitud = get_object_or_404(SolicitudARCO, pk=pk)

    if solicitud.tipo != 'cancelacion':
        messages.error(request, 'Esta solicitud no es de cancelacion.')
        return redirect('expediente:lista_arco')
    if solicitud.estado != 'firmada_coordinador':
        messages.error(request, 'La cancelacion aun no fue firmada por un Coordinador.')
        return redirect('expediente:lista_arco')

    # Parsear payloads JSON para mostrar legible.
    campos_dict = {}
    if solicitud.campos_solicitados:
        try:
            campos_dict = json.loads(solicitud.campos_solicitados)
        except (json.JSONDecodeError, TypeError):
            campos_dict = {'_': solicitud.campos_solicitados}

    # Patron unificado para recuperar POST tras redirect del @firma_requerida.
    pending_data = request.session.pop('pending_post_data', None)
    pending_url = request.session.pop('pending_post_url', None)
    post_data = None
    if request.method == 'POST':
        post_data = request.POST
    elif pending_data and pending_url == request.path:
        from django.utils.datastructures import MultiValueDict
        post_data = MultiValueDict(pending_data)

    if post_data:
        accion = post_data.get('accion')
        respuesta = post_data.get('respuesta_admin', '').strip()

        if accion == 'rechazar':
            solicitud.estado = 'rechazada'
            solicitud.admin = request.user
            solicitud.respuesta_admin = respuesta
            solicitud.fecha_ejecucion_admin = timezone.now()
            solicitud.save()
            BitacoraEvento.objects.create(
                usuario=request.user,
                tipo='solicitud_arco_cancelacion_rechazada',
                descripcion=f'ARCO #{solicitud.pk} (cancelacion) rechazada por Admin tras firma de Coordinador',
                ip=request.META.get('REMOTE_ADDR', '')
            )
            messages.success(request, 'Cancelacion rechazada en el paso final.')
            return redirect('expediente:lista_arco')

        if accion != 'ejecutar':
            messages.error(request, 'Accion no valida.')
            return redirect('expediente:ejecutar_arco_admin', pk=pk)

        # === Firma de ejecucion ===
        llave_privada_firma = request.session.get('llave_privada_firma')
        if not llave_privada_firma:
            messages.error(request, 'No se encontro tu llave de firma. Vuelve a validarla.')
            return redirect('expediente:lista_arco')

        expediente = solicitud.expediente
        exp_id = expediente.pk
        exp_hash = expediente.hash_expediente
        datos_a_firmar = f"ARCO-CANCEL-{solicitud.pk}-{exp_id}-{exp_hash}-{timezone.now().timestamp()}"
        firma_b64 = firmar(datos_a_firmar, llave_privada_firma)

        solicitud.firma_digital_admin = firma_b64
        solicitud.admin = request.user
        solicitud.respuesta_admin = respuesta
        solicitud.fecha_ejecucion_admin = timezone.now()
        solicitud.estado = 'ejecutada'

        # Borrado fisico del expediente. Las relaciones FK protect previenen
        # borrar mientras haya solicitudes ARCO activas; por eso primero
        # desligamos la FK de esta solicitud al expediente (apuntara a None).
        # Guardamos referencia historica del hash del expediente en la bitacora.
        BitacoraEvento.objects.create(
            usuario=request.user,
            tipo='expediente_cancelado_arco',
            descripcion=f'Expediente #{exp_id} (hash={exp_hash}) eliminado por ARCO #{solicitud.pk}',
            ip=request.META.get('REMOTE_ADDR', '')
        )

        # Romper FK protect: limpiar otras solicitudes ARCO del mismo expediente
        # (todas las que apuntan a este expediente). Las dejamos como ejecutadas
        # sin expediente_id (referencia historica para auditoria).
        from portal_migrante.models import SolicitudARCO as _SArco
        _SArco.objects.filter(expediente=expediente).exclude(pk=solicitud.pk).update(
            expediente=None
        )
        # Esta misma solicitud queda con expediente=None tambien (auditoria).
        solicitud.expediente = None
        solicitud.save()
        expediente.delete()

        messages.success(request, f'Expediente #{exp_id} eliminado definitivamente por ejecucion ARCO.')
        return redirect('expediente:lista_arco')

    return render(request, 'expediente/ejecutar_arco_admin.html', {
        'solicitud': solicitud,
        'campos_dict': campos_dict,
    })