from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group, Permission
from django.contrib import messages
from django.utils import timezone
from django.http import JsonResponse, HttpResponse
import zipfile
import io
import base64

from .forms import LoginForm
from .models import Usuario, SolicitudRol
from .permissions import TODOS_LOS_PERMISOS
from .roles import ROLES
from auditoria.models import BitacoraEvento
from .decorators import rol_requerido, firma_requerida


# ─── Helpers ────────────────────────────────────────────────────────────────

def _get_client_ip(request):
    """Extrae la IP del cliente del request."""
    x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded:
        return x_forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def _registrar_evento(request, tipo, descripcion):
    """Registra un evento en la bitácora de auditoría."""
    BitacoraEvento.objects.create(
        usuario=request.user,
        tipo=tipo,
        descripcion=descripcion,
        ip=_get_client_ip(request),
    )


# ─── Login / Logout ─────────────────────────────────────────────────────────

def login_view(request):
    # Si ya está autenticado, redirigir
    if request.user.is_authenticated:
        return redirect('expediente:dashboard')

    form = LoginForm(request.POST or None)

    if request.method == 'POST' and form.is_valid():
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']
        user     = authenticate(request, username=username, password=password)

        if user is not None:
            if user.activo:
                login(request, user)
                
                # --- DESBLOQUEO AUTOMATICO (Login Key) ---
                if user.llave_privada and user.salt_login:
                    from cripto.crypto import descifrar_llave_con_password, descifrar_datos
                    import json
                    try:
                        llave_privada_pem = descifrar_llave_con_password(user.llave_privada, password, user.salt_login)
                        request.session['_llave_privada_cache'] = llave_privada_pem
                        
                        # Cargar y descifrar llaves de rol
                        llaves_rol_cache = {}
                        for acceso in user.accesos_rol.select_related('llave_rol').all():
                            try:
                                paquete = json.loads(acceso.llave_privada_rol_cifrada)
                                datos = descifrar_datos(paquete, llave_privada_pem)
                                llaves_rol_cache[acceso.llave_rol.rol] = datos['key']
                            except Exception:
                                pass
                        
                        request.session['_llaves_rol_cache'] = llaves_rol_cache
                    except ValueError:
                        # Si la llave de login no se pudo descifrar (cambio de password forzado o error)
                        pass
                # ------------------------------------------

                # Registrar en bitácora
                BitacoraEvento.objects.create(
                    usuario=user,
                    tipo='login',
                    descripcion=f'Inicio de sesión de {user.username}',
                    ip=_get_client_ip(request),
                )
                return redirect('expediente:dashboard')
            else:
                messages.error(request, 'Tu cuenta está desactivada. Contacta al administrador.')
        else:
            messages.error(request, 'Usuario o contraseña incorrectos.')

    return render(request, 'usuarios/login.html', {'form': form})


def logout_view(request):
    if request.user.is_authenticated:
        BitacoraEvento.objects.create(
            usuario=request.user,
            tipo='logout',
            descripcion=f'Cierre de sesión de {request.user.username}',
            ip=_get_client_ip(request),
        )
    logout(request)
    return redirect('usuarios:login')


# ─── Panel de admin ──────────────────────────────────────────────────────────

@rol_requerido('Administrador')
@firma_requerida
def admin_panel(request):
    """Panel principal de gestión de usuarios — solo Admin."""

    usuarios = Usuario.objects.all().order_by('username')
    solicitudes_pendientes = SolicitudRol.objects.filter(estado='pendiente')
    eventos = BitacoraEvento.objects.all()[:20]

    # Construir datos de permisos por usuario
    usuarios_data = []
    for u in usuarios:
        permisos_usuario = u.user_permissions.values_list('codename', flat=True)
        permisos_grupo = Permission.objects.filter(group__user=u).values_list('codename', flat=True)
        todos = set(permisos_usuario) | set(permisos_grupo)

        cert_expirado = False
        if u.certificado_digital and u.fecha_expiracion_certificado:
            cert_expirado = u.fecha_expiracion_certificado < timezone.now()

        usuarios_data.append({
            'usuario': u,
            'permisos_activos': todos,
            'permisos_individuales': set(permisos_usuario),
            'cert_expirado': cert_expirado,
        })

    # Extraer llave de firma de la sesión (se muestra una sola vez)
    llave_firma_generada = request.session.pop('llave_firma_generada', None)
    llave_firma_usuario = request.session.pop('llave_firma_usuario', None)

    return render(request, 'usuarios/admin_panel.html', {
        'usuarios_data': usuarios_data,
        'solicitudes': solicitudes_pendientes,
        'eventos': eventos,
        'roles_disponibles': Usuario.ROLES,
        'todos_los_permisos': TODOS_LOS_PERMISOS,
        'roles_config': ROLES,
        'usuario_actual': request.user,
        'llave_firma_generada': llave_firma_generada,
        'llave_firma_usuario': llave_firma_usuario,
    })


# ─── Cambiar rol ─────────────────────────────────────────────────────────────

@rol_requerido('Administrador')
def cambiar_rol(request, pk):
    """Cambia el rol de un usuario — solo Admin, vía POST."""

    if request.method != 'POST':
        return redirect('usuarios:admin_panel')

    usuario = get_object_or_404(Usuario, pk=pk)
    nuevo_rol = request.POST.get('nuevo_rol', '')

    roles_validos = [r[0] for r in Usuario.ROLES]
    if nuevo_rol not in roles_validos:
        messages.error(request, f'Rol inválido: {nuevo_rol}')
        return redirect('usuarios:admin_panel')

    rol_anterior = usuario.rol
    usuario.rol = nuevo_rol
    usuario.save()
    usuario.asignar_rol()

    # --- NUEVO: Distribuir Llaves de Rol ---
    if nuevo_rol != 'Usuario':
        from .models import LlaveRol, AccesoLlaveRol
        from cripto.crypto import cifrar_datos, descifrar_datos
        import json
        
        # Si es Admin, le damos TODAS las llaves. Si no, solo la de su rol.
        if nuevo_rol == 'Administrador':
            llaves_a_asignar = LlaveRol.objects.all()
        else:
            llaves_a_asignar = LlaveRol.objects.filter(rol=nuevo_rol)

        for llave_rol_obj in llaves_a_asignar:
            if not AccesoLlaveRol.objects.filter(llave_rol=llave_rol_obj, usuario=usuario).exists():
                # El admin que realiza el cambio debe tener la llave en su cache
                # o debemos sacarla de su propio AccesoLlaveRol
                llave_privada_admin_cache = request.session.get('_llave_privada_cache')
                acceso_admin = AccesoLlaveRol.objects.filter(llave_rol=llave_rol_obj, usuario=request.user).first()
                
                if acceso_admin and llave_privada_admin_cache:
                    try:
                        paquete = json.loads(acceso_admin.llave_privada_rol_cifrada)
                        datos_descifrados = descifrar_datos(paquete, llave_privada_admin_cache)
                        llave_privada_rol_descifrada = datos_descifrados['key']
                        
                        paquete_nuevo = cifrar_datos({'key': llave_privada_rol_descifrada}, usuario.llave_publica)
                        AccesoLlaveRol.objects.create(
                            llave_rol=llave_rol_obj,
                            usuario=usuario,
                            llave_privada_rol_cifrada=json.dumps(paquete_nuevo)
                        )
                    except Exception:
                        pass
                else:
                    messages.warning(request, f'No se pudo asignar la llave de rol "{llave_rol_obj.rol}" porque tu sesión no está desbloqueada.')
    # ---------------------------------------

    _registrar_evento(
        request, 'cambio_rol',
        f'Cambió rol de {usuario.username}: {rol_anterior} → {nuevo_rol}'
    )
    messages.success(request, f'Rol de {usuario.username} actualizado a {nuevo_rol}.')
    return redirect('usuarios:admin_panel')


# ─── Toggle permiso individual ───────────────────────────────────────────────

@rol_requerido('Administrador')
def toggle_permiso(request):
    """Activa/desactiva un permiso individual para un usuario — solo Admin, vía POST."""

    if request.method != 'POST':
        return redirect('usuarios:admin_panel')

    user_id = request.POST.get('user_id')
    codename = request.POST.get('codename')

    usuario = get_object_or_404(Usuario, pk=user_id)

    try:
        permiso = Permission.objects.get(codename=codename)
    except Permission.DoesNotExist:
        messages.error(request, f'Permiso no encontrado: {codename}')
        return redirect('usuarios:admin_panel')

    if usuario.user_permissions.filter(pk=permiso.pk).exists():
        usuario.user_permissions.remove(permiso)
        accion = 'quitado'
    else:
        usuario.user_permissions.add(permiso)
        accion = 'agregado'

    _registrar_evento(
        request, 'toggle_permiso',
        f'Permiso "{codename}" {accion} a {usuario.username}'
    )
    messages.success(request, f'Permiso "{codename}" {accion} para {usuario.username}.')
    return redirect('usuarios:admin_panel')


# ─── Toggle activo/inactivo ──────────────────────────────────────────────────

@rol_requerido('Administrador')
def toggle_activo(request, pk):
    """Activa/desactiva la cuenta de un usuario — solo Admin, vía POST."""

    if request.method != 'POST':
        return redirect('usuarios:admin_panel')

    usuario = get_object_or_404(Usuario, pk=pk)

    if usuario.pk == request.user.pk:
        messages.error(request, 'No puedes desactivarte a ti mismo.')
        return redirect('usuarios:admin_panel')

    usuario.activo = not usuario.activo
    # También toggle is_active de Django para que no pueda hacer login
    usuario.is_active = usuario.activo
    usuario.save()

    estado = 'activado' if usuario.activo else 'desactivado'
    _registrar_evento(
        request, 'toggle_activo',
        f'Usuario {usuario.username} {estado}'
    )
    messages.success(request, f'Usuario {usuario.username} {estado}.')
    return redirect('usuarios:admin_panel')


# ─── Solicitar cambio de rol ─────────────────────────────────────────────────

@login_required(login_url='usuarios:login')
def solicitar_rol(request):
    """Cualquier usuario puede solicitar un cambio de rol."""
    if request.method == 'POST':
        rol_solicitado = request.POST.get('rol_solicitado', '')
        mensaje = request.POST.get('mensaje', '')

        roles_validos = [r[0] for r in Usuario.ROLES]
        if rol_solicitado not in roles_validos:
            messages.error(request, 'Rol inválido.')
            return redirect('usuarios:solicitar_rol')

        if rol_solicitado == request.user.rol:
            messages.warning(request, 'Ya tienes ese rol.')
            return redirect('usuarios:solicitar_rol')

        # Verificar que no tenga una solicitud pendiente
        pendiente = SolicitudRol.objects.filter(
            solicitante=request.user, estado='pendiente'
        ).exists()
        if pendiente:
            messages.warning(request, 'Ya tienes una solicitud pendiente. Espera a que sea revisada.')
            return redirect('usuarios:solicitar_rol')

        SolicitudRol.objects.create(
            solicitante=request.user,
            rol_actual=request.user.rol,
            rol_solicitado=rol_solicitado,
            mensaje=mensaje,
        )

        _registrar_evento(
            request, 'solicitud_creada',
            f'{request.user.username} solicitó cambio de rol: {request.user.rol} → {rol_solicitado}'
        )
        messages.success(request, 'Tu solicitud ha sido enviada al administrador.')
        return redirect('expediente:dashboard')

    # GET — mostrar formulario + historial
    mis_solicitudes = SolicitudRol.objects.filter(solicitante=request.user)
    return render(request, 'usuarios/solicitar_rol.html', {
        'roles': [r for r in Usuario.ROLES if r[0] != request.user.rol],
        'solicitudes': mis_solicitudes,
        'usuario': request.user,
    })


# ─── Responder solicitud (aprobar/rechazar) ──────────────────────────────────

@rol_requerido('Administrador')
def responder_solicitud(request, pk):
    """El admin aprueba o rechaza una solicitud de cambio de rol — vía POST."""

    if request.method != 'POST':
        return redirect('usuarios:admin_panel')

    solicitud = get_object_or_404(SolicitudRol, pk=pk, estado='pendiente')
    accion = request.POST.get('accion', '')  # 'aprobar' o 'rechazar'
    respuesta = request.POST.get('respuesta', '')

    if accion == 'aprobar':
        # Cambiar el rol del solicitante
        usuario = solicitud.solicitante
        rol_anterior = usuario.rol
        usuario.rol = solicitud.rol_solicitado
        usuario.save()
        usuario.asignar_rol()

        # --- NUEVO: Asignar Llave de Rol si el nuevo rol la requiere ---
        nuevo_rol = solicitud.rol_solicitado
        if nuevo_rol != 'Usuario':  # Todos los roles excepto Usuario reciben llave
            from .models import LlaveRol, AccesoLlaveRol
            from cripto.crypto import cifrar_datos, descifrar_datos
            import json
            
            # Si es Admin, le damos TODAS las llaves. Si no, solo la de su rol.
            if nuevo_rol == 'Administrador':
                llaves_a_asignar = LlaveRol.objects.all()
            else:
                llaves_a_asignar = LlaveRol.objects.filter(rol=nuevo_rol)

            for llave_rol_obj in llaves_a_asignar:
                # Verificar si ya la tiene
                if not AccesoLlaveRol.objects.filter(llave_rol=llave_rol_obj, usuario=usuario).exists():
                    # Usar las llaves de rol en cache de la sesion del admin
                    llave_privada_admin = request.session.get('_llave_privada_cache')
                    
                    # El admin debe tener acceso a la llave del rol destino
                    acceso_admin = AccesoLlaveRol.objects.filter(
                        llave_rol=llave_rol_obj, usuario=request.user
                    ).first()
                    
                    if acceso_admin and llave_privada_admin:
                        try:
                            paquete = json.loads(acceso_admin.llave_privada_rol_cifrada)
                            datos_descifrados = descifrar_datos(paquete, llave_privada_admin)
                            llave_privada_rol_descifrada = datos_descifrados['key']
                            
                            paquete_nuevo = cifrar_datos({'key': llave_privada_rol_descifrada}, usuario.llave_publica)
                            AccesoLlaveRol.objects.create(
                                llave_rol=llave_rol_obj,
                                usuario=usuario,
                                llave_privada_rol_cifrada=json.dumps(paquete_nuevo)
                            )
                        except Exception:
                            messages.error(request, 'Error al descifrar la llave de rol para asignarla.')
                    else:
                        messages.warning(request, f'No se pudo asignar la llave de rol "{llave_rol_obj.rol}" porque tu sesion no esta desbloqueada.')
        # --------------------------------------------------------------

        solicitud.estado = 'aprobada'
        solicitud.respondido_por = request.user
        solicitud.respuesta_admin = respuesta
        solicitud.fecha_respuesta = timezone.now()
        solicitud.save()

        _registrar_evento(
            request, 'solicitud_aprobada',
            f'Aprobó solicitud de {usuario.username}: {rol_anterior} → {solicitud.rol_solicitado}'
        )
        messages.success(request, f'Solicitud aprobada. {usuario.username} ahora es {solicitud.rol_solicitado}.')

    elif accion == 'rechazar':
        solicitud.estado = 'rechazada'
        solicitud.respondido_por = request.user
        solicitud.respuesta_admin = respuesta
        solicitud.fecha_respuesta = timezone.now()
        solicitud.save()

        _registrar_evento(
            request, 'solicitud_rechazada',
            f'Rechazó solicitud de {solicitud.solicitante.username}: '
            f'{solicitud.rol_actual} → {solicitud.rol_solicitado}'
        )
        messages.info(request, f'Solicitud de {solicitud.solicitante.username} rechazada.')
    else:
        messages.error(request, 'Acción inválida.')

    return redirect('usuarios:admin_panel')


# ─── Crear usuario (admin) ───────────────────────────────────────────────────

@rol_requerido('Administrador')
def crear_usuario(request):
    """El admin crea un nuevo usuario con username, contraseña, rol y llaves RSA."""
    if request.method != 'POST':
        return redirect('usuarios:admin_panel')

    username = request.POST.get('username', '').strip()
    password = request.POST.get('password', '').strip()
    first_name = request.POST.get('first_name', '').strip()
    last_name = request.POST.get('last_name', '').strip()
    rol = request.POST.get('rol', 'Usuario')

    # Validaciones
    if not username or not password:
        messages.error(request, 'El nombre de usuario y la contraseña son obligatorios.')
        return redirect('usuarios:admin_panel')

    if len(password) < 8:
        messages.error(request, 'La contraseña debe tener al menos 8 caracteres.')
        return redirect('usuarios:admin_panel')

    if Usuario.objects.filter(username=username).exists():
        messages.error(request, f'El usuario "{username}" ya existe.')
        return redirect('usuarios:admin_panel')

    roles_validos = [r[0] for r in Usuario.ROLES]
    if rol not in roles_validos:
        messages.error(request, f'Rol inválido: {rol}')
        return redirect('usuarios:admin_panel')

    # Generar Llave de Acceso (Login Keypair)
    from cripto.crypto import generar_par_llaves, generar_certificado, generar_llave_firma, exportar_llave_privada_der, cifrar_llave_con_password
    import secrets
    import base64

    # 1. Par RSA para Login y su cifrado
    salt_login = secrets.token_hex(32)
    llave_privada_login, llave_publica_login = generar_par_llaves()
    llave_privada_cifrada = cifrar_llave_con_password(llave_privada_login, password, salt_login)

    # Variables de firma (SAT)
    certificado_pem = None
    fecha_expiracion = None
    llave_firma = None

    if rol not in ['Usuario', 'Operativo']:
        # 2. Par RSA para Firma (SAT Style)
        llave_firma = generar_llave_firma()
        privada_firma, publica_firma = generar_par_llaves()
        certificado_pem, certificado_der, fecha_expiracion = generar_certificado(
            privada_firma, publica_firma, username
        )
        llave_privada_der_cifrada = exportar_llave_privada_der(privada_firma, llave_firma)

        # Preparar archivos para descarga en la sesión temporalmente
        request.session['cert_temp_zip'] = {
            'username': username,
            'cer_b64': base64.b64encode(certificado_der).decode('utf-8'),
            'key_b64': base64.b64encode(llave_privada_der_cifrada).decode('utf-8'),
        }

    # Crear usuario
    nuevo_usuario = Usuario.objects.create_user(
        username=username,
        password=password,
        first_name=first_name,
        last_name=last_name,
        rol=rol,
        activo=True,
        llave_publica=llave_publica_login,
        llave_privada=llave_privada_cifrada,
        salt_login=salt_login,
        certificado_digital=certificado_pem,
        fecha_expiracion_certificado=fecha_expiracion,
    )
    nuevo_usuario.asignar_rol()

    # --- NUEVO: Distribuir Llave de Rol si aplica ---
    if rol != 'Usuario':  # Todos los roles excepto Usuario reciben llave
        from .models import LlaveRol, AccesoLlaveRol
        from cripto.crypto import cifrar_datos, descifrar_datos
        import json
        
        # Si es Admin, le damos TODAS las llaves. Si no, solo la de su rol.
        if rol == 'Administrador':
            llaves_a_asignar = LlaveRol.objects.all()
        else:
            llaves_a_asignar = LlaveRol.objects.filter(rol=rol)

        for llave_rol_obj in llaves_a_asignar:
            llave_privada_rol_descifrada = None
            
            # Buscamos si el admin actual tiene acceso a la llave de este rol
            acceso_admin = AccesoLlaveRol.objects.filter(llave_rol=llave_rol_obj, usuario=request.user).first()
            llave_privada_admin = request.session.get('_llave_privada_cache')
            
            if acceso_admin and llave_privada_admin:
                try:
                    paquete = json.loads(acceso_admin.llave_privada_rol_cifrada)
                    datos_descifrados = descifrar_datos(paquete, llave_privada_admin)
                    llave_privada_rol_descifrada = datos_descifrados['key']
                except Exception:
                    pass
            
            if llave_privada_rol_descifrada:
                paquete_nuevo = cifrar_datos({'key': llave_privada_rol_descifrada}, llave_publica_login)
                AccesoLlaveRol.objects.create(
                    llave_rol=llave_rol_obj,
                    usuario=nuevo_usuario,
                    llave_privada_rol_cifrada=json.dumps(paquete_nuevo)
                )
            else:
                messages.warning(request, f'No se pudo asignar la llave de rol "{llave_rol_obj.rol}" al nuevo usuario. Desbloquea tu sesion primero.')
    # ------------------------------------------------

    _registrar_evento(
        request, 'cambio_rol',
        f'Creó nuevo usuario: {username} con rol {rol}'
    )

    # Guardar la llave de firma en la sesión si aplica
    if llave_firma:
        request.session['llave_firma_generada'] = llave_firma
        request.session['llave_firma_usuario'] = username

    messages.success(request, f'Usuario "{username}" creado exitosamente con rol {rol}.')
    return redirect('usuarios:admin_panel')


@rol_requerido('Administrador')
def regenerar_identidad(request, pk):
    """Regenera el certificado de firma (SAT) para un usuario existente — solo Admin."""
    if request.method != 'POST':
        return redirect('usuarios:admin_panel')

    usuario = get_object_or_404(Usuario, pk=pk)

    if usuario.rol in ['Usuario', 'Operativo']:
        messages.error(request, 'Los roles Usuario y Operativo no usan certificados de firma.')
        return redirect('usuarios:admin_panel')

    from cripto.crypto import generar_llave_firma, generar_par_llaves, generar_certificado, exportar_llave_privada_der
    import base64
    
    llave_firma = generar_llave_firma()
    privada_firma, publica_firma = generar_par_llaves()
    certificado_pem, certificado_der, expiracion = generar_certificado(
        privada_firma, publica_firma, usuario.username
    )
    llave_privada_der_cifrada = exportar_llave_privada_der(privada_firma, llave_firma)

    usuario.certificado_digital = certificado_pem
    usuario.fecha_expiracion_certificado = expiracion
    usuario.save()

    # Preparar archivos para descarga en la sesión temporalmente
    request.session['cert_temp_zip'] = {
        'username': usuario.username,
        'cer_b64': base64.b64encode(certificado_der).decode('utf-8'),
        'key_b64': base64.b64encode(llave_privada_der_cifrada).decode('utf-8'),
    }

    _registrar_evento(
        request, 'cambio_rol',
        f'Regeneró certificado de firma para {usuario.username}'
    )

    request.session['llave_firma_generada'] = llave_firma
    request.session['llave_firma_usuario'] = usuario.username

    messages.success(request, f'Certificado de firma de {usuario.username} regenerado correctamente.')
    return redirect('usuarios:admin_panel')

    # Nota: Ya no se re-cifran expedientes ni llaves de rol porque la Llave de Acceso (Login Keypair) se mantiene intacta.
    # ------------------------------------------------

    _registrar_evento(
        request, 'cambio_rol',
        f'Regeneró identidad criptográfica para {usuario.username}'
    )

    # Guardar la llave de firma en la sesión para mostrarla UNA sola vez en el modal
    request.session['llave_firma_generada'] = llave_firma
    request.session['llave_firma_usuario'] = usuario.username

    messages.success(request, f'Identidad criptográfica de {usuario.username} restablecida correctamente.')
    return redirect('usuarios:admin_panel')


@rol_requerido('Administrador')
def revocar_certificado(request, pk):
    """Revoca (elimina) el certificado y llaves de un usuario — solo Admin."""
    if request.method != 'POST':
        return redirect('usuarios:admin_panel')

    usuario = get_object_or_404(Usuario, pk=pk)

    # Limpiar solo campos del certificado (SAT)
    usuario.certificado_digital = None
    usuario.fecha_expiracion_certificado = None
    usuario.save()

    _registrar_evento(
        request, 'cambio_rol',
        f'Revocó certificado e identidad criptográfica para {usuario.username}'
    )

    messages.success(request, f'Certificado de {usuario.username} revocado exitosamente.')
    return redirect('usuarios:admin_panel')


@rol_requerido('Administrador')
def reset_password_admin(request, pk):
    """Permite al admin resetear el password y las llaves de login de un usuario."""
    if request.method != 'POST':
        return redirect('usuarios:admin_panel')

    usuario = get_object_or_404(Usuario, pk=pk)
    nueva_password = request.POST.get('nueva_password', '').strip()

    if len(nueva_password) < 8:
        messages.error(request, 'La contraseña debe tener al menos 8 caracteres.')
        return redirect('usuarios:admin_panel')

    # Generar NUEVO par de llaves de login
    from cripto.crypto import generar_par_llaves, cifrar_llave_con_password
    import secrets

    salt_login = secrets.token_hex(32)
    llave_privada_login, llave_publica_login = generar_par_llaves()
    llave_privada_cifrada = cifrar_llave_con_password(llave_privada_login, nueva_password, salt_login)

    # Actualizar usuario
    usuario.set_password(nueva_password)
    usuario.llave_publica = llave_publica_login
    usuario.llave_privada = llave_privada_cifrada
    usuario.salt_login = salt_login
    usuario.save()

    # --- Distribuir Llaves de Rol ---
    if usuario.rol != 'Usuario':
        from .models import LlaveRol, AccesoLlaveRol
        from cripto.crypto import cifrar_datos, descifrar_datos
        import json
        
        # Eliminar accesos viejos ya que no se pueden descifrar con la nueva llave
        usuario.accesos_rol.all().delete()

        if usuario.rol == 'Administrador':
            llaves_a_asignar = LlaveRol.objects.all()
        else:
            llaves_a_asignar = LlaveRol.objects.filter(rol=usuario.rol)

        for llave_rol_obj in llaves_a_asignar:
            llave_privada_admin_cache = request.session.get('_llave_privada_cache')
            acceso_admin = AccesoLlaveRol.objects.filter(llave_rol=llave_rol_obj, usuario=request.user).first()
            
            if acceso_admin and llave_privada_admin_cache:
                try:
                    paquete = json.loads(acceso_admin.llave_privada_rol_cifrada)
                    datos_descifrados = descifrar_datos(paquete, llave_privada_admin_cache)
                    llave_privada_rol_descifrada = datos_descifrados['key']
                    
                    paquete_nuevo = cifrar_datos({'key': llave_privada_rol_descifrada}, llave_publica_login)
                    AccesoLlaveRol.objects.create(
                        llave_rol=llave_rol_obj,
                        usuario=usuario,
                        llave_privada_rol_cifrada=json.dumps(paquete_nuevo)
                    )
                except Exception:
                    pass

    _registrar_evento(
        request, 'cambio_rol',
        f'Reseteó contraseña y llaves de login para {usuario.username}'
    )
    messages.success(request, f'Contraseña y llaves de {usuario.username} restablecidas correctamente.')
    return redirect('usuarios:admin_panel')

# ─── Cambiar contraseña ──────────────────────────────────────────────────────

@login_required(login_url='usuarios:login')
def cambiar_password(request):
    """Cualquier usuario puede cambiar su propia contraseña."""
    if request.method == 'POST':
        password_actual = request.POST.get('password_actual', '')
        password_nueva = request.POST.get('password_nueva', '')
        password_confirmar = request.POST.get('password_confirmar', '')

        if not request.user.check_password(password_actual):
            messages.error(request, 'La contraseña actual es incorrecta.')
            return redirect('usuarios:cambiar_password')

        if len(password_nueva) < 8:
            messages.error(request, 'La nueva contraseña debe tener al menos 8 caracteres.')
            return redirect('usuarios:cambiar_password')

        if password_nueva != password_confirmar:
            messages.error(request, 'Las contraseñas nuevas no coinciden.')
            return redirect('usuarios:cambiar_password')

        # --- NUEVO: Re-cifrar Llave de Acceso (Login Keypair) ---
        from cripto.crypto import descifrar_llave_con_password, cifrar_llave_con_password
        import secrets
        
        try:
            # 1. Descifrar con la contraseña actual
            llave_privada_pem = descifrar_llave_con_password(
                request.user.llave_privada, password_actual, request.user.salt_login
            )
            
            # 2. Generar nuevo salt y cifrar con la nueva contraseña
            nuevo_salt = secrets.token_hex(32)
            nueva_llave_privada_cifrada = cifrar_llave_con_password(
                llave_privada_pem, password_nueva, nuevo_salt
            )
            
            # 3. Guardar cambios en el modelo de usuario
            request.user.llave_privada = nueva_llave_privada_cifrada
            request.user.salt_login = nuevo_salt
            
            # Actualizar la caché de la sesión para que las llaves de rol sigan funcionando
            request.session['_llave_privada_cache'] = llave_privada_pem
            
        except Exception as e:
            # Si algo falla (ej. la llave no estaba cifrada o el salt era nulo), 
            # podrías decidir si permitir el cambio o no. 
            # Por seguridad, si el usuario no tiene llaves, simplemente ignoramos.
            pass
        # --------------------------------------------------------

        request.user.set_password(password_nueva)
        request.user.save()

        # Re-autenticar para que no se cierre la sesión
        from django.contrib.auth import update_session_auth_hash
        update_session_auth_hash(request, request.user)

        _registrar_evento(
            request, 'cambio_rol',
            f'{request.user.username} cambió su contraseña'
        )
        messages.success(request, 'Tu contraseña ha sido actualizada correctamente.')
        return redirect('expediente:dashboard')

    return render(request, 'usuarios/cambiar_password.html', {
        'usuario': request.user,
    })


@rol_requerido('Administrador')
def descargar_certificado(request):
    """
    Descarga el archivo ZIP temporal generado durante crear_usuario o regenerar_identidad.
    Se borra de la sesión inmediatamente después de descargar.
    """
    cert_data = request.session.get('cert_temp_zip')
    if not cert_data:
        messages.error(request, 'El certificado ya fue descargado o la sesión expiró.')
        return redirect('usuarios:admin_panel')

    username = cert_data['username']
    cer_bytes = base64.b64decode(cert_data['cer_b64'])
    key_bytes = base64.b64decode(cert_data['key_b64'])

    # Crear ZIP en memoria
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr(f'{username}.cer', cer_bytes)
        zip_file.writestr(f'{username}.key', key_bytes)
    
    buffer.seek(0)
    
    # Borrar de la sesión (solo se descarga una vez)
    del request.session['cert_temp_zip']

    response = HttpResponse(buffer, content_type='application/zip')
    response['Content-Disposition'] = f'attachment; filename="FirmaDigital_{username}.zip"'
    return response


@login_required(login_url='usuarios:login')
def ingresar_firma(request):
    """
    Vista para subir el archivo .key y la contraseña de la llave de firma.
    Si es válido, guarda la llave privada en la sesión por 15 minutos.
    """
    next_url = request.GET.get('next', 'expediente:dashboard')
    
    if request.user.rol in ['Usuario', 'Operativo']:
        messages.error(request, 'Tu rol no requiere ni tiene permisos para usar firma digital.')
        return redirect('expediente:dashboard')
        
    if request.method == 'POST':
        archivo_key = request.FILES.get('archivo_key')
        passphrase = request.POST.get('passphrase', '')
        
        if not archivo_key or not passphrase:
            messages.error(request, 'Debes subir tu archivo .key y proporcionar la contraseña.')
            return redirect(f'/usuarios/ingresar-firma/?next={next_url}')
            
        try:
            der_bytes = archivo_key.read()
            from cripto.crypto import importar_llave_privada_der
            privada_pem = importar_llave_privada_der(der_bytes, passphrase)
            
            # Verificar que la llave corresponda al certificado guardado
            # (Una forma simple es intentar firmar algo o comparar llave publica)
            from cryptography.x509 import load_pem_x509_certificate
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            import base64
            
            cert_pem = request.user.certificado_digital
            if not cert_pem:
                raise ValueError("No tienes certificado registrado.")
                
            cert = load_pem_x509_certificate(cert_pem.encode('utf-8'))
            key = load_pem_private_key(privada_pem.encode('utf-8'), password=None)
            
            # Comparar modulus para verificar que la llave privada corresponde al certificado
            if cert.public_key().public_numbers().n != key.public_key().public_numbers().n:
                raise ValueError("La llave no corresponde a tu certificado actual.")
                
            # Guardar estado en sesión
            import time
            request.session['tiempo_firma_reciente'] = time.time()
            request.session['llave_privada_firma'] = privada_pem
            
            messages.success(request, 'Firma validada correctamente. Tienes 15 minutos para realizar operaciones críticas.')
            
            from django.utils.http import url_has_allowed_host_and_scheme
            if url_has_allowed_host_and_scheme(url=next_url, allowed_hosts={request.get_host()}):
                return redirect(next_url)
            else:
                return redirect('expediente:dashboard')
                
        except Exception as e:
            messages.error(request, f'Error al validar la firma: {str(e)}')
            return redirect(f'/usuarios/ingresar-firma/?next={next_url}')
            
    return render(request, 'usuarios/ingresar_firma.html', {'next_url': next_url})