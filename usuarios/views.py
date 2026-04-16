from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group, Permission
from django.contrib import messages
from django.utils import timezone
from django.http import JsonResponse

from .forms import LoginForm
from .models import Usuario, SolicitudRol
from .permissions import TODOS_LOS_PERMISOS
from .roles import ROLES
from auditoria.models import BitacoraEvento
from .decorators import rol_requerido


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

@rol_requerido('Admin')
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

    return render(request, 'usuarios/admin_panel.html', {
        'usuarios_data': usuarios_data,
        'solicitudes': solicitudes_pendientes,
        'eventos': eventos,
        'roles_disponibles': Usuario.ROLES,
        'todos_los_permisos': TODOS_LOS_PERMISOS,
        'roles_config': ROLES,
        'usuario_actual': request.user,
    })


# ─── Cambiar rol ─────────────────────────────────────────────────────────────

@rol_requerido('Admin')
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

    _registrar_evento(
        request, 'cambio_rol',
        f'Cambió rol de {usuario.username}: {rol_anterior} → {nuevo_rol}'
    )
    messages.success(request, f'Rol de {usuario.username} actualizado a {nuevo_rol}.')
    return redirect('usuarios:admin_panel')


# ─── Toggle permiso individual ───────────────────────────────────────────────

@rol_requerido('Admin')
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

@rol_requerido('Admin')
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

@rol_requerido('Admin')
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

@rol_requerido('Admin')
def crear_usuario(request):
    """El admin crea un nuevo usuario con username, contraseña, rol y llaves RSA."""
    if request.method != 'POST':
        return redirect('usuarios:admin_panel')

    username = request.POST.get('username', '').strip()
    password = request.POST.get('password', '').strip()
    first_name = request.POST.get('first_name', '').strip()
    last_name = request.POST.get('last_name', '').strip()
    rol = request.POST.get('rol', 'Junior')

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

    # Generar llaves y certificados RSA 
    from cripto.crypto import generar_par_llaves, generar_certificado
    llave_privada, llave_publica = generar_par_llaves()
    certificado_pem, expiracion = generar_certificado(llave_privada, llave_publica, username)

    # Crear usuario
    nuevo_usuario = Usuario.objects.create_user(
        username=username,
        password=password,
        first_name=first_name,
        last_name=last_name,
        rol=rol,
        activo=True,
        llave_publica=llave_publica,
        llave_privada=llave_privada,
        certificado_digital=certificado_pem,
        fecha_expiracion_certificado=expiracion,
    )
    nuevo_usuario.asignar_rol()

    _registrar_evento(
        request, 'cambio_rol',
        f'Creó nuevo usuario: {username} con rol {rol}'
    )
    messages.success(request, f'Usuario "{username}" creado exitosamente con rol {rol}.')
    return redirect('usuarios:admin_panel')


@rol_requerido('Admin')
def regenerar_identidad(request, pk):
    """Regenera llaves y certificado para un usuario existente — solo Admin."""
    if request.method != 'POST':
        return redirect('usuarios:admin_panel')

    usuario = get_object_or_404(Usuario, pk=pk)

    from cripto.crypto import generar_par_llaves, generar_certificado
    llave_privada, llave_publica = generar_par_llaves()
    certificado_pem, expiracion = generar_certificado(llave_privada, llave_publica, usuario.username)

    usuario.llave_publica = llave_publica
    usuario.llave_privada = llave_privada
    usuario.certificado_digital = certificado_pem
    usuario.fecha_expiracion_certificado = expiracion
    usuario.save()

    _registrar_evento(
        request, 'cambio_rol',
        f'Regeneró identidad criptográfica para {usuario.username}'
    )
    messages.success(request, f'Identidad criptográfica de {usuario.username} restablecida correctamente.')
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