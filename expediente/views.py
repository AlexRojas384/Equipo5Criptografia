from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import EntrevistaForm
from .models import Expediente
from cripto.crypto import cifrar_datos, calcular_hash, firmar, desbloquear_llave_privada
from usuarios.decorators import certificado_requerido

@login_required(login_url='usuarios:login')
def dashboard(request):
    from django.contrib.auth.models import Permission
    from django.utils import timezone
    
    context = {
        'usuario': request.user,
        'rol': request.user.rol,
    }
    
    # Calcular permisos amigables
    permisos_usuario = request.user.user_permissions.all()
    permisos_grupo = Permission.objects.filter(group__user=request.user)
    todos_permisos_raw = set(permisos_usuario) | set(permisos_grupo)
    
    nombres_amigables = {
        'add_expediente': 'Registrar expedientes nuevos',
        'view_expediente': 'Visualizar expedientes',
        'change_expediente': 'Editar expedientes',
        'delete_expediente': 'Eliminar expedientes',
        'add_usuario': 'Agregar nuevos usuarios',
        'view_usuario': 'Vistas de la base de usuarios',
        'change_usuario': 'Modificar roles o usuarios',
        'delete_usuario': 'Eliminar usuarios',
    }
    
    permisos_amigables = []
    for p in todos_permisos_raw:
        permisos_amigables.append(nombres_amigables.get(p.codename, p.name))
        
    context['permisos_amigables'] = sorted(list(set(permisos_amigables)))
    
    # Status de llaves y certificados
    context['tiene_llaves'] = bool(request.user.llave_privada and request.user.llave_publica)
    context['tiene_cert'] = bool(request.user.certificado_digital)
    context['cert_expirado'] = (
        request.user.fecha_expiracion_certificado < timezone.now() 
        if context['tiene_cert'] and request.user.fecha_expiracion_certificado 
        else False
    )

    # Si es Admin, contar solicitudes pendientes para mostrar badge
    if request.user.rol == 'Admin':
        from usuarios.models import SolicitudRol
        context['solicitudes_pendientes'] = SolicitudRol.objects.filter(estado='pendiente').count()
    return render(request, 'expediente/dashboard.html', context)

@certificado_requerido
def registrar_migrante(request):
    if request.method == 'POST':
        form = EntrevistaForm(request.POST)
        if form.is_valid():
            usuario = request.user
            llave_firma = request.POST.get('llave_firma', '')

            # 1. Validar la llave de firma (desbloquear la llave privada)
            if not llave_firma:
                messages.error(request, '❌ Debes ingresar tu llave de firma para autorizar el expediente.')
                return render(request, 'expediente/formulario.html', {'form': form})

            try:
                llave_privada_descifrada = desbloquear_llave_privada(usuario.llave_privada, llave_firma)
            except ValueError:
                messages.error(request, '❌ Llave de firma incorrecta. Verifica e intenta de nuevo.')
                return render(request, 'expediente/formulario.html', {'form': form})

            # 2. Recopilar datos del formulario
            datos = form.cleaned_data
            # Convertir fechas a string para poder cifrarlas
            datos['fecha_atencion']   = str(datos['fecha_atencion'])
            datos['fecha_nacimiento'] = str(datos['fecha_nacimiento'])

            # 3. Cifrar con AES-256 + RSA-4096
            paquete = cifrar_datos(datos, usuario.llave_publica)

            # 4. Calcular hash del expediente cifrado
            hash_exp = calcular_hash(paquete['datos_cifrados'])

            # 5. Firma digital del colaborador (con la llave desbloqueada)
            firma = firmar(hash_exp, llave_privada_descifrada)

            # 6. Guardar en BD
            Expediente.objects.create(
                creado_por        = usuario,
                fecha_atencion    = datos['fecha_atencion'],
                datos_cifrados    = paquete['datos_cifrados'],
                nonce             = paquete['nonce'],
                tag               = paquete['tag'],
                llave_aes_cifrada = paquete['llave_aes_cifrada'],
                firma_digital     = firma,
                hash_expediente   = hash_exp,
            )

            messages.success(request, '✅ Expediente registrado, cifrado y firmado correctamente.')
            return redirect('expediente:dashboard')
    else:
        form = EntrevistaForm()

    return render(request, 'expediente/formulario.html', {'form': form})