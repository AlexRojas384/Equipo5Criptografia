from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import EntrevistaForm
from .models import Expediente
from cripto.crypto import cifrar_datos, calcular_hash, firmar
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

            # 1. Recopilar datos del formulario
            datos = form.cleaned_data
            # Convertir fechas a string para poder cifrarlas
            datos['fecha_atencion']   = str(datos['fecha_atencion'])
            datos['fecha_nacimiento'] = str(datos['fecha_nacimiento'])

            # 2. Cifrar con AES-256 + RSA-4096
            paquete = cifrar_datos(datos, usuario.llave_publica)

            # 3. Calcular hash del expediente cifrado
            hash_exp = calcular_hash(paquete['datos_cifrados'])

            # 4. Firma digital del colaborador
            firma = firmar(hash_exp, usuario.llave_privada)

            # 5. Guardar en BD
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

            messages.success(request, 'Expediente registrado y cifrado correctamente.')
            return redirect('expediente:dashboard')
    else:
        form = EntrevistaForm()

    return render(request, 'expediente/formulario.html', {'form': form})