from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import EntrevistaForm
from .models import Expediente
from cripto.crypto import cifrar_datos, calcular_hash, firmar

@login_required(login_url='usuarios:login')
def dashboard(request):
    context = {
        'usuario': request.user,
        'rol': request.user.rol,
    }
    # Si es Admin, contar solicitudes pendientes para mostrar badge
    if request.user.rol == 'Admin':
        from usuarios.models import SolicitudRol
        context['solicitudes_pendientes'] = SolicitudRol.objects.filter(estado='pendiente').count()
    return render(request, 'expediente/dashboard.html', context)

@login_required(login_url='usuarios:login')
def registrar_migrante(request):
    if request.method == 'POST':
        form = EntrevistaForm(request.POST)
        if form.is_valid():
            usuario = request.user

            # Verificar que el usuario tiene llaves RSA
            if not usuario.llave_publica or not usuario.llave_privada:
                messages.error(request, 'Tu usuario no tiene llaves RSA. Contacta al administrador.')
                return redirect('expediente:dashboard')

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