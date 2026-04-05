from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from .forms import LoginForm

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
                # Registrar en bitácora (lo conectamos después)
                return redirect('expediente:dashboard')
            else:
                messages.error(request, 'Tu cuenta está desactivada. Contacta al administrador.')
        else:
            messages.error(request, 'Usuario o contraseña incorrectos.')

    return render(request, 'usuarios/login.html', {'form': form})


def logout_view(request):
    logout(request)
    return redirect('usuarios:login')