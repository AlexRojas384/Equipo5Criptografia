from django.urls import path
from . import views

app_name = 'expediente'

urlpatterns = [
    path('dashboard/',              views.dashboard,              name='dashboard'),
    path('registrar/',              views.registrar_migrante,     name='registrar'),
    path('desbloquear/',            views.desbloquear_sesion,     name='desbloquear_sesion'),
    path('expedientes/',            views.lista_expedientes,      name='lista_expedientes'),
    path('expedientes/verificar/',  views.verificar_expedientes,  name='verificar_expedientes'),
]