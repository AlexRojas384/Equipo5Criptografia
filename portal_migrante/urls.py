from django.urls import path
from . import views

app_name = 'portal_migrante'

urlpatterns = [
    path('',             views.acceso_migrante,       name='acceso'),
    path('mis-datos/',   views.dashboard_migrante,    name='dashboard'),
    path('privacidad/',  views.aviso_privacidad,      name='privacidad'),
    path('arco/',        views.solicitar_arco,        name='solicitar_arco'),
    path('solicitudes/', views.mis_solicitudes,       name='mis_solicitudes'),
    path('salir/',       views.cerrar_sesion_migrante, name='salir'),
]
