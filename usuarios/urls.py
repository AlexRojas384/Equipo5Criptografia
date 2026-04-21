from django.urls import path
from . import views

app_name = 'usuarios'

urlpatterns = [
    path('login/',                        views.login_view,          name='login'),
    path('logout/',                       views.logout_view,         name='logout'),
    path('admin-panel/',                  views.admin_panel,         name='admin_panel'),
    path('cambiar-rol/<int:pk>/',         views.cambiar_rol,         name='cambiar_rol'),
    path('toggle-permiso/',               views.toggle_permiso,      name='toggle_permiso'),
    path('toggle-activo/<int:pk>/',       views.toggle_activo,       name='toggle_activo'),
    path('solicitar-rol/',                views.solicitar_rol,       name='solicitar_rol'),
    path('responder-solicitud/<int:pk>/', views.responder_solicitud, name='responder_solicitud'),
    path('crear-usuario/',                views.crear_usuario,       name='crear_usuario'),
    path('regenerar-identidad/<int:pk>/', views.regenerar_identidad, name='regenerar_identidad'),
    path('revocar-certificado/<int:pk>/', views.revocar_certificado, name='revocar_certificado'),
    path('cambiar-password/',             views.cambiar_password,    name='cambiar_password'),
]