from django.urls import path
from . import views

app_name = 'expediente'

urlpatterns = [
    path('dashboard/',              views.dashboard,              name='dashboard'),
    path('registrar/',              views.registrar_migrante,     name='registrar'),

    path('expedientes/',            views.lista_expedientes,      name='lista_expedientes'),
    path('expedientes/verificar/',  views.verificar_expedientes,  name='verificar_expedientes'),
    path('expedientes/pre-aprobar/<int:pk>/', views.pre_aprobar_expediente, name='pre_aprobar_expediente'),
    path('expedientes/editar/<int:pk>/', views.editar_expediente, name='editar_expediente'),
    path('expedientes/eliminar/<int:pk>/', views.eliminar_expediente, name='eliminar_expediente'),
    
    # ─── ARCO ─────────────────────────────────────────────────────────────
    path('arco/',                    views.lista_solicitudes_arco,   name='lista_arco'),
    path('arco/responder/<int:pk>/', views.responder_solicitud_arco, name='responder_arco'),
    path('arco/firmar/<int:pk>/',    views.firmar_solicitud_arco,    name='firmar_arco'),
    path('arco/ejecutar/<int:pk>/',  views.ejecutar_cancelacion_arco_admin, name='ejecutar_arco_admin'),
]