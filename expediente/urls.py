from django.urls import path
from . import views

app_name = 'expediente'

urlpatterns = [
    path('dashboard/',              views.dashboard,              name='dashboard'),
    path('registrar/',              views.registrar_migrante,     name='registrar'),

    path('expedientes/',            views.lista_expedientes,      name='lista_expedientes'),
    path('expedientes/verificar/',  views.verificar_expedientes,  name='verificar_expedientes'),
    path('expedientes/editar/<int:pk>/', views.editar_expediente, name='editar_expediente'),
    path('expedientes/eliminar/<int:pk>/', views.eliminar_expediente, name='eliminar_expediente'),
]