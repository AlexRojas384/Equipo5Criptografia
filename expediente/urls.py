from django.urls import path
from . import views

app_name = 'expediente'

urlpatterns = [
    path('dashboard/',          views.dashboard,          name='dashboard'),
    path('registrar/',          views.registrar_migrante, name='registrar'),
]