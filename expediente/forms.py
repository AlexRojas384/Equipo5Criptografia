from django import forms
from .paises import PAISES  # lo definimos abajo

GENERO_CHOICES = [
    ('', 'Selecciona...'),
    ('Femenino',   'Femenino'),
    ('Masculino',  'Masculino'),
    ('No binario', 'No binario'),
    ('LGBTIQ+',    'LGBTIQ+'),
]

ESTADO_CIVIL_CHOICES = [
    ('', 'Selecciona...'),
    ('Soltero/a',       'Soltero/a'),
    ('Casado/a',        'Casado/a'),
    ('Unión libre',     'Unión libre'),
    ('Divorciado/a',    'Divorciado/a'),
    ('Viudo/a',         'Viudo/a'),
    ('Separado/a',      'Separado/a'),
]

EDAD_CHOICES = [('', 'Selecciona...')] + [(str(i), str(i)) for i in range(0, 121)]

GRUPO_POBLACION_CHOICES = [
    ('', 'Selecciona...'),
    ('Adulto (18-59 años)',              'Adulto (18-59 años)'),
    ('Adulto mayor (+60 años)',          'Adulto mayor (+60 años)'),
    ('Niña acompañada',                 'Niña acompañada'),
    ('Niño acompañado',                 'Niño acompañado'),
    ('Adolescente hombre acompañado',   'Adolescente hombre acompañado'),
    ('Adolescente mujer acompañada',    'Adolescente mujer acompañada'),
    ('NNA No acompañado',               'NNA No acompañado'),
]


class EntrevistaForm(forms.Form):
    fecha_atencion    = forms.DateField(
        label='1. Fecha de atención',
        widget=forms.DateInput(attrs={'type': 'date'})
    )
    nombre_pila       = forms.CharField(
        label='2. Nombre de pila (sin apellidos)',
        max_length=100
    )
    primer_apellido   = forms.CharField(
        label='3. Primer apellido',
        max_length=100
    )
    segundo_apellido  = forms.CharField(
        label='4. Segundo apellido',
        max_length=100,
        help_text='En caso de no tener, poner "X"'
    )
    telefono          = forms.CharField(
        label='5. Número telefónico de contacto',
        max_length=20
    )
    genero            = forms.ChoiceField(
        label='6. Género',
        choices=GENERO_CHOICES
    )
    pais_origen       = forms.ChoiceField(
        label='7. País de origen',
        choices=PAISES
    )
    departamento      = forms.CharField(
        label='8. Departamento / Estado',
        max_length=100
    )
    estado_civil      = forms.ChoiceField(
        label='9. Estado Civil',
        choices=ESTADO_CIVIL_CHOICES
    )
    fecha_nacimiento  = forms.DateField(
        label='10. Fecha de nacimiento',
        widget=forms.DateInput(attrs={'type': 'date'})
    )
    edad              = forms.ChoiceField(
        label='11. Edad',
        choices=EDAD_CHOICES
    )
    grupo_poblacion   = forms.ChoiceField(
        label='12. ¿A qué grupo de población pertenece?',
        choices=GRUPO_POBLACION_CHOICES
    )