from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('expediente', '0004_expediente_etiquetas_oposicion'),
    ]

    operations = [
        migrations.AddField(
            model_name='expediente',
            name='pre_aprobado',
            field=models.BooleanField(default=False),
        ),
    ]
