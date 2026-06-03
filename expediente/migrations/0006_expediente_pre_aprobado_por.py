from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('expediente', '0005_expediente_pre_aprobado'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='expediente',
            name='pre_aprobado_por',
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='expedientes_pre_aprobados',
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
