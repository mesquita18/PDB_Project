# Generated by Django 5.1.3 on 2025-01-23 18:12

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rest_api', '0005_nota'),
    ]

    operations = [
        migrations.AlterField(
            model_name='nota',
            name='aluno',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='notas', to='rest_api.aluno'),
        ),
        migrations.AlterField(
            model_name='nota',
            name='final',
            field=models.DecimalField(blank=True, decimal_places=2, default=0.0, max_digits=5, null=True),
        ),
        migrations.AlterField(
            model_name='nota',
            name='nota1',
            field=models.DecimalField(blank=True, decimal_places=2, default=0.0, max_digits=5, null=True),
        ),
        migrations.AlterField(
            model_name='nota',
            name='nota2',
            field=models.DecimalField(blank=True, decimal_places=2, default=0.0, max_digits=5, null=True),
        ),
        migrations.AlterField(
            model_name='nota',
            name='nota3',
            field=models.DecimalField(blank=True, decimal_places=2, default=0.0, max_digits=5, null=True),
        ),
        migrations.AlterField(
            model_name='nota',
            name='turma',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='notas', to='rest_api.turma'),
        ),
    ]
