# Generated by Django 5.1.5 on 2025-02-26 21:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0011_remove_contact_building_remove_contact_structure'),
    ]

    operations = [
        migrations.AddField(
            model_name='shop',
            name='is_active',
            field=models.BooleanField(default=True, verbose_name='Статус приема заказов'),
        ),
    ]
