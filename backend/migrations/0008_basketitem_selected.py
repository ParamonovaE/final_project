# Generated by Django 5.1.5 on 2025-02-22 19:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0007_basket_basketitem'),
    ]

    operations = [
        migrations.AddField(
            model_name='basketitem',
            name='selected',
            field=models.BooleanField(default=False, verbose_name='Выбран для заказа'),
        ),
    ]
