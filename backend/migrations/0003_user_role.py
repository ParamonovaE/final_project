# Generated by Django 5.1.5 on 2025-02-06 18:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0002_contact_order_orderitem_alter_category_options_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='role',
            field=models.CharField(choices=[('customer', 'Покупатель'), ('shop', 'Магазин')], default='customer', max_length=10, verbose_name='Роль'),
        ),
    ]
