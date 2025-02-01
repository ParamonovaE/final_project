from django.db import models

class Shop(models.Model):
    name = models.CharField(max_length=100, unique=True, verbose_name="Название магазина")
    url = models.URLField(max_length=300, unique=True, help_text="Введите полный URL, включая https://")

class Category(models.Model):
    name = models.CharField(max_length=100, unique=True, verbose_name="Название категории")
    shops = models.ManyToManyField(Shop, related_name='categories')

class Product(models.Model):
    name = models.CharField(max_length=100, unique=True, verbose_name="Название продукта")
    categories = models.ManyToManyField(Category, related_name='products')

class ProductInfo(models.Model):
    product = models.ForeignKey(Product, related_name="product_infos", on_delete=models.CASCADE, verbose_name="Название продукта")
    shop = models.ForeignKey(Shop, related_name="shop_infos", on_delete=models.CASCADE, verbose_name="Название магазина")
    quantity = models.PositiveIntegerField(default=0, verbose_name="Количество")
    price = models.DecimalField(max_digits=10, decimal_places=2, verbose_name="Цена")
    price_rrc = models.DecimalField(max_digits=10, decimal_places=2, verbose_name="Рекомендуемая цена")

class Parameter(models.Model):
    name = models.CharField(max_length=100, unique=True, verbose_name='Название параметра')

class ProductParameter(models.Model):
    product_info = models.ForeignKey(ProductInfo, related_name="product_infos", on_delete=models.CASCADE, verbose_name='Информация о продукте')
    parameter = models.ForeignKey(Parameter, related_name="product_parameters", on_delete=models.CASCADE, verbose_name="Параметр")
    value = models.CharField(max_length=255, verbose_name="Значение параметра")

