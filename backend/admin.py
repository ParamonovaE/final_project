from django.contrib import admin
from .models import Shop, Product, Category, ProductInfo, Parameter, ProductParameter

# Register your models here.
admin.site.register(Shop)
admin.site.register(Product)
admin.site.register(Category)
admin.site.register(ProductInfo)
admin.site.register(Parameter)
admin.site.register(ProductParameter)