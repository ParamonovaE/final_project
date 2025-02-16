import django_filters
from .models import ProductInfo

class ProductInfoFilter(django_filters.FilterSet):
    product_name = django_filters.CharFilter(field_name='product__name', lookup_expr='icontains', label="Название товара")
    shop_name = django_filters.CharFilter(field_name='shop__name', lookup_expr='icontains', label="Поставщик")
    min_price = django_filters.NumberFilter(field_name='price', lookup_expr='gte', label="Минимальная цена")
    max_price = django_filters.NumberFilter(field_name='price', lookup_expr='lte', label="Максимальная цена")
    category = django_filters.NumberFilter(field_name='product__categories__id', lookup_expr='exact', label="Категория")

    class Meta:
        model = ProductInfo
        fields = ['product_name', 'shop_name', 'min_price', 'max_price', 'category']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # фильтры по параметрам динамически
        for key, value in self.data.items():
            if key.startswith('param-'):
                self.filters[key] = django_filters.CharFilter(
                    field_name='parameters__value',
                    lookup_expr='icontains',
                    label=key.replace('param-', '')
                )