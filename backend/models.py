from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager

class UserManager(BaseUserManager):
    use_in_migrations = True

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email обязателен!")
        email = self.normalize_email(email)
        extra_fields.setdefault("is_active", False)  # по умолчанию пользователь не активен (ждёт подтверждения)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, password, **extra_fields)

class User(AbstractUser):
    ROLE_CHOICES = (
        ('customer', 'Покупатель'),
        ('shop', 'Магазин'),
    )
    username = None
    email = models.EmailField(unique=True, verbose_name="Email")
    is_active = models.BooleanField(default=False, verbose_name="Подтверждён")  # подтверждение регистрации
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='customer', verbose_name="Роль")

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = UserManager()

    class Meta:
        verbose_name = 'Пользователь'
        verbose_name_plural = "Список пользователей"

    def __str__(self):
        return f'{self.first_name} {self.last_name}'

class Shop(models.Model):
    objects = models.manager.Manager()
    name = models.CharField(max_length=100, unique=True, verbose_name="Название магазина")
    url = models.URLField(max_length=300, unique=True, help_text="Введите полный URL, включая https://", null=True, blank=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="shop", verbose_name="Пользователь", null=True, blank=True)
    is_active = models.BooleanField(default=True, verbose_name="Статус приема заказов")

    class Meta:
        verbose_name = 'Магазин'
        verbose_name_plural = "Список магазинов"

    def __str__(self):
        return self.name

class Category(models.Model):
    objects = models.manager.Manager()
    name = models.CharField(max_length=100, verbose_name="Название категории")
    shops = models.ManyToManyField(Shop, related_name='categories')

    class Meta:
        verbose_name = 'Категория'
        verbose_name_plural = "Список категорий"

    def __str__(self):
        return self.name

class Product(models.Model):
    objects = models.manager.Manager()
    name = models.CharField(max_length=100, verbose_name="Название продукта")
    categories = models.ManyToManyField(Category, related_name='products')

    class Meta:
        verbose_name = 'Продукт'
        verbose_name_plural = "Список продуктов"

    def __str__(self):
        return self.name

class ProductInfo(models.Model):
    objects = models.manager.Manager()
    product = models.ForeignKey(Product, related_name="product_infos", on_delete=models.CASCADE, verbose_name="Название продукта")
    external_id = models.PositiveIntegerField(default=0, verbose_name='Внешний ID')
    shop = models.ForeignKey(Shop, related_name="shop_infos", on_delete=models.CASCADE, verbose_name="Название магазина")
    quantity = models.PositiveIntegerField(default=0, verbose_name="Количество")
    price = models.DecimalField(max_digits=10, decimal_places=2, verbose_name="Цена")
    price_rrc = models.DecimalField(max_digits=10, decimal_places=2, verbose_name="Рекомендуемая цена")

    class Meta:
        verbose_name = 'Информация о продукте'
        verbose_name_plural = "Информационный список о продуктах"
        constraints = [
            models.UniqueConstraint(fields=['product', 'shop', 'external_id'], name='unique_product_info'),
        ]

    def __str__(self):
        return f"{self.product.name} в {self.shop.name} - {self.price} руб."


class Parameter(models.Model):
    objects = models.manager.Manager()
    name = models.CharField(max_length=100, unique=True, verbose_name='Название параметра')

    class Meta:
        verbose_name = 'Имя параметра'
        verbose_name_plural = "Список имен параметров"

    def __str__(self):
        return self.name

class ProductParameter(models.Model):
    objects = models.manager.Manager()
    product_info = models.ForeignKey(ProductInfo, related_name="parameters", on_delete=models.CASCADE, verbose_name='Информация о продукте')
    parameter = models.ForeignKey(Parameter, related_name="product_parameters", on_delete=models.CASCADE, verbose_name="Параметр")
    value = models.CharField(max_length=255, verbose_name="Значение параметра")

    class Meta:
        verbose_name = 'Параметр'
        verbose_name_plural = "Список параметров"
        constraints = [
            models.UniqueConstraint(fields=['product_info', 'parameter'], name='unique_product_parameter'),
        ]

    def __str__(self):
        return f"{self.parameter.name}: {self.product_info.product.name} {self.value} "

class Basket(models.Model):
    objects = models.manager.Manager()
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='basket')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Корзина {self.id} - {self.user.first_name} {self.user.last_name}"

class BasketItem(models.Model):
    objects = models.manager.Manager()
    basket = models.ForeignKey(Basket, on_delete=models.CASCADE, related_name='items')
    product_info = models.ForeignKey(ProductInfo, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    selected = models.BooleanField(default=False, verbose_name='Выбран для заказа')

    def __str__(self):
        return f"{self.quantity} x {self.product_info.product.name}"

    def total_price(self):
        return self.quantity * self.product_info.price

class Contact(models.Model):
    objects = models.manager.Manager()
    user = models.ForeignKey(User, verbose_name='Пользователь', related_name='contacts', blank=True, on_delete=models.CASCADE)
    city = models.CharField(max_length=50, verbose_name='Город')
    street = models.CharField(max_length=100, verbose_name='Улица')
    house = models.CharField(max_length=15, verbose_name='Дом', blank=True)
    apartment = models.CharField(max_length=15, verbose_name='Квартира', blank=True)
    phone = models.CharField(max_length=20, verbose_name='Телефон')

    class Meta:
        verbose_name = 'Контакты пользователя'
        verbose_name_plural = "Список контактов пользователя"

    def __str__(self):
        return f"{self.city}, {self.street}, {self.house}, {self.phone}"

class Order(models.Model):
    STATUS_CHOICES = [
        ('new', 'Новый'),
        ('confirmed', 'Подтвержден'),
        ('assembled', 'Собран'),
        ('sent', 'Отправлен'),
        ('delivered', 'Доставлен'),
        ('canceled', 'Отменён'),
    ]
    objects = models.manager.Manager()
    user = models.ForeignKey(User, related_name='orders', on_delete=models.CASCADE, verbose_name='Пользователь')
    dt = models.DateTimeField(auto_now_add=True, verbose_name='Дата заказа')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new', verbose_name='Статус заказа')
    contact = models.ForeignKey(Contact, verbose_name='Адрес', blank=True, null=True, on_delete=models.CASCADE)

    class Meta:
        verbose_name = 'Заказ'
        verbose_name_plural = "Список заказ"
        ordering = ('dt',)

    def __str__(self):
        return f"Заказ {self.id} - {self.user.first_name} {self.user.last_name} ({self.status})"

class OrderItem(models.Model):
    objects = models.manager.Manager()
    order = models.ForeignKey(Order, related_name='items', on_delete=models.CASCADE, verbose_name='Заказ')
    product_info = models.ForeignKey(ProductInfo, related_name='order_items', on_delete=models.CASCADE, verbose_name='Информация о продукте')
    quantity = models.PositiveIntegerField(default=1, verbose_name='Количество')

    class Meta:
        verbose_name = 'Заказанная позиция'
        verbose_name_plural = "Список заказанных позиций"
        constraints = [
            models.UniqueConstraint(fields=['order_id', 'product_info'], name='unique_order_item'),
        ]

    def __str__(self):
        return f"{self.product_info.product.name} x{self.quantity} для заказа {self.order.id}"



