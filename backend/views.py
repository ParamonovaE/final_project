import smtplib
from django.contrib.auth import login
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.utils.encoding import force_str, force_bytes
from rest_framework.authentication import TokenAuthentication
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.permissions import IsAuthenticated
from orders.settings import DEFAULT_FROM_EMAIL
from . import serializers
from .filters import ProductInfoFilter
from .serializers import RegisterSerializer, LoginSerializer, ProductInfoSerializer, CategorySerializer, \
    BasketSerializer, BasketItemSerializer, CreateOrderSerializer, OrderSerializer, ContactSerializer, \
    OrderItemSerializer
from backend.models import User, Category, Basket, BasketItem, Order, OrderItem, Contact
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.core.cache import cache
from rest_framework.authtoken.models import Token
from django.conf import settings
from django.contrib.auth.decorators import login_required
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import yaml
from .models import Product, ProductInfo, Parameter, ProductParameter, Shop
from .permissions import IsSupplier
from sentence_transformers import SentenceTransformer
import torch
import pandas as pd

@login_required
def main_depends_role(request):
    return render(request, "main_depends_role.html", {"user": request.user})

# регистрация
class RegisterView(APIView):
    def get(self, request):  # если GET-запрос – рендерим HTML-страницу
        return render(request, "register.html")

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)

        if serializer.is_valid():
            try:
                serializer.save()
                return Response({'message': 'Письмо с подтверждением отправлено.'}, status=status.HTTP_201_CREATED)
            except smtplib.SMTPDataError:
                return Response({"email": ["Такого email не существует."]}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# подтверждение email
class VerifyEmailView(APIView):
    def get(self, request, uid, token):
        try:
            email = force_str(urlsafe_base64_decode(uid)) # декодируем email

            # проверяем, есть ли уже подтверждённый пользователь
            if User.objects.filter(email=email).exists():
                return render(request, "verify_success.html")

            # проверяем, есть ли токен в кэше
            cached_token = cache.get(f"email_verify_{uid}")
            if cached_token is None:
                return Response({"error": "Срок действия токена истёк."}, status=status.HTTP_400_BAD_REQUEST)

            temp_user = cache.get(f"temp_user_{email}")
            if not temp_user:
                return Response({"error": "Данные пользователя не найдены."}, status=status.HTTP_400_BAD_REQUEST)

            fake_user = User(email=email)
            if default_token_generator.check_token(fake_user, token):
                user = User.objects.create(
                    email=email,
                    first_name=temp_user["first_name"],
                    last_name=temp_user["last_name"],
                    role=temp_user["role"]
                )
                user.set_password(temp_user["password"])
                user.is_active = True
                user.save()

                # автоматически авторизуем пользователя после подтверждения email
                login(request, user)

                # удаляем токен из кэша после подтверждения
                cache.delete(f"email_verify_{uid}")
                cache.delete(f"temp_user_{email}")

                return render(request, "verify_success.html")

            return Response({"error": "Неверный токен."}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": "Ошибка при обработке токена."}, status=status.HTTP_400_BAD_REQUEST)

# логин
class LoginAccount(APIView):
    def get(self, request): # если GET-запрос – рендерим HTML-страницу
        return render(request, "login.html")

    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)

        if not serializer.is_valid():
            return Response({'status': False, 'error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data["user"]
        token, _ = Token.objects.get_or_create(user=user)

        login(request, user)

        return Response({'status': True, 'token': token.key, 'role': user.role}, status=status.HTTP_200_OK)

# сброс пароля
class ResetPasswordView(APIView):
    def get(self, request):
        return render(request, "password_reset.html")

    def post(self, request):
        email = request.data.get("email")

        if not email:
            return Response({"error": "Введите email"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"error": "Пользователь с таким email не найден"}, status=status.HTTP_404_NOT_FOUND)

        token = default_token_generator.make_token(user)  # генерируем токен

        uid = urlsafe_base64_encode(force_bytes(user.email))

        cache.set(f"password_reset_{uid}", token, timeout=600)  # сохраняем токен в кэше на 10 минут

        reset_link = f"http://127.0.0.1:8000/password-reset/{uid}/{token}/"

        # отправляем письмо
        send_mail(
            "Сброс пароля",
            f"Перейдите по ссылке для сброса пароля: {reset_link}",
            settings.EMAIL_HOST_USER,
            [user.email],
            fail_silently=False,
        )

        return Response({"message": "Письмо для сброса пароля отправлено."}, status=status.HTTP_200_OK)

# подтверждение нового пароля
class ResetPasswordConfirmView(APIView):
    def get(self, request, uid, token):
        return render(request, "password_reset_confirm.html", {"uid": uid, "token": token})

    # проверяет токен и обновляет пароль в базе
    def post(self, request, uid, token):
        new_password = request.data.get("password")

        if not new_password:
            return Response({"error": "Введите новый пароль"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            email = force_str(urlsafe_base64_decode(uid))
        except Exception:
            return Response({"error": "Неверный токен"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"error": "Пользователь не найден"}, status=status.HTTP_404_NOT_FOUND)

        cached_token = cache.get(f"password_reset_{uid}")
        if not cached_token or cached_token != token:
            return Response({"error": "Недействительный или устаревший токен"}, status=status.HTTP_400_BAD_REQUEST)

        user.password = make_password(new_password)
        user.save()

        cache.delete(f"password_reset_{uid}")

        return Response({"message": "Пароль успешно изменён. Теперь вы можете войти."}, status=status.HTTP_200_OK)

@login_required(login_url="/login/")
def shop_products_view(request):
    try:
        shop = Shop.objects.get(user=request.user)
    except Shop.DoesNotExist:
        return render(request, 'shop_products.html', {'error': 'Вы не являетесь поставщиком'})

    return render(request, "shop-products.html", {'shop': shop, "user": request.user})

# импорт, получение и обновление товаров магазина
class ShopProductView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated, IsSupplier]
    parser_classes = [JSONParser, MultiPartParser, FormParser]  # поддержка загрузки файлов

    # получение списка товаров магазина
    def get(self, request, *args, **kwargs):
        shop = Shop.objects.filter(user=request.user).first()
        if not shop:
            return Response({"error": "Магазин не найден"}, status=status.HTTP_404_NOT_FOUND)

        products = ProductInfo.objects.filter(shop=shop).prefetch_related('parameters')
        # product_data = []
        #
        # for product in products:
        #     parameters = [
        #         {"name": param.parameter.name, "value": param.value}
        #         for param in product.parameters.all()
        #     ]
        #     shop_name = product.shop.name if product.shop else "Не указано"
        #     product_data.append({
        #         "id": product.id,
        #         "name": product.product.name,
        #         "price": product.price,
        #         "quantity": product.quantity,
        #         "parameters": parameters,  # передаём параметры как массив объектов
        #         "shop": shop_name
        #     })
        product_data = ProductInfoSerializer(products, many=True)
        return Response(product_data.data, status=status.HTTP_200_OK)

    # загрузка товаров из файла
    def post(self, request, *args, **kwargs):
        print("Файл пришёл:", request.FILES)
        file = request.FILES.get("file")  # получаем загруженный файл
        if not file:
            return Response({"error": "Файл не найден"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            data = yaml.safe_load(file.read())  # читаем YAML-файл
            print("Файл прочитан:", data)
        except Exception as e:
            return Response({"error": "Ошибка обработки файла"}, status=status.HTTP_400_BAD_REQUEST)

        shop, _ = Shop.objects.get_or_create(name=data["shop"], defaults={"user": request.user})

        for category in data["categories"]:
            category_obj, _ = Category.objects.get_or_create(id=category["id"], defaults={"name": category["name"]})
            category_obj.shops.add(shop)  # привязываем категорию к магазину

        for item in data["goods"]:
            product, _ = Product.objects.get_or_create(name=item["name"])
            category_obj = Category.objects.get(id=item["category"])
            product.categories.add(category_obj)  # привязываем продукт к категории

            product_info, _ = ProductInfo.objects.update_or_create(
                product=product,
                shop=shop,
                external_id=item["id"],
                defaults={
                    "price": item["price"],
                    "price_rrc": item["price_rrc"],
                    "quantity": item["quantity"],
                }
            )

            for name, value in item["parameters"].items():
                parameter, _ = Parameter.objects.get_or_create(name=name)
                ProductParameter.objects.update_or_create(
                    product_info=product_info, parameter=parameter, defaults={"value": value}
                )

        return Response({"status": "Товары успешно загружены"}, status=status.HTTP_201_CREATED)

    # обновление информации о товаре
    def put(self, request, product_id, *args, **kwargs):
        try:
            product = ProductInfo.objects.get(id=product_id, shop__user=request.user)
        except ProductInfo.DoesNotExist:
            return Response({"error": "Товар не найден"}, status=status.HTTP_404_NOT_FOUND)

        # обновляем цену и количество
        product.price = request.data.get("price", product.price)
        product.quantity = request.data.get("quantity", product.quantity)
        product.save()

        # обновляем характеристики
        parameters = request.data.get("parameters", [])
        for param_data in parameters:
            try:
                param = ProductParameter.objects.get(id=param_data["id"], product_info=product)
                param.value = param_data["value"]
                param.save()
            except ProductParameter.DoesNotExist:
                continue

        return Response({"status": "Товар успешно обновлён"}, status=status.HTTP_200_OK)

@login_required(login_url="/login/")
def customer_products_view(request):
    products = ProductInfo.objects.select_related('product', 'shop').prefetch_related('parameters').all()
    return render(request, "customer-products.html", {"products": products})

class CategoryListView(APIView):
    def get(self, request):
        categories = Category.objects.all()
        serializer = CategorySerializer(categories, many=True)
        return Response(serializer.data, status=200)

class CategoryParametersView(APIView):
    def get(self, request, category_id):
        try:
            category = Category.objects.get(id=category_id)
        except Category.DoesNotExist:
            return Response({"error": "Категория не найдена"}, status=404)

        # уникальные параметры для категории
        parameters = Parameter.objects.filter(product_parameters__product_info__product__categories=category).distinct()
        parameter_data = [{"id": param.id, "name": param.name} for param in parameters]

        return Response(parameter_data, status=200)

# получение всех товаров для покупателей
class CustomerProductsView(APIView):
    def get(self, request):
        products = ProductInfo.objects.select_related('product', 'shop').prefetch_related('parameters').filter(shop__is_active=True)
        filterset = ProductInfoFilter(request.query_params, queryset=products)
        filtered_products = filterset.qs
        serializer = ProductInfoSerializer(filtered_products, many=True)
        return Response(serializer.data, status=200)

# для отображения корзины пользователя
@login_required(login_url="/login/")
def basket_view(request):
    basket, created = Basket.objects.get_or_create(user=request.user)
    basket_items = BasketItem.objects.filter(basket=basket).select_related(
        "product_info__product", "product_info__shop"
    )
    is_basket_empty = not basket_items.exists()
    contacts = Contact.objects.filter(user=request.user)

    for item in basket_items:
        item.is_shop_active_orders = item.product_info.shop.is_active

    context = {
        "basket": basket,
        "basket_items": basket_items,
        "is_basket_empty": is_basket_empty,
        'contacts': contacts,
    }

    return render(request, "basket.html", context)

class BasketView(APIView):
    # получить корзину пользователя
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Требуется авторизация'}, status=403)

        try:
            basket = Basket.objects.get(user=request.user)
            print(basket)
        except Basket.DoesNotExist:
            return Response({'Status': True, 'Message': 'Корзина пуста'}, status=status.HTTP_200_OK)

        serializer = BasketSerializer(basket)
        return Response(serializer.data)

    # добавить товар в корзину
    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Требуется авторизация'}, status=403)

        try:
            data = request.data
            product_info_id = data.get('product_info_id')
            quantity = int(data.get('quantity', 1))
        except (AttributeError, ValueError, KeyError) as e:
            return JsonResponse({'Status': False, 'Error': 'Некорректные данные'}, status=400)

        if not product_info_id:
            return JsonResponse({'Status': False, 'Error': 'Не указан товар'}, status=400)

        Basket.objects.filter(user=None).delete()

        basket, created = Basket.objects.get_or_create(user_id=request.user.id)
        print("Корзина пользователя:", basket)

        if BasketItem.objects.filter(basket=basket, product_info_id=product_info_id).exists():
            return JsonResponse({'Status': True, 'Message': 'Этот товар уже в корзине'}, status=200)

        # проверяем, есть ли уже такой товар в корзине
        try:
            basket_item = BasketItem.objects.get_or_create(
                basket=basket,
                product_info_id=product_info_id,
                quantity=quantity
            )

            print("Товар добавлен в корзину:", basket_item)  # выводим добавленный товар

            serializer = BasketSerializer(basket)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            return JsonResponse({'Status': False, 'Error': str(e)}, status=400)

    # обновить количество товара в корзине
    def patch(self, request, item_id, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Требуется авторизация'}, status=403)

        try:
            basket_item = BasketItem.objects.get(id=item_id, basket__user=request.user)
        except BasketItem.DoesNotExist:
            return JsonResponse({'Status': False, 'Error': 'Товар не найден в корзине'}, status=404)

        # обновляем данные
        try:
            data = request.data
            serializer = BasketItemSerializer(basket_item, data=data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        except serializers.ValidationError as e:
            return JsonResponse({'Status': False, 'Error': str(e)}, status=400)
        except Exception as e:
            return JsonResponse({'Status': False, 'Error': str(e)}, status=400)

    # удалить товар из корзины
    def delete(self, request, item_id, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Требуется авторизация'}, status=403)

        try:
            basket_item = BasketItem.objects.get(id=item_id, basket__user=request.user)
        except BasketItem.DoesNotExist:
            return JsonResponse({'Status': False, 'Error': 'Товар не найден в корзине'}, status=404)

        # удаляем товар из корзины
        try:
            basket_item.delete()
            return JsonResponse({'Status': True, 'Message': 'Товар удален из корзины'}, status=200)
        except Exception as e:
            return JsonResponse({'Status': False, 'Error': str(e)}, status=400)
class ContactView(APIView):
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Требуется авторизация'}, status=status.HTTP_403_FORBIDDEN)

        contacts = Contact.objects.filter(user=request.user)
        serializer = ContactSerializer(contacts, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Требуется авторизация'}, status=status.HTTP_403_FORBIDDEN)

        serializer = ContactSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response({'Status': True, 'Message': 'Контакт успешно добавлен'}, status=status.HTTP_201_CREATED)
        return Response({'Status': False, 'Error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, contact_id, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Требуется авторизация'}, status=status.HTTP_403_FORBIDDEN)

        try:
            contact = Contact.objects.get(id=contact_id, user=request.user)
        except Contact.DoesNotExist:
            return Response({'Status': False, 'Error': 'Контакт не найден'}, status=404)

        contact.delete()
        return Response({'Status': True, 'Message': 'Контакт удален'}, status=200)

class OrderView(APIView):
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Требуется авторизация'}, status=status.HTTP_403_FORBIDDEN)

        orders = Order.objects.filter(user=request.user).order_by('dt')
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)

    # создать заказ из выбранных товаров с адресом доставки
    def post(self, request, *args, **kwargs):
        print("Данные запроса:", request.data)
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Требуется авторизация'}, status=status.HTTP_403_FORBIDDEN)

        serializer = CreateOrderSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            order = serializer.save()
            print(f"Заказ {order.id} создан. Отправка email на {request.user.email}.")
            self.send_confirmation_email(request.user.email, order.id)
            self.send_invoice_email(order)
            return Response({'Status': True, 'Message': 'Заказ успешно оформлен', 'OrderId': order.id}, status=status.HTTP_201_CREATED)
        print("Ошибки валидации:", serializer.errors)
        return Response({'Status': False, 'Error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def send_confirmation_email(self, email, order_id):
        subject = 'Подтверждение заказа'
        message = f'Ваш заказ №{order_id} успешно оформлен. Спасибо за покупку!'
        from_email = DEFAULT_FROM_EMAIL
        recipient_list = [email]

        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

    # отправляет email каждому поставщику с его товарами в заказе
    def send_invoice_email(self, order):
        # группируем товары по поставщикам
        shops = {}
        for item in order.items.all():
            shop = item.product_info.shop
            if shop not in shops:
                shops[shop] = []
            shops[shop].append(item)

        # отправка email каждому поставщику
        for shop, items in shops.items():
            if not shop.user.email:
                continue

            subject = f"Новый заказ №{order.id}"
            message = f"Здравствуйте, {shop.name}!\n\nВам поступил новый заказ. Детали:\n\n"

            total_order_price = 0

            for item in items:
                total_price = item.quantity * item.product_info.price
                total_order_price += total_price
                message += f"- {item.product_info.product.name} (x{item.quantity}): {item.product_info.price} руб. за шт. Всего: {total_price} руб.\n"

            message += f"\nОбщая сумма заказа: {total_order_price} руб.\n"
            message += f"\nАдрес доставки: {order.contact.city}, {order.contact.street}, {order.contact.house}\n"
            message += f"Телефон клиента: {order.contact.phone}\n\n"

            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [shop.user.email],
                fail_silently=False,
            )

@login_required(login_url="/login/")
def order_history_view(request):
    orders = Order.objects.filter(user=request.user).order_by('dt')
    return render(request, 'order.html', {'orders': orders})

@login_required(login_url="/login/")
def order_detail_view(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user)
    items = OrderItem.objects.filter(order=order).select_related('product_info__shop')  # товары с информацией о поставщике

    # Вычисляем общую сумму заказа
    total_price = sum(item.quantity * item.product_info.price for item in items)

    context = {
        'order': order,
        'items': items,
        'total_price': total_price,
    }
    return render(request, 'order_details.html', context)

@login_required(login_url="/login/")
def shop_order_history_view(request):
    try:
        shop = Shop.objects.get(user=request.user)  # получаем магазин текущего пользователя
    except Shop.DoesNotExist:
        return render(request, 'shop_orders.html', {'error': 'Вы не являетесь поставщиком'})
    status_filter = request.GET.get('status')

    # получаем заказы, содержащие товары из прайса поставщика
    orders = Order.objects.filter(items__product_info__shop=shop).distinct().order_by('dt')
    if status_filter:
        orders = orders.filter(status=status_filter)
    orders_total_price = []
    for order in orders:
        total_price = 0
        for item in order.items.filter(product_info__shop=shop):
            total_price += item.quantity * item.product_info.price
        orders_total_price.append({
            'order': order,
            'total_price': total_price,
        })

    return render(request, 'shop_orders.html', {'orders': orders_total_price, 'Order': Order})

@login_required(login_url="/login/")
def shop_order_detail_view(request, order_id):
    try:
        shop = Shop.objects.get(user=request.user)  # получаем магазин текущего пользователя
    except Shop.DoesNotExist:
        return render(request, 'shop_order_details.html', {'error': 'Вы не являетесь поставщиком'})

    # получаем заказ, который содержит товары из прайса поставщика
    orders = Order.objects.filter(id=order_id, items__product_info__shop=shop).distinct()
    if not orders.exists():
        return render(request, 'shop_order_details.html', {'error': 'Заказ не найден или не содержит ваших товаров'})

    order = orders.first()

    # фильтруем товары, которые принадлежат текущему поставщику
    items = OrderItem.objects.filter(order=order, product_info__shop=shop).select_related('product_info__shop')

    total_price = sum(item.quantity * item.product_info.price for item in items)

    address = (
        f"{order.contact.city}, {order.contact.street}, {order.contact.house}, кв. {order.contact.apartment}"
        if order.contact
        else "Адрес не указан"
    )

    context = {
        'order': order,
        'items': items,
        'total_price': total_price,
        'address': address,
    }
    return render(request, 'shop_order_details.html', context)

class ShopOrdersView(APIView):
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({"error": "Требуется авторизация"}, status=status.HTTP_403_FORBIDDEN)
        try:
            shop = Shop.objects.get(user=request.user)
        except Shop.DoesNotExist:
            return Response({"error": "Вы не являетесь поставщиком"}, status=status.HTTP_403_FORBIDDEN)

        status_filter = request.query_params.get('status')

        # получаем заказы, содержащие товары из прайса поставщика
        orders = Order.objects.filter(items__product_info__shop=shop).distinct()
        if status_filter:
            orders = orders.filter(status=status_filter)
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)

    def patch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({"error": "Требуется авторизация"}, status=status.HTTP_403_FORBIDDEN)

        try:
            shop = Shop.objects.get(user=request.user)
        except Shop.DoesNotExist:
            return Response({"error": "Вы не являетесь поставщиком"}, status=status.HTTP_403_FORBIDDEN)

        # получаем ID заказа и новый статус из запроса
        order_id = request.data.get('order_id')
        new_status = request.data.get('status')

        if not order_id or not new_status:
            return Response({"error": "Необходимо указать order_id и status"}, status=status.HTTP_400_BAD_REQUEST)

        # получаем заказ, который содержит товары из прайса поставщика
        try:
            orders = Order.objects.filter(id=order_id, items__product_info__shop=shop).distinct()
            if orders.exists():
                order = orders.first()
        except Order.DoesNotExist:
            return Response({"error": "Заказ не найден или не содержит ваших товаров"},
                            status=status.HTTP_404_NOT_FOUND)

        if new_status not in dict(Order.STATUS_CHOICES).keys():
            return Response({"error": "Недопустимый статус"}, status=status.HTTP_400_BAD_REQUEST)

        # обновляем статус заказа
        order.status = new_status
        order.save()

        return Response({"status": "Статус заказа успешно обновлен", "order_id": order.id, "new_status": new_status})

class ShopStatusView(APIView):
    def get(self, request):
        try:
            shop = Shop.objects.get(user=request.user)
            return Response({"is_active": shop.is_active})
        except Shop.DoesNotExist:
            return Response({"error": "Магазин не найден"}, status=404)
    def post(self, request, *args, **kwargs):
        try:
            shop = Shop.objects.get(user=request.user)
            shop.is_active = not shop.is_active  # переключаем статус
            shop.save()
            return Response({'status': 'success', 'is_active': shop.is_active})
        except Shop.DoesNotExist:
            return Response({'status': 'error', 'message': 'Вы не являетесь поставщиком'}, status=status.HTTP_404_NOT_FOUND)

class GiftAssistant:
    def __init__(self):
        self.sbert_model = SentenceTransformer(r"C:\Users\USER\Downloads\sbert_contextual3")

        # загружаем товары из базы данных
        self.products = []
        self.texts = []

        for info in ProductInfo.objects.select_related("product", "shop").prefetch_related("parameters__parameter"):
            name = info.product.name
            shop = info.shop.name
            price = info.price

            parameters = ", ".join([
                f"{pp.parameter.name}: {pp.value}"
                for pp in info.parameters.all()
            ])

            text = f"{name}. Магазин: {shop}. {parameters}. Цена: {price} руб."

            self.products.append({
                "id": info.id,
                "product_name": name,
                "price": float(price),
                "shop": shop,
                "text": text,
            })
            self.texts.append(text)

    def extract_price_limit(self, query):
        match = re.search(r'до\s*(\d{3,})', query)
        if match:
            return int(match.group(1))
        return None

    def find_similar_products(self, query, top_k=9):
        price_limit = self.extract_price_limit(query)

        filtered = self.products
        if price_limit:
            filtered = [p for p in self.products if p['price'] <= price_limit]

        if not filtered:
            return []

        texts = [p['text'] for p in filtered]

        query_embedding = self.sbert_model.encode(query, convert_to_tensor=True)
        product_embeddings = self.sbert_model.encode(texts, convert_to_tensor=True)
        cos_scores = torch.nn.functional.cosine_similarity(query_embedding, product_embeddings)
        top_results = torch.topk(cos_scores, k=min(top_k, len(filtered)))

        return [
            {
                "id": filtered[i.item()]['id'],
                "product_name": filtered[i.item()]['product_name'],
                "price": filtered[i.item()]['price'],
                "shop": filtered[i.item()]['shop'],
            }
            for i in top_results.indices
        ]

    def process_request(self, user_query):
        products = self.find_similar_products(user_query)
        return {
            'products': products
        }

# инициализация ассистента (один раз при запуске сервера)
assistant = GiftAssistant()

# View для обработки запросов
@csrf_exempt
def assistant_api(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_query = data.get('query', '')
            if not user_query:
                return JsonResponse({'error': 'Query is required'}, status=400)
            result = assistant.process_request(user_query)
            return JsonResponse(result)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Only POST method is allowed'}, status=405)

def assistant_view(request):
    return render(request, 'assistant.html')
