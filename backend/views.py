import smtplib
from django.contrib.auth import login
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.shortcuts import render
from django.utils.encoding import force_str, force_bytes
from rest_framework.authentication import TokenAuthentication
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.permissions import IsAuthenticated

from .filters import ProductInfoFilter
from .serializers import RegisterSerializer, LoginSerializer, ProductInfoSerializer, CategorySerializer
from backend.models import User, Category
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
    return render(request, "shop-products.html", {"user": request.user})

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
        products = ProductInfo.objects.select_related('product', 'shop').prefetch_related('parameters').all()
        filterset = ProductInfoFilter(request.query_params, queryset=products)
        filtered_products = filterset.qs
        serializer = ProductInfoSerializer(filtered_products, many=True)
        return Response(serializer.data, status=200)
