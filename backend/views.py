import smtplib
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.shortcuts import render
from django.utils.encoding import force_str, force_bytes
from .serializers import RegisterSerializer, LoginSerializer
from backend.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.core.cache import cache
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.conf import settings

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
                    last_name=temp_user["last_name"]
                )
                user.set_password(temp_user["password"])
                user.is_active = True
                user.save()

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

        return Response({'status': True, 'token': token.key}, status=status.HTTP_200_OK)

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