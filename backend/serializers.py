from rest_framework import serializers
from django.core.mail import send_mail
from django.conf import settings
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.cache import cache
from backend.models import User
from django.core.exceptions import ValidationError
import re
from django.contrib.auth.hashers import check_password

# функции валидации

# валидатор для уникальности email
def validate_email_unique(value):
    if User.objects.filter(email=value).exists():
        raise ValidationError("Пользователь с такой почтой уже зарегистрирован.")
    return value

# валидатор, чтобы в поле email не вводились русские буквы
def validate_email_no_russian(value):
    if re.search(r'[а-яА-Я]', value):
        raise ValidationError("Email не должен содержать русские буквы.")
    return value


# валидатор для уникальности password
def validate_password_not_in_use(value):
    users = User.objects.all()
    for user in users:
        if user.password and check_password(value, user.password):
            raise ValidationError("Этот пароль уже используется другим пользователем. Выберите другой.")
    return value

# валидатор для длины пароля
def validate_password_length(value):
    if len(value) < 8:
        raise ValidationError("Пароль должен содержать минимум 8 символов.")
    return value

# валидатор для проверки спецсимволов в first_name и last_name
def validate_no_special_characters(value):
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
        raise ValidationError("Имя и фамилия не должны содержать специальных символов.")
    return value

# cериализатор для регистрации с email-подтверждением
class RegisterSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=30, validators=[validate_no_special_characters])
    last_name = serializers.CharField(max_length=30, validators=[validate_no_special_characters])
    email = serializers.EmailField(validators=[validate_email_unique, validate_email_no_russian])
    password = serializers.CharField(write_only=True, validators=[validate_password_length, validate_password_not_in_use])

    def create(self, validated_data):
        temp_user = validated_data
        fake_user = User(email=temp_user["email"])

        cache.set(f"temp_user_{temp_user['email']}", temp_user, timeout=600) # сохраняем пользователя во временное хранилище (кэш)

        uid = urlsafe_base64_encode(force_bytes(temp_user["email"]))

        token = default_token_generator.make_token(fake_user) # генерируем токен

        cache.set(f"email_verify_{uid}", token, timeout=600) # сохраняем токен в кэше

        verification_link = f"http://127.0.0.1:8000/verify-email/{uid}/{token}"

        send_mail(
            "Подтверждение регистрации",
            f"Перейдите по ссылке для подтверждения: {verification_link}",
            settings.EMAIL_HOST_USER,
            [temp_user["email"]],
            fail_silently=False,
        )

        return {"message": "Письмо с подтверждением отправлено."}

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")

        errors = {}

        if not email:
            errors["email"] = ["Не указан email"]

        if not password:
            errors["password"] = ["Не указан пароль"]

        if errors:
            raise serializers.ValidationError(errors)

        # проверяем, существует ли пользователь
        user = User.objects.filter(email=email).first()
        if user is None:
            errors["email"] = ["Пользователь с таким email не найден"]

        elif not user.check_password(password):
            errors["password"] = ["Неверный пароль"]

        elif not user.is_active:
            errors["email"] = ["Аккаунт не подтверждён"]

        if errors:
            raise serializers.ValidationError(errors)

        # если всё хорошо, передаём пользователя дальше
        data["user"] = user
        return data

