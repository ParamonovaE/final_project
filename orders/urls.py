"""
URL configuration for orders project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path
from backend.views import RegisterView, VerifyEmailView, LoginAccount, ResetPasswordView, ResetPasswordConfirmView

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("verify-email/<str:uid>/<str:token>/", VerifyEmailView.as_view(), name="verify-email"),
    path("login/", LoginAccount.as_view(), name="login"),
    path("password-reset/", ResetPasswordView.as_view(), name="password-reset"),
    path("password-reset/<str:uid>/<str:token>/", ResetPasswordConfirmView.as_view(), name="password-reset-confirm"),
]

