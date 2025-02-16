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
from django.shortcuts import redirect
from django.urls import path
from backend.views import RegisterView, VerifyEmailView, LoginAccount, ResetPasswordView, ResetPasswordConfirmView, \
    main_depends_role, shop_products_view, ShopProductView, customer_products_view, CustomerProductsView, \
    CategoryListView, CategoryParametersView

urlpatterns = [
    path('', lambda request: redirect('login/')),
    path("main_depends/", main_depends_role, name="main_depends_role"),
    path("register/", RegisterView.as_view(), name="register"),
    path("verify-email/<str:uid>/<str:token>/", VerifyEmailView.as_view(), name="verify-email"),
    path("login/", LoginAccount.as_view(), name="login"),
    path("password-reset/", ResetPasswordView.as_view(), name="password-reset"),
    path("password-reset/<str:uid>/<str:token>/", ResetPasswordConfirmView.as_view(), name="password-reset-confirm"),
    path("shop-products/", shop_products_view, name="shop-products"),
    path("api/shop/products/", ShopProductView.as_view(), name="shop-products-api"),
    path("api/shop/products/<int:product_id>/", ShopProductView.as_view(), name="update-product"),
    path('customer-products/', customer_products_view, name='customer-products'),
    path('api/customer/products/', CustomerProductsView.as_view(), name='customer-products-api'),
    path("api/categories/", CategoryListView.as_view(), name="category-list"),
    path("api/categories/<int:category_id>/parameters/", CategoryParametersView.as_view(), name="category-parameters"),
]

