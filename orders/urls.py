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
    CategoryListView, CategoryParametersView, basket_view, BasketView, OrderView, order_history_view, \
    order_detail_view, ContactView, ShopOrdersView, shop_order_history_view, shop_order_detail_view, \
    ShopStatusView, assistant_view, assistant_api

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
    path('api/basket/', BasketView.as_view(), name='basket-api'),
    path('basket/', basket_view, name='basket-page'),
    path('api/basket/items/<int:item_id>/', BasketView.as_view(), name='basket-item-update'),
    path('api/basket/items/<int:item_id>/', BasketView.as_view(), name='basket-item-detail'),
    path('api/contacts/', ContactView.as_view(), name='contacts'),
    path('api/contacts/<int:contact_id>/', ContactView.as_view(), name='delete-contact'),
    path('api/orders/', OrderView.as_view(), name='create-order'),
    path('orders/', order_history_view, name='order-history'),
    path('orders/', OrderView.as_view(), name='order'),
    path('orders/<int:order_id>/', order_detail_view, name='order-details'),
    path('shop_orders/', shop_order_history_view, name='shop-orders'),
    path('shop_orders/', ShopOrdersView.as_view(), name='api-shop-orders'),
    path('shop_orders/<int:order_id>/', shop_order_detail_view, name='shop-order-details'),
    path('api/shop/orders/', ShopOrdersView.as_view(), name='shop-orders-api'),
    # path('api/shop/toggle-active-orders/', ToggleAcceptingOrdersView.as_view(), name='toggle-active-orders-api'),
    path('api/shop/status/', ShopStatusView.as_view(), name='shop-status'),
    path('assistant/', assistant_view, name='assistant'),
    path('api/assistant/', assistant_api, name='assistant_api'),
]

