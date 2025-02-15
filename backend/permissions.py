from rest_framework.permissions import BasePermission

class IsSupplier(BasePermission):
     # разрешает доступ только поставщикам.
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'shop'