"""Deployment Assurance routes, mounted under ``/api/v1/assurance/``.

Namespaced under its own prefix so the module's surface is obviously separate
from the existing ``/api/v1/`` resources, and so an operator can restrict or
rate-limit the CI-facing gate at the edge without touching the rest of the API.
"""

from rest_framework.routers import DefaultRouter

from .views import ASSURANCE_VIEWSETS

router = DefaultRouter()
for prefix, viewset in ASSURANCE_VIEWSETS.items():
    router.register(prefix, viewset, basename=f"assurance-{prefix}")

urlpatterns = router.urls
