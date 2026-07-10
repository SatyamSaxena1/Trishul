from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import MODEL_VIEWSETS, ai_invoke, context, live, metrics, oidc_config, oidc_metadata, ready

router = DefaultRouter()
for prefix, viewset in MODEL_VIEWSETS.items():
    router.register(prefix, viewset, basename=prefix)

urlpatterns = [
    path("context", context),
    path("auth/config", oidc_config),
    path("auth/metadata", oidc_metadata),
    path("health/live", live),
    path("health/ready", ready),
    path("metrics", metrics),
    path("internal/ai/invoke", ai_invoke),
    *router.urls,
]
