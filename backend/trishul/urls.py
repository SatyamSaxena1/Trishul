from django.urls import include, path

urlpatterns = [
    path("api/v1/", include("core.urls")),
    path("api/v1/assurance/", include("deployment_assurance.urls")),
]
