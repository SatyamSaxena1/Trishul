import os
from pathlib import Path
from urllib.parse import unquote, urlparse

BASE_DIR = Path(__file__).resolve().parent.parent


def secret(name: str, default: str = "") -> str:
    file_name = os.getenv(f"{name}_FILE")
    if file_name:
        return Path(file_name).read_text(encoding="utf-8").strip()
    return os.getenv(name, default)


def env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}


def database_config(url: str) -> dict:
    if not url and not os.getenv("DB_HOST"):
        return {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}
    if not url:
        return {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("DB_NAME", "trishul"),
            "USER": os.getenv("DB_USER", "trishul_app"),
            "PASSWORD": secret("DB_PASSWORD"),
            "HOST": os.getenv("DB_HOST", "postgres"),
            "PORT": int(os.getenv("DB_PORT", "5432")),
            "CONN_MAX_AGE": int(os.getenv("DB_CONN_MAX_AGE", "60")),
            "OPTIONS": {"sslmode": os.getenv("DB_SSLMODE", "prefer")},
            "ATOMIC_REQUESTS": True,
        }
    parsed = urlparse(url)
    if parsed.scheme not in {"postgres", "postgresql"}:
        raise ValueError("DATABASE_URL must use postgresql://")
    return {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": parsed.path.lstrip("/"),
        "USER": unquote(parsed.username or ""),
        "PASSWORD": unquote(parsed.password or ""),
        "HOST": parsed.hostname,
        "PORT": parsed.port or 5432,
        "CONN_MAX_AGE": int(os.getenv("DB_CONN_MAX_AGE", "60")),
        "OPTIONS": {"sslmode": os.getenv("DB_SSLMODE", "prefer")},
        "ATOMIC_REQUESTS": True,
    }


DEBUG = env_bool("DEBUG")
SECRET_KEY = secret("DJANGO_SECRET_KEY", "unsafe-development-key" if DEBUG else "")
if not SECRET_KEY:
    raise RuntimeError("DJANGO_SECRET_KEY or DJANGO_SECRET_KEY_FILE is required")

ALLOWED_HOSTS = [x for x in os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if x]
CSRF_TRUSTED_ORIGINS = [x for x in os.getenv("CSRF_TRUSTED_ORIGINS", "").split(",") if x]

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "core",
    "deployment_assurance",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "core.security.TenantContextCleanupMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "trishul.urls"
TEMPLATES = []
WSGI_APPLICATION = "trishul.wsgi.application"
ASGI_APPLICATION = "trishul.asgi.application"

DATABASES = {"default": database_config(secret("DATABASE_URL"))}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_PASSWORD_VALIDATORS = []
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
STATIC_URL = "/static/"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "core.security.ServiceTokenAuthentication",
        "core.security.OIDCBearerAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PAGINATION_CLASS": "core.api.CursorPagination",
    "PAGE_SIZE": 50,
    "EXCEPTION_HANDLER": "core.api.problem_exception_handler",
}

OIDC_ISSUER = os.getenv("OIDC_ISSUER", "")
OIDC_AUDIENCE = os.getenv("OIDC_AUDIENCE", "")
OIDC_JWKS_URL = os.getenv("OIDC_JWKS_URL", "")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "")
OIDC_DISCOVERY_URL = os.getenv("OIDC_DISCOVERY_URL", "")
OIDC_CA_BUNDLE = os.getenv("OIDC_CA_BUNDLE", "") or True
OIDC_MFA_REQUIRED = env_bool("OIDC_MFA_REQUIRED", True)
OIDC_MFA_ACR_VALUES = set(filter(None, os.getenv("OIDC_MFA_ACR_VALUES", "").split(",")))

_redis_url = secret("REDIS_URL")
_redis_password = secret("REDIS_PASSWORD")
if not _redis_url:
    from urllib.parse import quote

    _redis_url = (
        f"redis://:{quote(_redis_password, safe='')}@{os.getenv('REDIS_HOST', 'localhost')}:6379/0"
        if _redis_password
        else "redis://localhost:6379/0"
    )
CELERY_BROKER_URL = _redis_url
CELERY_RESULT_BACKEND = None
CELERY_TASK_ACKS_LATE = True
CELERY_TASK_REJECT_ON_WORKER_LOST = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_TASK_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_RESULT_SERIALIZER = "json"
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
CELERY_BEAT_SCHEDULE = {
    "reconcile-jobs": {"task": "core.tasks.reconcile_jobs", "schedule": 60.0},
    "expire-acceptances": {"task": "core.tasks.expire_acceptances", "schedule": 3600.0},
    "reconcile-evaluations": {"task": "deployment_assurance.tasks.reconcile_evaluations", "schedule": 60.0},
    "expire-waivers": {"task": "deployment_assurance.tasks.expire_waivers", "schedule": 900.0},
}

# Deployment Assurance reuses the existing analysis-controller queue and its
# isolated runtime; no second privileged worker or queue is introduced.
ASSURANCE_EVALUATION_LEASE_SECONDS = int(os.getenv("ASSURANCE_EVALUATION_LEASE_SECONDS", "1800"))
ASSURANCE_MAX_EVALUATION_ATTEMPTS = int(os.getenv("ASSURANCE_MAX_EVALUATION_ATTEMPTS", "3"))
ASSURANCE_EVIDENCE_RETENTION_CLASS = os.getenv("ASSURANCE_EVIDENCE_RETENTION_CLASS", "deployment-evidence-default")
ASSURANCE_ALLOW_IN_PROCESS_NORMALIZATION = False

S3_ENDPOINT_URL = os.getenv("S3_ENDPOINT_URL", "")
S3_REGION = os.getenv("S3_REGION", "us-east-1")
S3_BUCKET = os.getenv("S3_BUCKET", "trishul")
S3_ACCESS_KEY = secret("S3_ACCESS_KEY")
S3_SECRET_KEY = secret("S3_SECRET_KEY")
S3_CA_BUNDLE = os.getenv("S3_CA_BUNDLE", "") or None
INTERNAL_AI_TOKEN = secret("INTERNAL_AI_TOKEN", "unsafe-development-internal-token" if DEBUG else "")
METRICS_TOKEN = secret("METRICS_TOKEN")

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = not DEBUG
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {"format": '{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}'}
    },
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "json"}},
    "root": {"handlers": ["console"], "level": os.getenv("LOG_LEVEL", "INFO")},
}
