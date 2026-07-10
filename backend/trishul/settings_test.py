import os

os.environ["DEBUG"] = "true"
os.environ["DJANGO_SECRET_KEY"] = "test-secret-key-not-for-production"
for name in ("DATABASE_URL", "DATABASE_URL_FILE", "DB_HOST", "DB_USER", "DB_PASSWORD", "DB_PASSWORD_FILE"):
    os.environ.pop(name, None)

from .settings import *  # noqa: F403
