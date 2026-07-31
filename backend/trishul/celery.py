import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "trishul.settings")

app = Celery("trishul")
app.config_from_object("django.conf:settings", namespace="CELERY")
# Redis may redeliver after a worker/host failure.  Database leases, rather than
# broker delivery state, are the authority for whether an analyzer may start.
app.conf.broker_transport_options = {
    **(app.conf.broker_transport_options or {}),
    "visibility_timeout": 3600,
}
app.autodiscover_tasks()
