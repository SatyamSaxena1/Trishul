FROM python:3.13.13-slim@sha256:aa938a849bcb82dce8f49480f056ab82bf5c1c3ebc294f0430f37b6820e7f286 AS app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/home/trishul/.local/bin:$PATH

WORKDIR /app
RUN groupadd --gid 10001 trishul \
    && useradd --uid 10001 --gid trishul --create-home --shell /usr/sbin/nologin trishul
COPY requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.lock
COPY --chown=10001:10001 backend /app
RUN python -m compileall -q /app
USER 10001:10001
EXPOSE 8000
CMD ["gunicorn", "trishul.wsgi:application", "--bind=0.0.0.0:8000", "--workers=3", "--timeout=60", "--graceful-timeout=30", "--access-logfile=-", "--error-logfile=-"]

FROM docker:28-cli@sha256:625d9431a9f54c5a2bc90f24f0e1c3d55b1349fd857dd85035f98c2c9acbdd4d AS docker_cli

FROM app AS controller
COPY --from=docker_cli /usr/local/bin/docker /usr/local/bin/docker
