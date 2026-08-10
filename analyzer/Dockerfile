FROM python:3.13.13-slim@sha256:aa938a849bcb82dce8f49480f056ab82bf5c1c3ebc294f0430f37b6820e7f286

WORKDIR /app
RUN pip install --no-cache-dir --disable-pip-version-check PyYAML==6.0.2
COPY backend/core/archive.py /app/archive.py
COPY backend/deployment_assurance/__init__.py /app/deployment_assurance/__init__.py
COPY backend/deployment_assurance/limits.py backend/deployment_assurance/resources.py /app/deployment_assurance/
COPY backend/deployment_assurance/normalizers /app/deployment_assurance/normalizers
COPY analyzer/main.py /app/main.py
RUN python -m compileall -q /app && chown -R 65532:65532 /app
USER 65532:65532
ENTRYPOINT ["python", "/app/main.py"]
