FROM python:3.13.13-slim@sha256:aa938a849bcb82dce8f49480f056ab82bf5c1c3ebc294f0430f37b6820e7f286

WORKDIR /app
COPY backend/core/archive.py /app/archive.py
COPY analyzer/main.py /app/main.py
RUN python -m compileall -q /app && chown -R 65532:65532 /app
USER 65532:65532
ENTRYPOINT ["python", "/app/main.py"]
