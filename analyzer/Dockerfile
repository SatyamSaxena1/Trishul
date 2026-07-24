FROM aquasec/trivy:0.67.2@sha256:e2b22eac59c02003d8749f5b8d9bd073b62e30fefaef5b7c8371204e0a4b0c08 AS trivy
RUN trivy image --download-db-only --cache-dir /trivy-cache

FROM python:3.13.13-slim@sha256:aa938a849bcb82dce8f49480f056ab82bf5c1c3ebc294f0430f37b6820e7f286

WORKDIR /app
RUN pip install --no-cache-dir --disable-pip-version-check semgrep==1.171.0
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=trivy /trivy-cache /trivy-cache
COPY backend/core/archive.py /app/archive.py
COPY analyzer/main.py /app/main.py
COPY analyzer/rules.yml /app/rules.yml
RUN semgrep --validate --config /app/rules.yml \
    && trivy --version \
    && python -m compileall -q /app \
    && chown -R 65532:65532 /app
USER 65532:65532
ENTRYPOINT ["python", "/app/main.py"]
