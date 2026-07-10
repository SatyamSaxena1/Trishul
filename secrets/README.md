# Runtime secrets

Create each file named by `compose.yaml` with mode `0600`. Do not put secrets in `.env`.

Required files: `db_owner_password`, `db_app_password`, `redis_password`, `s3_access_key`, `s3_secret_key`, `django_secret_key`, `internal_ai_token`, `metrics_token`, `ai_endpoint_credential`, `backup_key`, `tls.crt`, and `tls.key`.

Generate `backup_key` with `openssl rand -base64 32`. Keep a separately protected recovery copy; a database backup cannot be restored without it.

Production values must be independently generated. An external secrets manager may materialize these files immediately before `docker compose up`.
