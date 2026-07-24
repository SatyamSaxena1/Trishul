# Runtime secrets

Create each file named by `compose.yaml` with mode `0600`. Do not put secrets in `.env`.

Required files: `db_owner_password`, `db_app_password`, `redis_password`, `s3_access_key`, `s3_secret_key`, `django_secret_key`, `internal_ai_token`, `metrics_token`, `ai_endpoint_credential`, `backup_key`, `integration_secret_key`, `git_credential_public_key.pem`, `git_credential_private_key.pem`, `github_app_private_key.pem`, `tls.crt`, and `tls.key`.

Generate `backup_key` with `openssl rand -base64 32`. Keep a separately protected recovery copy; a database backup cannot be restored without it.

Generate the integration and Git credential keys with:

```text
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > secrets/integration_secret_key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out secrets/git_credential_private_key.pem
openssl pkey -in secrets/git_credential_private_key.pem -pubout -out secrets/git_credential_public_key.pem
```

Put the GitHub App private key in `github_app_private_key.pem`. Only the repository fetcher receives private Git credentials; the API receives the public encryption key.

Production values must be independently generated. An external secrets manager may materialize these files immediately before `docker compose up`.
