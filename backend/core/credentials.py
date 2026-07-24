import base64

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from django.conf import settings


def _fernet():
    if not settings.INTEGRATION_SECRET_KEY:
        raise ValueError("INTEGRATION_SECRET_KEY is required for repository integrations.")
    return Fernet(settings.INTEGRATION_SECRET_KEY.encode())


def encrypt_credential(value: str) -> str:
    if not settings.GIT_CREDENTIAL_PUBLIC_KEY:
        raise ValueError("GIT_CREDENTIAL_PUBLIC_KEY is required for GitLab integrations.")
    key = serialization.load_pem_public_key(settings.GIT_CREDENTIAL_PUBLIC_KEY.encode())
    encrypted = key.encrypt(
        value.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return base64.urlsafe_b64encode(encrypted).decode()


def decrypt_credential(value: str) -> str:
    if not settings.GIT_CREDENTIAL_PRIVATE_KEY:
        raise ValueError("GIT_CREDENTIAL_PRIVATE_KEY is required in the repository fetcher.")
    key = serialization.load_pem_private_key(settings.GIT_CREDENTIAL_PRIVATE_KEY.encode(), password=None)
    try:
        return key.decrypt(
            base64.urlsafe_b64decode(value),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        ).decode()
    except (ValueError, InvalidTag) as exc:
        raise ValueError("Repository credential cannot be decrypted.") from exc


def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode() if value else ""


def decrypt_secret(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode()).decode() if value else ""
    except InvalidToken as exc:
        raise ValueError("Repository credential cannot be decrypted.") from exc
