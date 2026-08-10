import io
from unittest.mock import Mock, patch

from django.test import override_settings

from core import storage


def setup_function():
    storage.client.cache_clear()


@patch("core.storage.boto3.client")
@override_settings(
    S3_ENDPOINT_URL="",
    S3_REGION="ap-south-1",
    S3_ACCESS_KEY="",
    S3_SECRET_KEY="",
    S3_CA_BUNDLE=None,
)
def test_aws_storage_uses_default_credentials(mock_client):
    storage.client()
    mock_client.assert_called_once_with("s3", region_name="ap-south-1", verify=True)


@patch("core.storage.boto3.client")
@override_settings(
    S3_ENDPOINT_URL="https://minio.example",
    S3_REGION="us-east-1",
    S3_ACCESS_KEY="local-key",
    S3_SECRET_KEY="local-secret",
    S3_CA_BUNDLE=None,
)
def test_private_storage_keeps_explicit_credentials(mock_client):
    storage.client()
    mock_client.assert_called_once_with(
        "s3",
        endpoint_url="https://minio.example",
        region_name="us-east-1",
        aws_access_key_id="local-key",
        aws_secret_access_key="local-secret",
        verify=True,
    )


@patch("core.storage.client")
@override_settings(S3_BUCKET="evidence")
def test_upload_relies_on_bucket_encryption(mock_client):
    s3 = Mock()
    mock_client.return_value = s3
    storage.put_file("tenant/evidence.json", io.BytesIO(b"{}"), content_type="application/json")
    assert s3.upload_fileobj.call_args.kwargs["ExtraArgs"] == {"ContentType": "application/json"}
