from functools import lru_cache

import boto3
from django.conf import settings


@lru_cache(maxsize=1)
def client():
    options = {"region_name": settings.S3_REGION, "verify": settings.S3_CA_BUNDLE or True}
    if settings.S3_ENDPOINT_URL:
        options["endpoint_url"] = settings.S3_ENDPOINT_URL
    if settings.S3_ACCESS_KEY and settings.S3_SECRET_KEY:
        options.update(
            aws_access_key_id=settings.S3_ACCESS_KEY,
            aws_secret_access_key=settings.S3_SECRET_KEY,
        )
    return boto3.client("s3", **options)


def put_file(key, file_obj, *, content_type="application/octet-stream"):
    file_obj.seek(0)
    client().upload_fileobj(
        file_obj,
        settings.S3_BUCKET,
        key,
        ExtraArgs={"ContentType": content_type},
    )


def download_file(key, filename):
    client().download_file(settings.S3_BUCKET, key, filename)


def delete_file(key):
    client().delete_object(Bucket=settings.S3_BUCKET, Key=key)


def presigned_get(key, expires=900):
    return client().generate_presigned_url(
        "get_object", Params={"Bucket": settings.S3_BUCKET, "Key": key}, ExpiresIn=expires
    )


def presigned_put(key, expires=900):
    return client().generate_presigned_url(
        "put_object", Params={"Bucket": settings.S3_BUCKET, "Key": key}, ExpiresIn=expires
    )


def healthcheck():
    client().head_bucket(Bucket=settings.S3_BUCKET)
