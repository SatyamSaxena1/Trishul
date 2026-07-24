#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import os
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle")
    parser.add_argument("--url", default=os.getenv("TRISHUL_URL"))
    parser.add_argument("--version", default=os.getenv("TRISHUL_VERSION_ID"))
    parser.add_argument("--token", default=os.getenv("TRISHUL_TOKEN"))
    parser.add_argument("--secret", default=os.getenv("TRISHUL_CI_SECRET"))
    args = parser.parse_args()
    if not all((args.url, args.version, args.token, args.secret)):
        parser.error("URL, version, token, and CI signing secret are required")
    if urlsplit(args.url).scheme != "https":
        parser.error("Trishul URL must use HTTPS")
    body = Path(args.bundle).read_bytes()
    signature = "sha256=" + hmac.new(args.secret.encode(), body, hashlib.sha256).hexdigest()
    request = urllib.request.Request(  # noqa: S310 - URL scheme is restricted to HTTPS above.
        f"{args.url.rstrip('/')}/api/v1/repository-versions/{args.version}/external-results/",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {args.token}",
            "Content-Type": "application/json",
            "X-Trishul-Signature-256": signature,
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        print(response.read().decode())


if __name__ == "__main__":
    main()
