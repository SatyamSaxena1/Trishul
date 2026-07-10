import argparse
from pathlib import Path
from urllib.parse import urlparse

import httpx

CHUNK_SIZE = 1024 * 1024


def validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Transfer URL must be a credential-free HTTPS authority")


def download(url: str, path: str, maximum: int) -> None:
    validate_url(url)
    total = 0
    with httpx.stream("GET", url, follow_redirects=False, timeout=120) as response:
        response.raise_for_status()
        with Path(path).open("xb") as output:
            for chunk in response.iter_bytes(CHUNK_SIZE):
                total += len(chunk)
                if total > maximum:
                    raise ValueError("Transfer exceeds configured limit")
                output.write(chunk)


def upload(url: str, path: str, maximum: int) -> None:
    validate_url(url)
    source = Path(path)
    if source.stat().st_size > maximum:
        raise ValueError("Transfer exceeds configured limit")
    with source.open("rb") as content:
        response = httpx.put(url, content=content, follow_redirects=False, timeout=120)
        response.raise_for_status()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["download", "upload"])
    parser.add_argument("url")
    parser.add_argument("path")
    parser.add_argument("--maximum", type=int, required=True)
    arguments = parser.parse_args()
    globals()[arguments.operation](arguments.url, arguments.path, arguments.maximum)


if __name__ == "__main__":
    main()

