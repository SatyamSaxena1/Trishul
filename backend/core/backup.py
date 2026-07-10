import argparse
import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"TRISHUL1"
NONCE_SIZE = 12
TAG_SIZE = 16
CHUNK_SIZE = 1024 * 1024


def load_key(path: str) -> bytes:
    value = Path(path).read_bytes().strip()
    for decoder in (base64.b64decode, bytes.fromhex):
        try:
            key = decoder(value.decode())
            if len(key) == 32:
                return key
        except (ValueError, UnicodeDecodeError):
            pass
    if len(value) == 32:
        return value
    raise ValueError("Backup key must be 32 raw bytes, 64 hex characters, or base64-encoded 32 bytes")


def encrypt(source: str, destination: str, key_path: str) -> None:
    key = load_key(key_path)
    nonce = os.urandom(NONCE_SIZE)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(MAGIC)
    with open(source, "rb") as input_file, open(destination, "wb") as output_file:
        output_file.write(MAGIC + nonce)
        while chunk := input_file.read(CHUNK_SIZE):
            output_file.write(encryptor.update(chunk))
        output_file.write(encryptor.finalize())
        output_file.write(encryptor.tag)


def decrypt(source: str, destination: str, key_path: str) -> None:
    key = load_key(key_path)
    size = Path(source).stat().st_size
    if size < len(MAGIC) + NONCE_SIZE + TAG_SIZE:
        raise ValueError("Backup is truncated")
    with open(source, "rb") as input_file:
        if input_file.read(len(MAGIC)) != MAGIC:
            raise ValueError("Backup format is invalid")
        nonce = input_file.read(NONCE_SIZE)
        input_file.seek(-TAG_SIZE, os.SEEK_END)
        tag = input_file.read(TAG_SIZE)
        input_file.seek(len(MAGIC) + NONCE_SIZE)
        remaining = size - len(MAGIC) - NONCE_SIZE - TAG_SIZE
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(MAGIC)
        with open(destination, "wb") as output_file:
            while remaining:
                chunk = input_file.read(min(CHUNK_SIZE, remaining))
                remaining -= len(chunk)
                output_file.write(decryptor.update(chunk))
            output_file.write(decryptor.finalize())


def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt an AI Trishul backup")
    parser.add_argument("operation", choices=["encrypt", "decrypt"])
    parser.add_argument("source")
    parser.add_argument("destination")
    parser.add_argument("--key-file", default="/run/secrets/backup_key")
    arguments = parser.parse_args()
    globals()[arguments.operation](arguments.source, arguments.destination, arguments.key_file)


if __name__ == "__main__":
    main()
