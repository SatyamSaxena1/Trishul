import base64
import os

import pytest
from cryptography.exceptions import InvalidTag

from core.backup import decrypt, encrypt


def test_backup_encryption_round_trip_and_tamper_detection(tmp_path):
    source = tmp_path / "database.dump"
    encrypted = tmp_path / "database.dump.enc"
    restored = tmp_path / "restored.dump"
    key_file = tmp_path / "key"
    source.write_bytes(os.urandom(1024 * 1024 + 17))
    key_file.write_bytes(base64.b64encode(os.urandom(32)))
    encrypt(str(source), str(encrypted), str(key_file))
    assert source.read_bytes() not in encrypted.read_bytes()
    decrypt(str(encrypted), str(restored), str(key_file))
    assert restored.read_bytes() == source.read_bytes()
    content = bytearray(encrypted.read_bytes())
    content[-20] ^= 1
    encrypted.write_bytes(content)
    with pytest.raises(InvalidTag):
        decrypt(str(encrypted), str(restored), str(key_file))
