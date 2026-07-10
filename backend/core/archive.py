import hashlib
import io
import stat
import tarfile
import zipfile
from pathlib import PurePosixPath

MAX_COMPRESSED = 250 * 1024 * 1024
MAX_EXTRACTED = 1024 * 1024 * 1024
MAX_FILES = 50_000
MAX_FILE = 10 * 1024 * 1024
MAX_DEPTH = 20


class UnsafeArchive(ValueError):
    pass


def _validate_name(name: str) -> PurePosixPath:
    if "\x00" in name or "\\" in name:
        raise UnsafeArchive("Archive contains an invalid path.")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or len(path.parts) > MAX_DEPTH or ":" in path.parts[0]:
        raise UnsafeArchive("Archive path escapes the repository root.")
    return path


def inspect_archive(file_obj) -> dict:
    size = getattr(file_obj, "size", None)
    if size is not None and size > MAX_COMPRESSED:
        raise UnsafeArchive("Compressed archive exceeds 250 MiB.")
    file_obj.seek(0)
    digest = hashlib.file_digest(file_obj, "sha256").hexdigest()
    file_obj.seek(0)
    manifest = []
    total = 0
    try:
        if zipfile.is_zipfile(file_obj):
            file_obj.seek(0)
            with zipfile.ZipFile(file_obj) as archive:
                entries = archive.infolist()
                if len(entries) > MAX_FILES:
                    raise UnsafeArchive("Archive contains too many files.")
                for entry in entries:
                    path = _validate_name(entry.filename)
                    mode = entry.external_attr >> 16
                    if stat.S_ISLNK(mode):
                        raise UnsafeArchive("Symbolic links are forbidden.")
                    if entry.is_dir():
                        continue
                    if entry.file_size > MAX_FILE:
                        raise UnsafeArchive(f"File exceeds 10 MiB: {path}")
                    total += entry.file_size
                    manifest.append({"path": str(path), "size": entry.file_size})
        else:
            file_obj.seek(0)
            with tarfile.open(fileobj=file_obj, mode="r:*") as archive:
                entries = archive.getmembers()
                if len(entries) > MAX_FILES:
                    raise UnsafeArchive("Archive contains too many files.")
                for entry in entries:
                    path = _validate_name(entry.name)
                    if entry.issym() or entry.islnk() or entry.isdev() or entry.isfifo():
                        raise UnsafeArchive("Links and special files are forbidden.")
                    if not entry.isfile():
                        continue
                    if entry.size > MAX_FILE:
                        raise UnsafeArchive(f"File exceeds 10 MiB: {path}")
                    total += entry.size
                    manifest.append({"path": str(path), "size": entry.size})
    except (zipfile.BadZipFile, tarfile.TarError) as exc:
        raise UnsafeArchive("Only valid ZIP and TAR archives are accepted.") from exc
    if total > MAX_EXTRACTED:
        raise UnsafeArchive("Extracted archive exceeds 1 GiB.")
    file_obj.seek(0)
    return {"sha256": digest, "compressed_size": size, "extracted_size": total, "files": manifest}


def inspect_bytes(data: bytes) -> dict:
    stream = io.BytesIO(data)
    stream.size = len(data)
    return inspect_archive(stream)
