import io
import zipfile

import pytest

from core.archive import UnsafeArchive, inspect_archive


def archive(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as zipped:
        for name, value in entries.items():
            zipped.writestr(name, value)
    output.seek(0)
    output.size = len(output.getvalue())
    return output


def test_archive_inventory_does_not_extract_source():
    result = inspect_archive(archive({"src/app.py": "print('safe')"}))
    assert result["files"] == [{"path": "src/app.py", "size": 13}]
    assert len(result["sha256"]) == 64


@pytest.mark.parametrize("path", ["../secret", "/etc/passwd", "C:/windows/system32"])
def test_archive_rejects_paths_outside_root(path):
    with pytest.raises(UnsafeArchive):
        inspect_archive(archive({path: "bad"}))
