from io import BytesIO
from zipfile import ZipFile, ZIP_DEFLATED

import pytest

from tili import ingestion


class FakeUpload:
    def __init__(self, name, data):
        self.name = name
        self._data = data

    def getvalue(self):
        return self._data


def make_zip(*items):
    stream = BytesIO()
    with ZipFile(stream, "w", compression=ZIP_DEFLATED) as archive:
        for name, content in items:
            archive.writestr(name, content)
    return stream.getvalue()


def test_zip_member_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(
        ingestion,
        "load_settings",
        lambda: {"app": {"max_upload_mb": 1, "max_zip_members": 1}},
    )
    archive = make_zip(("one.log", "one"), ("two.log", "two"))
    with pytest.raises(ValueError, match="configured maximum is 1"):
        ingestion.read_uploaded_files([FakeUpload("logs.zip", archive)])


def test_uploaded_file_size_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(
        ingestion,
        "load_settings",
        lambda: {"app": {"max_upload_mb": 0, "max_zip_members": 10}},
    )
    with pytest.raises(ValueError, match="upload exceeds the configured limit"):
        ingestion.read_uploaded_files([FakeUpload("sample.log", b"x")])


def test_combined_zip_expansion_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(
        ingestion,
        "load_settings",
        lambda: {"app": {"max_upload_mb": 1, "max_zip_members": 10}},
    )
    archive = make_zip(("one.log", "0" * (600 * 1024)), ("two.log", "1" * (600 * 1024)))
    assert len(archive) < 1024 * 1024
    with pytest.raises(ValueError, match="expands beyond the configured limit"):
        ingestion.read_uploaded_files([FakeUpload("logs.zip", archive)])
