from __future__ import annotations

from pathlib import PurePosixPath
from zipfile import ZipFile, BadZipFile
import io

from .settings import load_settings

ALLOWED_EXTENSIONS = {".log", ".txt", ".csv", ".json"}


def read_uploaded_files(uploaded_files):
    """Return [(display_name, decoded_text)] from Streamlit UploadedFile objects."""
    settings = load_settings()
    app_settings = settings.get("app", {})
    max_upload_bytes = int(app_settings.get("max_upload_mb", 1024)) * 1024 * 1024
    max_members = int(app_settings.get("max_zip_members", 1024))

    output = []

    for uploaded in uploaded_files:
        name = uploaded.name
        size = getattr(uploaded, "size", None)
        raw = None

        if size is None:
            raw = uploaded.getvalue()
            size = len(raw)

        if size > max_upload_bytes:
            raise ValueError(
                f"{name}: upload exceeds the configured limit of "
                f"{app_settings.get('max_upload_mb', 1024)} MB."
            )

        suffix = PurePosixPath(name).suffix.lower()

        if suffix == ".zip":
            try:
                if raw is not None:
                    zip_source = io.BytesIO(raw)
                else:
                    uploaded.seek(0)
                    zip_source = uploaded

                with ZipFile(zip_source) as archive:
                    members = [m for m in archive.infolist() if not m.is_dir()]

                    if len(members) > max_members:
                        raise ValueError(
                            f"{name}: ZIP contains {len(members)} files; "
                            f"the configured maximum is {max_members}."
                        )

                    expanded_bytes = 0

                    for member in members:
                        member_suffix = PurePosixPath(member.filename).suffix.lower()

                        if member_suffix not in ALLOWED_EXTENSIONS:
                            continue

                        if member.file_size > max_upload_bytes:
                            raise ValueError(
                                f"{name}::{PurePosixPath(member.filename).name}: ZIP member "
                                f"exceeds the configured limit of "
                                    f"{app_settings.get('max_upload_mb', 1024)} MB."
                            )

                        if expanded_bytes + member.file_size > max_upload_bytes:
                            raise ValueError(
                                f"{name}: supported ZIP content expands beyond the configured "
                                f"limit of {app_settings.get('max_upload_mb', 1024)} MB."
                            )

                        content = archive.read(member)
                        expanded_bytes += len(content)

                        safe_name = PurePosixPath(member.filename).name
                        output.append(
                            (f"{name}::{safe_name}", content.decode("utf-8", errors="replace"))
                        )

            except BadZipFile as exc:
                raise ValueError(f"{name} is not a valid ZIP archive.") from exc

        elif suffix in ALLOWED_EXTENSIONS:
            uploaded.seek(0)
            content = uploaded.read()
            output.append((name, content.decode("utf-8", errors="replace")))

        else:
            raise ValueError(f"Unsupported file type: {name}")

    return output
