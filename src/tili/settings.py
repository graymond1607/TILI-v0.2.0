from __future__ import annotations

from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SETTINGS_FILE = PROJECT_ROOT / "config" / "settings.yaml"

DEFAULT_SETTINGS = {
    "app": {
        "name": "TI Log Intelligence",
        "version": "0.2.0",
        "max_upload_mb": 500,
        "max_zip_members": 1024,
    },
    "analysis": {
        "correlation_window_minutes": 10,
        "default_timezone": "Europe/Berlin",
    },
}


def load_settings() -> dict:
    """Load settings.yaml and merge it with defaults."""
    settings = {key: value.copy() for key, value in DEFAULT_SETTINGS.items()}
    if not SETTINGS_FILE.exists():
        return settings

    with SETTINGS_FILE.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}

    for section, values in loaded.items():
        if isinstance(values, dict):
            settings.setdefault(section, {}).update(values)
    return settings
