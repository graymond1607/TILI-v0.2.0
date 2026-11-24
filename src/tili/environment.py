
from __future__ import annotations

import re
from typing import Optional

from .settings import load_settings


ENVIRONMENT_PATTERNS = [
    re.compile(
        r"\benvironment\s*[=:]\s*[\"']?(Production|Prod|Test/RU|Test-RU|Test|RU)\b",
        re.I,
    ),
    re.compile(
        r"\benv\s*[=:]\s*[\"']?(Production|Prod|Test/RU|Test-RU|Test|RU)\b",
        re.I,
    ),
    re.compile(
        r"\bstage\s*[=:]\s*[\"']?(Production|Prod|Test/RU|Test-RU|Test|RU)\b",
        re.I,
    ),
]


def normalize_environment(value: str) -> Optional[str]:
    """Normalize optional environment metadata."""

    value = value.strip().lower()

    aliases = {
        "production": "Production",
        "prod": "Production",
        "prodution": "Production",
        "test": "Test/RU",
        "test/ru": "Test/RU",
        "test-ru": "Test/RU",
        "test_ru": "Test/RU",
        "ru": "Test/RU",
    }

    return aliases.get(value)


def detect_explicit_environment(text: str) -> dict:
    """Detect optional environment metadata in log content."""

    settings = load_settings()
    config = settings.get("environment", {})
    detection = config.get("detection", {})

    if not detection.get("explicit_metadata", True):
        return {
            "environment": "",
            "source": "",
            "evidence": "",
        }

    for pattern in ENVIRONMENT_PATTERNS:
        match = pattern.search(text)

        if match:
            environment = normalize_environment(match.group(1))

            if environment:
                return {
                    "environment": environment,
                    "source": "Explicit log metadata",
                    "evidence": match.group(0),
                }

    return {
        "environment": "",
        "source": "",
        "evidence": "",
    }


def detect_hostname_environment(hostname: str = "") -> dict:
    """Detect optional environment metadata from hostname mapping."""

    if not hostname:
        return {
            "environment": "",
            "source": "",
            "evidence": "",
        }

    settings = load_settings()
    config = settings.get("environment", {})
    detection = config.get("detection", {})

    if not detection.get("hostname_mapping", True):
        return {
            "environment": "",
            "source": "",
            "evidence": "",
        }

    mappings = config.get("hostname_mapping", {})

    for configured_hostname, value in mappings.items():
        if hostname.casefold() == configured_hostname.casefold():
            environment = normalize_environment(str(value))

            if environment:
                return {
                    "environment": environment,
                    "source": "Hostname mapping",
                    "evidence": hostname,
                }

    return {
        "environment": "",
        "source": "",
        "evidence": "",
    }
