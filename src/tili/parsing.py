
from __future__ import annotations

import io
import re
import time
from datetime import datetime
from dateutil import parser as date_parser

from .models import LogEvent
from .environment import (
    detect_explicit_environment,
    detect_hostname_environment,
)

def parse_timestamp(value: str):
    """Parse common TILI timestamp formats efficiently."""

    value = value.strip().replace(",", ".")

    # ISO timestamps, including optional timezone offsets.
    if len(value) >= 19 and value[4] == "-":
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass

    # German timestamps: DD.MM.YYYY HH:MM:SS
    try:
        return datetime.strptime(value, "%d.%m.%Y %H:%M:%S.%f")
    except ValueError:
        try:
            return datetime.strptime(value, "%d.%m.%Y %H:%M:%S")
        except ValueError:
            pass

    # Fallback for unusual timestamp formats.
    try:
        return date_parser.parse(
            value,
            dayfirst="." in value,
        )
    except (ValueError, OverflowError):
        return None

TIMESTAMP_PATTERNS = [
    re.compile(
        r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
        r"(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    ),
    re.compile(
        r"(?P<ts>\d{2}\.\d{2}\.\d{4}[ ,T]+\d{2}:\d{2}:\d{2}"
        r"(?:[.,]\d+)?)"
    ),
]

LEVEL_RE = re.compile(
    r"\b(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL|SEVERE)\b",
    re.I,
)

UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.I,
)

CHSM_RE = re.compile(
    r"\bcHSM\s*(?:#|number|no\.?|instance)?\s*([0-9]{1,4})\b",
    re.I,
)

HOST_RE = re.compile(
    r"\b(?:hostname|host_name|host|HSK)\s*[=: ]\s*"
    r"([A-Za-z0-9_.-]{3,80})",
    re.I,
)

# Explicit identifier labels. Matching is case-insensitive.
FIELD_PATTERNS = {
    "device_id": re.compile(
        r"\b(?:device[_ -]?id|deviceid)\b\s*[=:]\s*"
        r"[\"']?([A-Za-z0-9_.:-]{2,100})",
        re.I,
    ),
    "konnektor_id": re.compile(
        r"\b(?:konnektor[_ -]?id|konnektorid|"
        r"konnektor[_ -]?(?:serial(?:[_ -]?(?:number|no))?)|"
        r"serial[_ -]?(?:number|no)|seriennummer)\b"
        r"\s*[=:]\s*[\"']?([A-Za-z0-9_./:-]{2,100})",
        re.I,
    ),
    "hardware_id": re.compile(
        r"\b(?:hardware[_ -]?(?:id|identifier)|hardwareid)\b"
        r"\s*[=: -]\s*[\"']?([A-Za-z0-9_.:-]{2,100})",
        re.I,
    ),
    "instance_id": re.compile(
        r"\b(?:instance[_ -]?id|instanceid)\b\s*[=:]\s*"
        r"[\"']?([A-Za-z0-9_.:-]{2,100})",
        re.I,
    ),
    "device_uid": re.compile(
        r"\b(?:device[_ -]?uid|deviceuid|uuid)\b\s*[=:]\s*"
        r"[\"']?([0-9a-f-]{36})",
        re.I,
    ),
}


def detect_source(text, filename=""):
    sample = (filename + "\n" + text[:12000]).lower()
    fn = filename.lower()

    # Check more specific infrastructure names first.
    filename_families = {
        "vHSK": ["vhsk", "virtual hsk"],
        "HSK": ["hskp", "physical hsk"],
        "HSM": ["hsm", "chsm", "gsmc-k", "utimaco"],
        "TIG": ["tig", "gateway"],
        "RZK": ["rzk"],
        "EBK": ["ebk"],
    }

    for family, terms in filename_families.items():
        if any(term in fn for term in terms):
            return family

    # Identify infrastructure from log content.
    content_scores = {
        "vHSK": sum(
            term in sample
            for term in ["vhsk", "virtual hsk"]
        ),
        "HSK": sum(
            term in sample
            for term in ["hskp", "physical hsk"]
        ),
        "HSM": sum(
            term in sample
            for term in ["hsm", "chsm", "gsmc-k", "utimaco", "b2010008"]
        ),
        "TIG": sum(
            term in sample
            for term in ["ti gateway", "gateway", "tls handshake", "upstream", "http 5"]
        ),
        "RZK": sum(
            term in sample
            for term in ["rzk", "rechenzentrumskonnektor"]
        ),
        "EBK": sum(
            term in sample
            for term in ["ebk", "einbaukonnektor", "konnektor"]
        ),
    }

    best = max(content_scores, key=content_scores.get)

    return best if content_scores[best] > 0 else "UNKNOWN"



def _identity(line, fallback_host="Unknown"):
    hostname_match = HOST_RE.search(line)
    hsk_match = re.search(
        r"\bHSKP[0-9A-Z_-]+\b",
        line,
        re.I,
    )

    hostname = (
        hostname_match.group(1)
        if hostname_match
        else hsk_match.group(0).upper() if hsk_match
        else fallback_host
    )

    # Extract UUID once.
    uid_match = FIELD_PATTERNS["device_uid"].search(line)
    uuid_match = UUID_RE.search(line)

    device_uid = (
        uid_match.group(1).lower()
        if uid_match
        else uuid_match.group(0).lower() if uuid_match else "Unknown"
    )

    # Extract instance identifier once.
    chsm_match = CHSM_RE.search(line)
    instance_match = FIELD_PATTERNS["instance_id"].search(line)

    # Preserve the established cHSM-0 representation.
    instance_id = (
        f"cHSM-{chsm_match.group(1)}"
        if chsm_match
        else instance_match.group(1) if instance_match else "Unknown"
    )

    # Extract only the remaining identifiers.
    identifiers = {}

    for field in ("device_id", "konnektor_id", "hardware_id"):
        match = FIELD_PATTERNS[field].search(line)
        identifiers[field] = match.group(1) if match else "Unknown"

    identifiers["device_uid"] = device_uid
    identifiers["instance_id"] = instance_id

    return hostname, identifiers


def parse_lines(
    text,
    filename="",
):
    source = detect_source(text, filename)
    events = []

    profile = {
        "timestamp": 0.0,
        "level": 0.0,
        "component": 0.0,
        "identity": 0.0,
        "environment": 0.0,
        "event_creation": 0.0,
    }

    # A filename-level HSKP identifier is safe to associate with its file.
    file_hsk = re.search(r"\bHSKP[0-9A-Z_-]+\b", filename, re.I)
    fallback_host = file_hsk.group(0).upper() if file_hsk else "Unknown"

    # Detect explicit environment metadata only once per file.
    explicit_environment = detect_explicit_environment(text)

    # Cache hostname results so configuration is not repeatedly loaded
    # for the same hostname.
    hostname_environment_cache = {}

    # Manual environment is evaluated once and reused as fallback.

    for number, raw in enumerate(io.StringIO(text), 1):
        line = raw.strip()
        if not line:
            continue

        stage_start = time.perf_counter()

        timestamp = None

        for pattern in TIMESTAMP_PATTERNS:
            match = pattern.search(line)
            if match:
                timestamp = parse_timestamp(match.group("ts"))
                break

        profile["timestamp"] += time.perf_counter() - stage_start

        stage_start = time.perf_counter()

        level_match = LEVEL_RE.search(line)
        level = level_match.group(1).upper() if level_match else "UNKNOWN"

        if level == "WARNING":
            level = "WARN"
        if level == "SEVERE":
            level = "ERROR"

        profile["level"] += time.perf_counter() - stage_start

        stage_start = time.perf_counter()

        component_match = re.search(r"\[([^\]]{1,100})\]", line)
        component = component_match.group(1) if component_match else "Unknown"

        profile["component"] += time.perf_counter() - stage_start

        stage_start = time.perf_counter()

        hostname, identifiers = _identity(line, fallback_host)

        profile["identity"] += time.perf_counter() - stage_start

        # Optional environment metadata:
        # 1. Explicit metadata
        # 2. Hostname mapping
        # Environment information never blocks analysis.
        stage_start = time.perf_counter()

        if explicit_environment["environment"]:
            environment_info = explicit_environment

        else:
            if hostname not in hostname_environment_cache:
                hostname_environment_cache[hostname] = (
                    detect_hostname_environment(hostname)
                )

            environment_info = hostname_environment_cache[hostname]

        profile["environment"] += time.perf_counter() - stage_start

        stage_start = time.perf_counter()

        events.append(
            LogEvent(
                source=source,
                timestamp=timestamp,
                level=level,
                component=component,
                message=line,
                line_number=number,
                file_name=filename,
                hostname=hostname,
                device_id=identifiers["device_id"],
                konnektor_id=identifiers["konnektor_id"],
                hardware_id=identifiers["hardware_id"],
                device_uid=identifiers["device_uid"],
                instance_id=identifiers["instance_id"],
                environment=environment_info["environment"],
                environment_source=environment_info["source"],
                environment_evidence=environment_info["evidence"],
            )
        )

        profile["event_creation"] += time.perf_counter() - stage_start
        
    print(
        "TILI parser profile: "
        + " | ".join(
            f"{name}={duration:.3f}s"
            for name, duration in profile.items()
        ),
        flush=True,
    )

    return events
