\
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from datetime import date, datetime, timezone
from typing import Optional
from dateutil import parser as date_parser

# These expressions intentionally require an explicit validity/expiry label.
# They do not treat an arbitrary date in a log line as a certificate expiry.
EXPIRY_PATTERNS = [
    re.compile(r"(?i)(?:notAfter|valid\s+until|validity\s+end|expires?\s+at|expiry\s+date|expiration\s+date)\s*[:=]\s*([0-9]{4}-[0-9]{2}-[0-9]{2}(?:[T ][0-9:.+-]+Z?)?)"),
    re.compile(r"(?i)(?:valid\s+until|expires?\s+at|expiry\s+date|expiration\s+date|Ablaufdatum|gültig\s+bis|gueltig\s+bis|Zertifikat\s+gültig\s+bis)\s*[:=]?\s*([0-9]{2}\.[0-9]{2}\.[0-9]{4}(?:\s+[0-9:]+)?)"),
]
CARD_RE = re.compile(r"(?i)\b(SMC-B|SMC-K|SMC-KT|HBA|gSMC-K)\b")
CARD_REF_RE = re.compile(r"(?i)\b(?:ICCSN|ICCSN|card(?:\s+id)?|karten(?:nummer)?)\s*[=: ]\s*([A-Za-z0-9_-]{4,})")

@dataclass
class CardValidity:
    card_type: str
    expiry_date: Optional[str]
    status: str
    source_file: str
    line_number: int
    evidence: str
    confidence: str

    def to_dict(self):
        return asdict(self)

def _parse_date(value: str) -> Optional[date]:
    try:
        return date_parser.parse(value, dayfirst="." in value).date()
    except (ValueError, OverflowError, TypeError):
        return None

def extract_card_validity(documents, as_of: Optional[date] = None):
    """Extract card validity only when a labelled expiry/notAfter date is present.

    Status values: EXPIRED, VALID, UNKNOWN. Expiry is evaluated by calendar date.
    A date-only notAfter value is treated as valid through that date; it becomes
    expired on the following date. No card serial/ICCSN is retained or displayed.
    """
    as_of = as_of or datetime.now(timezone.utc).date()
    records = []
    seen = set()
    for filename, text in documents:
        for line_no, line in enumerate(text.splitlines(), 1):
            card = CARD_RE.search(line)
            if not card:
                continue
            for pattern in EXPIRY_PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue
                expiry = _parse_date(match.group(1))
                if expiry is None:
                    continue
                status = "EXPIRED" if expiry < as_of else "VALID"
                # Keep the evidence privacy-safe: remove likely card identifiers.
                safe_evidence = CARD_REF_RE.sub(r"\1=[REDACTED]", line.strip())
                key = (card.group(1).upper(), expiry.isoformat(), filename, line_no)
                if key in seen:
                    continue
                seen.add(key)
                records.append(CardValidity(
                    card_type=card.group(1).upper(),
                    expiry_date=expiry.isoformat(),
                    status=status,
                    source_file=filename,
                    line_number=line_no,
                    evidence=safe_evidence,
                    confidence="EXPLICIT — labelled expiry date extracted from log"
                ))
                break
    return records

def card_validity_summary(records):
    return {
        "expired": sum(r.status == "EXPIRED" for r in records),
        "valid": sum(r.status == "VALID" for r in records),
        "unknown": sum(r.status == "UNKNOWN" for r in records),
    }
