from __future__ import annotations
import json,re
from pathlib import Path
from .models import Finding
DEFAULT_KB = Path("/var/lib/tili-kb/approved/knowledge_base.json")


def load_rules(path=None):
 with (Path(path) if path else DEFAULT_KB).open(encoding="utf-8") as f: return json.load(f)
def detect_findings(events, rules=None):
    rules = rules if rules is not None else load_rules()

    compiled = []

    # Compile each rule once and retain its original order.
    for index, rule in enumerate(rules):
        if rule.get("enabled", True) is False:
            continue

        try:
            pattern = re.compile(rule["pattern"], re.I)
            systems = rule.get("systems", ["ALL"])

            compiled.append((index, rule, pattern, systems))

        except (KeyError, re.error) as exc:
            raise ValueError(
                f"Invalid rule {rule.get('id', '<unknown>')}: {exc}"
            ) from exc

    findings = []

    # Check only the rules applicable to each event source.
    for event in events:
        applicable_rules = [
            (rule, pattern)
            for _, rule, pattern, systems in compiled
            if (
                "ALL" in systems
                or event.source in systems
                or (
                    "cHSM" in systems
                    and event.source == "HSM"
                    and str(event.instance_id).startswith("cHSM-")
                )
            )
        ]

        for rule, pattern in applicable_rules:
            if pattern.search(event.message):
                findings.append(Finding(
                    rule["id"],
                    event.source,
                    rule.get("severity", "HIGH"),
                    rule.get("title", rule["id"]),
                    rule.get("description", ""),
                    rule.get("recommendation", ""),
                    rule.get("confidence", "LOW"),
                    event.line_number,
                    event.file_name,
                    event.timestamp,
                    event.message,
                    rule.get("category", "General"),
                    event.hostname,
                    event.device_uid,
                    event.instance_id,
                    device_id=event.device_id,
                    konnektor_id=event.konnektor_id,
                    hardware_id=event.hardware_id
                ))

    return findings
