
import json
import pandas as pd

from .ai.redaction import EvidenceRedactor


def _redact_report_value(value, redactor):
    """Recursively redact secrets without pseudonymising identifiers."""

    if isinstance(value, str):
        return redactor.redact_secrets(value)

    if isinstance(value, dict):
        return {
            key: _redact_report_value(item, redactor)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            _redact_report_value(item, redactor)
            for item in value
        ]

    return value


def findings_dataframe(findings):
    """Build a report DataFrame, preserving identifiers and masking secrets."""

    redactor = EvidenceRedactor()
    rows = []

    for finding in findings:
        row = {
            "source": finding.source,
            "category": finding.category,
            "severity": finding.severity,
            "rule_id": finding.rule_id,
            "title": finding.title,
            "hostname": finding.hostname,
            "device_uid": finding.device_uid,
            "identity_id": finding.identity_id,
            "instance_id": finding.instance_id,
            "file": finding.file_name,
            "line": finding.line_number,
            "timestamp": (
                finding.timestamp.isoformat()
                if finding.timestamp else ""
            ),
            "confidence": finding.confidence,
            "evidence": finding.evidence,
            "recommendation": finding.recommendation,
        }

        rows.append(_redact_report_value(row, redactor))

    return pd.DataFrame(rows)


def report_json(result):
    """Build a JSON report, preserving identifiers and masking secrets."""

    report = {
        "summary": result["summary"],
        "findings": [
            finding.to_dict()
            for finding in result["findings"]
        ],
        "correlations": result["correlations"],
        "instances": result.get("instances", []),
        "frequency": result.get("frequency", []),
        "hypotheses": result.get("hypotheses", []),
        "events": [
            event.to_dict()
            for event in result["events"]
        ],
    }

    redacted_report = _redact_report_value(
        report,
        EvidenceRedactor(),
    )

    return json.dumps(
        redacted_report,
        indent=2,
        ensure_ascii=False,
        default=str,
    )
