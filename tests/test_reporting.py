
import json
from datetime import datetime

from tili.models import Finding, LogEvent
from tili.reporting import findings_dataframe, report_json


def make_test_data():
    timestamp = datetime(2026, 11, 20, 10, 30, 0)

    finding = Finding(
        rule_id="TILI-HSM-SYNC-001",
        source="HSK",
        severity="HIGH",
        title="HSM synchronisation error",
        description="Synchronisation failed",
        recommendation="Investigate HSM synchronisation",
        confidence="MEDIUM",
        line_number=125,
        file_name="Customer123_HSKP012F.log",
        timestamp=timestamp,
        evidence=(
            "host=HSKP012F password=Secret123 "
            "token=abc123 api_key=key456"
        ),
        category="HSM",
        hostname="HSKP012F",
        device_uid="123e4567-e89b-12d3-a456-426614174000",
        instance_id="cHSM-0",
        device_id="DEVICE-123",
        konnektor_id="KONNEKTOR-456",
        hardware_id="HW-98765",
    )

    event = LogEvent(
        source="HSK",
        timestamp=timestamp,
        level="ERROR",
        component="gSMC-K",
        message=(
            "Synchronisation failed password=Secret123 "
            "token=abc123 api_key=key456"
        ),
        line_number=125,
        file_name="Customer123_HSKP012F.log",
        hostname="HSKP012F",
        device_id="DEVICE-123",
        konnektor_id="KONNEKTOR-456",
        hardware_id="HW-98765",
        device_uid="123e4567-e89b-12d3-a456-426614174000",
        instance_id="cHSM-0",
    )

    result = {
        "summary": {"files": 1, "events": 1, "findings": 1},
        "findings": [finding],
        "events": [event],
        "correlations": [],
        "instances": [],
        "frequency": [],
        "hypotheses": [],
    }

    return finding, event, result


def test_csv_preserves_infrastructure_identifiers_and_masks_secrets():
    finding, _, _ = make_test_data()

    dataframe = findings_dataframe([finding])
    row = dataframe.iloc[0]

    assert row["hostname"] == "HSKP012F"
    assert row["device_uid"] == "123e4567-e89b-12d3-a456-426614174000"
    assert row["instance_id"] == "cHSM-0"
    assert row["file"] == "Customer123_HSKP012F.log"

    assert "Secret123" not in row["evidence"]
    assert "abc123" not in row["evidence"]
    assert "key456" not in row["evidence"]


def test_json_preserves_infrastructure_identifiers_and_masks_secrets():
    finding, event, result = make_test_data()

    report = json.loads(report_json(result))

    exported_finding = report["findings"][0]
    exported_event = report["events"][0]

    assert exported_finding["hostname"] == "HSKP012F"
    assert exported_finding["device_uid"] == "123e4567-e89b-12d3-a456-426614174000"
    assert exported_finding["instance_id"] == "cHSM-0"
    assert exported_finding["hardware_id"] == "HW-98765"
    assert exported_finding["file_name"] == "Customer123_HSKP012F.log"

    assert "Secret123" not in exported_finding["evidence"]
    assert "abc123" not in exported_finding["evidence"]
    assert "key456" not in exported_finding["evidence"]

    assert "Secret123" not in exported_event["message"]
    assert "abc123" not in exported_event["message"]
    assert "key456" not in exported_event["message"]


def test_reporting_does_not_modify_original_analysis_data():
    finding, event, result = make_test_data()

    original_finding_evidence = finding.evidence
    original_event_message = event.message

    findings_dataframe([finding])
    report_json(result)

    assert finding.evidence == original_finding_evidence
    assert event.message == original_event_message



def test_report_redacts_private_keys_and_authentication_headers():
    from tili.ai.redaction import EvidenceRedactor

    redactor = EvidenceRedactor()

    evidence = (
        "Authorization: Bearer abc.def.123\n"
        "Basic dXNlcjpwYXNzd29yZA==\n"
        "-----BEGIN PRIVATE KEY-----\n"
        "SECRET_PRIVATE_KEY_CONTENT\n"
        "-----END PRIVATE KEY-----"
    )

    result = redactor.redact_secrets(evidence)

    assert "abc.def.123" not in result
    assert "dXNlcjpwYXNzd29yZA==" not in result
    assert "SECRET_PRIVATE_KEY_CONTENT" not in result
    assert "[REDACTED_PRIVATE_KEY]" in result


def test_json_report_redacts_nested_secrets_and_preserves_diagnostic_codes():
    _, _, result = make_test_data()

    result["correlations"] = [{
        "evidence": [
            "Error 0xB2010008 password=NestedSecret123"
        ]
    }]

    result["hypotheses"] = [{
        "description": "token=HypothesisSecret456",
        "evidence": "cHSM-0 reported error 0xB2010008",
    }]

    report = json.loads(report_json(result))

    correlation_text = json.dumps(report["correlations"])
    hypothesis_text = json.dumps(report["hypotheses"])

    assert "NestedSecret123" not in correlation_text
    assert "HypothesisSecret456" not in hypothesis_text

    assert "0xB2010008" in correlation_text
    assert "0xB2010008" in hypothesis_text
    assert "cHSM-0" in hypothesis_text


def test_csv_export_preserves_resolved_identity():
    finding, _, _ = make_test_data()
    finding.identity_id = "DEV-ABC123"

    dataframe = findings_dataframe([finding])

    assert dataframe.iloc[0]["identity_id"] == "DEV-ABC123"


def test_json_export_preserves_resolved_identity():
    finding, event, result = make_test_data()

    finding.identity_id = "DEV-ABC123"
    event.identity_id = "DEV-ABC123"

    report = json.loads(report_json(result))

    assert report["findings"][0]["identity_id"] == "DEV-ABC123"
    assert report["events"][0]["identity_id"] == "DEV-ABC123"
