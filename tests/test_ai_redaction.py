
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tili.ai.redaction import EvidenceRedactor


def test_redacts_passwords_and_tokens():
    redactor = EvidenceRedactor()

    text = (
        "password=Secret123 "
        "access_token=abc123 "
        "api_key=key987"
    )

    result = redactor.redact_text(text)

    assert "Secret123" not in result
    assert "abc123" not in result
    assert "key987" not in result
    assert result.count("[REDACTED]") == 3


def test_preserves_diagnostic_information():
    redactor = EvidenceRedactor()

    text = (
        "2026-11-05 09:12:01 ERROR "
        "[gSMC-K] 0xB2010008 cHSM-0 sync failed"
    )

    result = redactor.redact_text(text)

    assert "2026-11-05 09:12:01" in result
    assert "ERROR" in result
    assert "0xB2010008" in result
    assert "cHSM-0" in result


def test_pseudonymises_identifiers_consistently():
    redactor = EvidenceRedactor()

    text = (
        "device_uid=123e4567-e89b-12d3-a456-426614174000 "
        "device_uid=123e4567-e89b-12d3-a456-426614174000"
    )

    result = redactor.redact_text(text)

    assert "123e4567-e89b-12d3-a456-426614174000" not in result
    assert result.count("[DEVICE_UID_001]") == 2


def test_pseudonymises_email_addresses():
    redactor = EvidenceRedactor()

    result = redactor.redact_text(
        "user contacted support@example.com"
    )

    assert "support@example.com" not in result
    assert "[EMAIL_001]" in result


def test_redacts_private_key_blocks():
    redactor = EvidenceRedactor()

    text = (
        "-----BEGIN PRIVATE KEY-----\n"
        "SECRET_PRIVATE_KEY_CONTENT\n"
        "-----END PRIVATE KEY-----"
    )

    result = redactor.redact_text(text)

    assert "SECRET_PRIVATE_KEY_CONTENT" not in result
    assert "[REDACTED_PRIVATE_KEY]" in result


def test_does_not_modify_original_text():
    redactor = EvidenceRedactor()

    original = "password=Secret123"

    redactor.redact_text(original)

    assert original == "password=Secret123"


def test_rejects_non_string_evidence():
    redactor = EvidenceRedactor()

    try:
        redactor.redact_text(None)
        assert False, "Expected TypeError"
    except TypeError:
        pass


def test_redacts_json_secrets():
    redactor = EvidenceRedactor()

    text = (
        '{"password": "Secret123", '
        '"access_token": "abc123", '
        '"api_key": "key987"}'
    )

    result = redactor.redact_text(text)

    assert "Secret123" not in result
    assert "abc123" not in result
    assert "key987" not in result


def test_pseudonymises_json_device_identifiers():
    redactor = EvidenceRedactor()

    text = (
        '{"device_uid": '
        '"123e4567-e89b-12d3-a456-426614174000"}'
    )

    result = redactor.redact_text(text)

    assert "123e4567-e89b-12d3-a456-426614174000" not in result
    assert "[DEVICE_UID_001]" in result

def test_redacts_metadata_identifiers():
    redactor = EvidenceRedactor()

    metadata = {
        "hostname": "HSKP012F",
        "device_uid": "123e4567-e89b-12d3-a456-426614174000",
        "instance_id": "cHSM-0",
        "hardware_id": "HW-98765",
        "line_number": 125,
        "timestamp": "2026-11-05T09:12:01",
        "severity": "HIGH",
        "rule_id": "TILI-HSM-SYNC-001",
    }

    result = redactor.redact_metadata(metadata)

    assert result["hostname"] != "HSKP012F"
    assert result["device_uid"] != metadata["device_uid"]
    assert result["instance_id"] == "cHSM-0"
    assert result["hardware_id"] != "HW-98765"
    assert result["line_number"] == 125
    assert result["timestamp"] == "2026-11-05T09:12:01"
    assert result["severity"] == "HIGH"
    assert result["rule_id"] == "TILI-HSM-SYNC-001"


def test_redacts_sensitive_filename():
    redactor = EvidenceRedactor()

    result = redactor.redact_metadata({
        "file_name": "Customer123_HSKP012F.log"
    })

    assert result["file_name"].endswith(".log")
    assert "Customer123" not in result["file_name"]
    assert "HSKP012F" not in result["file_name"]
