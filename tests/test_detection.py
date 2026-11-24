import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from tili.parsing import parse_lines
from tili.detection import detect_findings
from tili.models import LogEvent

def test_hsm_sync_rule_matches():
    events = parse_lines("2026-11-05 09:12:01 ERROR [gSMC-K] 0xB2010008 sync failed", "hsm.log")
    findings = detect_findings(events)
    assert any(f.rule_id == "TILI-HSM-SYNC-001" for f in findings)

def test_tig_tls_rule_matches():
    events = parse_lines("2026-11-05 09:08:03 ERROR [TIG] TLS handshake failed", "tig.log")
    findings = detect_findings(events)
    assert any(f.rule_id == "TILI-TIG-TLS-001" for f in findings)

def test_security_rule_matches():
    events = parse_lines("2026-11-05 09:12:01 ERROR [CryptoServer] secure messaging failed 0xB2010056", "hsm.log")
    findings = detect_findings(events)
    assert any(f.category == "Security" for f in findings)

def test_network_and_dns_rule_categories():
    events = parse_lines("2026-11-05 09:12:01 ERROR DNS_NAME_RESOLUTION_ERROR could not resolve host", "ebk.log")
    findings = detect_findings(events)
    assert any(f.category == "DNS" for f in findings)

def test_chsm_rule_matches_chsm_instance():
    event = LogEvent(
        source="HSM",
        timestamp=None,
        level="ERROR",
        component="gSMC-K",
        message="cHSM diagnostic marker",
        line_number=1,
        file_name="hsm.log",
        instance_id="cHSM-0",
    )

    rules = [{
        "id": "TEST-CHSM-001",
        "systems": ["cHSM"],
        "pattern": "cHSM diagnostic marker",
        "title": "cHSM test",
    }]

    findings = detect_findings([event], rules)
    assert len(findings) == 1


def test_chsm_rule_does_not_match_other_hsm_instance():
    event = LogEvent(
        source="HSM",
        timestamp=None,
        level="ERROR",
        component="gSMC-K",
        message="cHSM diagnostic marker",
        line_number=1,
        file_name="hsm.log",
        instance_id="HSM-1",
    )

    rules = [{
        "id": "TEST-CHSM-001",
        "systems": ["cHSM"],
        "pattern": "cHSM diagnostic marker",
        "title": "cHSM test",
    }]

    findings = detect_findings([event], rules)
    assert len(findings) == 0


def test_hsm_rule_still_matches_chsm_instance():
    event = LogEvent(
        source="HSM",
        timestamp=None,
        level="ERROR",
        component="gSMC-K",
        message="HSM diagnostic marker",
        line_number=1,
        file_name="hsm.log",
        instance_id="cHSM-0",
    )

    rules = [{
        "id": "TEST-HSM-001",
        "systems": ["HSM"],
        "pattern": "HSM diagnostic marker",
        "title": "HSM test",
    }]

    findings = detect_findings([event], rules)
    assert len(findings) == 1


def test_enabled_rule_matches():
    event = LogEvent(
        source="HSM",
        timestamp=None,
        level="ERROR",
        component="gSMC-K",
        message="activation test marker",
        line_number=1,
        file_name="hsm.log",
    )

    rules = [{
        "id": "TEST-ACTIVE-001",
        "systems": ["HSM"],
        "pattern": "activation test marker",
        "title": "Active test",
        "enabled": True,
    }]

    findings = detect_findings([event], rules)
    assert len(findings) == 1


def test_disabled_rule_does_not_match():
    event = LogEvent(
        source="HSM",
        timestamp=None,
        level="ERROR",
        component="gSMC-K",
        message="deactivation test marker",
        line_number=1,
        file_name="hsm.log",
    )

    rules = [{
        "id": "TEST-INACTIVE-001",
        "systems": ["HSM"],
        "pattern": "deactivation test marker",
        "title": "Inactive test",
        "enabled": False,
    }]

    findings = detect_findings([event], rules)
    assert len(findings) == 0


def test_legacy_rule_without_enabled_field_still_matches():
    event = LogEvent(
        source="HSM",
        timestamp=None,
        level="ERROR",
        component="gSMC-K",
        message="legacy rule marker",
        line_number=1,
        file_name="hsm.log",
    )

    rules = [{
        "id": "TEST-LEGACY-001",
        "systems": ["HSM"],
        "pattern": "legacy rule marker",
        "title": "Legacy test",
    }]

    findings = detect_findings([event], rules)
    assert len(findings) == 1
