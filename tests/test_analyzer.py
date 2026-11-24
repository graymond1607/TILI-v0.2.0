import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tili.models import LogEvent
from tili.analyzer import analyse_documents


def make_event(
    line_number,
    device_uid="Unknown",
    hardware_id="Unknown",
    device_id="Unknown",
    hostname="Unknown",
    instance_id="Unknown",
):
    return LogEvent(
        source="HSM",
        timestamp=datetime(2026, 11, 24, 10, line_number % 60),
        level="ERROR",
        component="gSMC-K",
        message="Test diagnostic failure",
        line_number=line_number,
        file_name="test.log",
        hostname=hostname,
        device_uid=device_uid,
        hardware_id=hardware_id,
        device_id=device_id,
        instance_id=instance_id,
    )


def test_analyzer_resolves_identity_from_shared_event_evidence(monkeypatch):
    events = [
        make_event(1, device_uid="UUID-001", hardware_id="HW-001"),
        make_event(2, hardware_id="HW-001", device_id="DEV-001"),
    ]

    monkeypatch.setattr(
        "tili.analyzer.detect_findings",
        lambda events: [],
    )

    result = analyse_documents(
        [("test.log", "")],
        parsed_documents=[("test.log", events)],
    )

    assert result["events"][0].identity_id is not None
    assert (
        result["events"][0].identity_id
        == result["events"][1].identity_id
    )


def test_analyzer_does_not_merge_devices_with_conflicting_uuids(monkeypatch):
    events = [
        make_event(1, device_uid="UUID-001", hostname="HSKP001F"),
        make_event(2, device_uid="UUID-002", hostname="HSKP001F"),
    ]

    monkeypatch.setattr(
        "tili.analyzer.detect_findings",
        lambda events: [],
    )

    result = analyse_documents(
        [("test.log", "")],
        parsed_documents=[("test.log", events)],
    )

    assert all(event.identity_id is not None for event in result["events"])
    assert (
        result["events"][0].identity_id
        != result["events"][1].identity_id
    )


def test_analyzer_leaves_unknown_devices_unidentified(monkeypatch):
    events = [
        make_event(1, hostname="HSKP001F"),
        make_event(2, hostname="HSKP001F"),
    ]

    monkeypatch.setattr(
        "tili.analyzer.detect_findings",
        lambda events: [],
    )

    result = analyse_documents(
        [("test.log", "")],
        parsed_documents=[("test.log", events)],
    )

    assert all(event.identity_id is None for event in result["events"])


def test_analyzer_preserves_separate_chsm_instances(monkeypatch):
    events = [
        make_event(1, device_uid="UUID-001", instance_id="cHSM-0"),
        make_event(2, device_uid="UUID-001", instance_id="cHSM-1"),
    ]

    monkeypatch.setattr(
        "tili.analyzer.detect_findings",
        lambda events: [],
    )

    result = analyse_documents(
        [("test.log", "")],
        parsed_documents=[("test.log", events)],
    )

    assert (
        result["events"][0].identity_id
        == result["events"][1].identity_id
    )
    assert (
        result["events"][0].instance_id
        != result["events"][1].instance_id
    )
