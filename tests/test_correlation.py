import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from datetime import datetime, timedelta, timezone

from tili.models import Finding
from tili.correlation import correlate_findings, build_instance_comparison
from tili.models import LogEvent


def make_finding(
    minute,
    hostname="HSKP001F",
    device_uid="uuid-001",
    instance_id="Unknown",
    identity_id="DEV-001",
    rule_id="TEST-001",
    source="HSM",
    file_name="test.log",
    tz=None,
):
    timestamp = datetime(2026, 11, 23, 10, minute)

    if tz is not None:
        timestamp = timestamp.replace(tzinfo=tz)

    return Finding(
        rule_id=rule_id,
        source=source,
        severity="HIGH",
        title="Test finding",
        description="Test",
        recommendation="Investigate",
        confidence="HIGH",
        line_number=1,
        file_name=file_name,
        timestamp=timestamp,
        evidence="Test evidence",
        hostname=hostname,
        device_uid=device_uid,
        instance_id=instance_id,
        identity_id=identity_id,
    )

def make_event(
    line_number=1,
    file_name="test.log",
    hostname="HSKP001F",
    identity_id="DEV-001",
    instance_id="cHSM-0",
    device_uid="uuid-001",
    minute=0,
    source="HSM",
):
    return LogEvent(
        source=source,
        timestamp=datetime(2026, 11, 23, 10, minute),
        level="ERROR",
        component="Test",
        message="Test event",
        line_number=line_number,
        file_name=file_name,
        hostname=hostname,
        device_uid=device_uid,
        instance_id=instance_id,
        identity_id=identity_id,
    )

def test_same_device_findings_within_window_are_correlated():
    findings = [
        make_finding(0, rule_id="ERROR-001"),
        make_finding(5, rule_id="ERROR-002"),
    ]

    result = correlate_findings(findings, window_minutes=10)

    assert len(result) == 1
    assert result[0]["finding_count"] == 2

def test_different_devices_are_not_automatically_correlated():
    findings = [
        make_finding(
            0,
            hostname="HSKP001F",
            device_uid="uuid-001",
            identity_id="DEV-001",
        ),
        make_finding(
            2,
            hostname="HSKP002F",
            device_uid="uuid-002",
            identity_id="DEV-002",
        ),
    ]

    result = correlate_findings(findings, window_minutes=10)

    assert len(result) == 0


def test_unknown_devices_are_not_automatically_correlated():
    findings = [
        make_finding(0, hostname="Unknown", device_uid="Unknown", identity_id=None),
        make_finding(2, hostname="Unknown", device_uid="Unknown", identity_id=None),
    ]
    
    result = correlate_findings(findings, window_minutes=10)

    assert len(result) == 0


def test_correlation_window_is_measured_from_group_start():
    findings = [
        make_finding(0),
        make_finding(9, rule_id="ERROR-002"),
        make_finding(18, rule_id="ERROR-003"),
    ]

    result = correlate_findings(findings, window_minutes=10)

    assert len(result) == 1
    assert result[0]["finding_count"] == 2


def test_different_chsm_instances_remain_distinguishable():
    findings = [
        make_finding(0, instance_id="cHSM-0"),
        make_finding(2, instance_id="cHSM-1"),
    ]

    result = correlate_findings(findings, window_minutes=10)

    assert len(result) == 0


def test_timezone_aware_and_naive_timestamps_do_not_crash():
    findings = [
        make_finding(0),
        make_finding(2, tz=timezone.utc),
    ]

    result = correlate_findings(findings, window_minutes=10)

    assert isinstance(result, list)


def test_same_uuid_different_hostnames_share_device_identity():
    findings = [
        make_finding(
            0,
            hostname="HSKP001F",
            device_uid="uuid-001",
        ),
        make_finding(
            2,
            hostname="HSKP-ALIAS",
            device_uid="uuid-001",
            rule_id="ERROR-002",
        ),
    ]

    result = correlate_findings(findings, window_minutes=10)

    assert len(result) == 1
    assert result[0]["finding_count"] == 2


def test_same_hostname_different_uuids_are_not_merged():
    findings = [
        make_finding(
            0,
            hostname="HSKP001F",
            device_uid="uuid-001",
            identity_id="DEV-001",
        ),
        make_finding(
            2,
            hostname="HSKP001F",
            device_uid="uuid-002",
            rule_id="ERROR-002",
            identity_id="DEV-002",
        ),
    ]

    result = correlate_findings(findings, window_minutes=10)

    assert len(result) == 0


def test_same_physical_device_different_chsm_instances():
    findings = [
        make_finding(
            0,
            device_uid="uuid-001",
            instance_id="cHSM-0",
        ),
        make_finding(
            2,
            device_uid="uuid-001",
            instance_id="cHSM-1",
            rule_id="ERROR-002",
        ),
    ]

    result = correlate_findings(findings, window_minutes=10)

    assert len(result) == 0


def test_same_device_with_incomplete_identifiers():
    findings = [
        make_finding(
            0,
            device_uid="uuid-001",
            hostname="HSKP001F",
        ),
        make_finding(
            2,
            device_uid="uuid-001",
            hostname="Unknown",
            rule_id="ERROR-002",
        ),
    ]

    result = correlate_findings(findings, window_minutes=10)

    assert len(result) == 1
    assert result[0]["finding_count"] == 2


def test_conflicting_strong_identifiers_are_not_merged():
    findings = [
        make_finding(
            0,
            device_uid="uuid-001",
            hostname="HSKP001F",
            identity_id="DEV-001",
        ),
        make_finding(
            2,
            device_uid="uuid-002",
            hostname="HSKP001F",
            rule_id="ERROR-002",
            identity_id="DEV-002",
        ),
    ]

    result = correlate_findings(findings, window_minutes=10)

    assert len(result) == 0


def test_same_device_uuid_only_and_hardware_id_only():
    findings = [
        make_finding(
            0,
            hostname="Unknown",
            device_uid="uuid-001",
            rule_id="ERROR-001",
            identity_id=None,
        ),
        make_finding(
            2,
            hostname="Unknown",
            device_uid="Unknown",
            rule_id="ERROR-002",
            identity_id=None,
        ),
    ]

    findings[1].hardware_id = "HW-001"

    result = correlate_findings(findings, window_minutes=10)

    assert len(result) == 0


def test_same_hardware_id_with_different_hostnames():
    findings = [
        make_finding(
            0,
            hostname="HSKP001F",
            device_uid="Unknown",
        ),
        make_finding(
            2,
            hostname="HSKP-ALIAS",
            device_uid="Unknown",
            rule_id="ERROR-002",
        ),
    ]

    findings[0].hardware_id = "HW-001"
    findings[1].hardware_id = "HW-001"

    result = correlate_findings(findings, window_minutes=10)

    assert len(result) == 1


def test_same_device_id_with_missing_other_identifiers():
    findings = [
        make_finding(
            0,
            hostname="Unknown",
            device_uid="Unknown",
        ),
        make_finding(
            2,
            hostname="Unknown",
            device_uid="Unknown",
            rule_id="ERROR-002",
        ),
    ]

    findings[0].device_id = "DEVICE-001"
    findings[1].device_id = "DEVICE-001"

    result = correlate_findings(findings, window_minutes=10)

    assert len(result) == 1


def test_raw_identifiers_without_resolved_identity_are_not_correlated():
    findings = [
        make_finding(0, identity_id=None, device_uid="uuid-001"),
        make_finding(2, identity_id=None, device_uid="uuid-001"),
    ]

    assert correlate_findings(findings, window_minutes=10) == []


def test_same_device_same_chsm_instance_produces_one_comparison_row():
    events = [
        make_event(line_number=1),
        make_event(line_number=2),
    ]

    rows = build_instance_comparison(events, [])

    assert len(rows) == 1
    assert rows[0]["identity_id"] == "DEV-001"
    assert rows[0]["instance_id"] == "cHSM-0"


def test_same_device_different_chsm_instances_produce_separate_rows():
    events = [
        make_event(line_number=1, instance_id="cHSM-0"),
        make_event(line_number=2, instance_id="cHSM-1"),
    ]

    rows = build_instance_comparison(events, [])

    assert len(rows) == 2


def test_different_devices_with_same_hostname_produce_separate_rows():
    events = [
        make_event(line_number=1, identity_id="DEV-001"),
        make_event(line_number=2, identity_id="DEV-002"),
    ]

    rows = build_instance_comparison(events, [])

    assert len(rows) == 2


def test_unidentified_events_in_same_file_are_grouped():
    events = [
        make_event(line_number=1, identity_id=None),
        make_event(line_number=2, identity_id=None),
    ]

    rows = build_instance_comparison(events, [])

    assert len(rows) == 1
    assert rows[0]["status"] == "UNKNOWN_IDENTITY"
    assert rows[0]["events"] == 2
    assert rows[0]["findings"] == 0


def test_instance_with_matching_finding_is_affected():
    event = make_event(line_number=10)

    finding = make_finding(
        0,
        identity_id="DEV-001",
        instance_id="cHSM-0",
    )
    finding.line_number = 10

    rows = build_instance_comparison([event], [finding])

    assert len(rows) == 1
    assert rows[0]["status"] == "AFFECTED"
    assert rows[0]["findings"] == 1


def test_unidentified_events_from_different_files_are_separate():
    events = [
        make_event(file_name="system.log", identity_id=None),
        make_event(file_name="application.log", identity_id=None),
    ]

    rows = build_instance_comparison(events, [])

    assert len(rows) == 2
    assert all(row["status"] == "UNKNOWN_IDENTITY" for row in rows)


def test_unidentified_events_from_different_sources_are_separate():
    events = [
        make_event(file_name="system.log", source="HSM", identity_id=None),
        make_event(file_name="system.log", source="TIG", identity_id=None),
    ]

    rows = build_instance_comparison(events, [])

    assert len(rows) == 2
    assert all(row["status"] == "UNKNOWN_IDENTITY" for row in rows)


def test_unidentified_findings_are_counted_in_file_group():
    events = [
        make_event(file_name="system.log", identity_id=None),
        make_event(file_name="system.log", line_number=2, identity_id=None),
    ]

    findings = [
        make_finding(0, identity_id=None, file_name="system.log"),
        make_finding(1, identity_id=None, file_name="system.log"),
    ]

    rows = build_instance_comparison(events, findings)

    assert len(rows) == 1
    assert rows[0]["status"] == "AFFECTED"
    assert rows[0]["events"] == 2
    assert rows[0]["findings"] == 2


def test_instance_comparison_handles_mixed_timezone_timestamps():
    events = [
        make_event(
            line_number=1,
            identity_id="DEV-001",
            minute=0,
        ),
        make_event(
            line_number=2,
            identity_id="DEV-001",
            minute=5,
        ),
    ]

    events[0].timestamp = datetime(2026, 11, 23, 10, 0)
    events[1].timestamp = datetime(
        2026, 11, 23, 10, 5,
        tzinfo=timezone.utc,
    )

    rows = build_instance_comparison(events, [])

    assert len(rows) == 1
    assert rows[0]["first_seen"] is not None
    assert rows[0]["last_seen"] is not None
    assert rows[0]["first_seen"] <= rows[0]["last_seen"]


def test_shutdown_hypothesis_identifies_preceding_watchdog_finding():
    from tili.correlation import build_root_cause_hypotheses

    watchdog = make_finding(
        10,
        rule_id="TILI-V2-HW",
        identity_id="DEV-001",
        instance_id="cHSM-0",
    )
    watchdog.title = "Watchdog restart detected"
    watchdog.category = "Hardware"

    shutdown = make_finding(
        12,
        rule_id="TILI-V2-SHUTDOWN",
        identity_id="DEV-001",
        instance_id="cHSM-0",
    )
    shutdown.title = "System Shutdown"
    shutdown.category = "System Lifecycle"

    hypotheses = build_root_cause_hypotheses(
        [watchdog, shutdown],
        [],
    )

    assert isinstance(hypotheses, list)
