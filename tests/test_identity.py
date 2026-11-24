import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from types import SimpleNamespace
from tili.identity import resolve_device_identities


def event(**kwargs):
    defaults = {
        "device_uid": "Unknown",
        "konnektor_id": "Unknown",
        "hardware_id": "Unknown",
        "device_id": "Unknown",
        "hostname": "Unknown",
        "instance_id": "Unknown",
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_same_strong_identifier_resolves_same_device():
    events = [
        event(device_uid="UUID-001"),
        event(device_uid="UUID-001", hostname="HSKP001F"),
    ]

    result = resolve_device_identities(events)

    assert result[0]["identity_id"] == result[1]["identity_id"]


def test_identifiers_link_through_same_event():
    events = [
        event(device_uid="UUID-001", hardware_id="HW-001"),
        event(hardware_id="HW-001", device_id="DEV-001"),
        event(device_id="DEV-001"),
    ]

    result = resolve_device_identities(events)

    assert len({item["identity_id"] for item in result}) == 1


def test_hostname_alone_does_not_link_devices():
    events = [
        event(hostname="HSKP001F"),
        event(hostname="HSKP001F"),
    ]

    result = resolve_device_identities(events)

    assert result[0]["identity_id"] is None
    assert result[1]["identity_id"] is None


def test_different_uuids_are_not_merged_by_hostname():
    events = [
        event(device_uid="UUID-001", hostname="HSKP001F"),
        event(device_uid="UUID-002", hostname="HSKP001F"),
    ]

    result = resolve_device_identities(events)

    assert result[0]["identity_id"] != result[1]["identity_id"]


def test_conflicting_identifier_chain_is_rejected():
    events = [
        event(device_uid="UUID-001", hardware_id="HW-001"),
        event(device_uid="UUID-002", hardware_id="HW-001"),
    ]

    result = resolve_device_identities(events)

    assert all(item["identity_id"] is None for item in result)


def test_different_instances_share_physical_identity():
    events = [
        event(device_uid="UUID-001", instance_id="cHSM-1"),
        event(device_uid="UUID-001", instance_id="cHSM-2"),
    ]

    result = resolve_device_identities(events)

    assert result[0]["identity_id"] == result[1]["identity_id"]
    assert result[0]["instance_id"] != result[1]["instance_id"]


def test_unknown_identifiers_remain_unidentified():
    events = [
        event(),
        event(),
    ]

    result = resolve_device_identities(events)

    assert all(item["identity_id"] is None for item in result)


def test_identifier_matching_is_case_sensitive():
    events = [
        event(device_uid="UUID-001"),
        event(device_uid="uuid-001"),
    ]

    result = resolve_device_identities(events)

    assert result[0]["identity_id"] != result[1]["identity_id"]


def test_transitive_conflict_invalidates_entire_chain():
    events = [
        event(device_uid="UUID-001", hardware_id="HW-001"),
        event(hardware_id="HW-001", device_id="DEV-001"),
        event(device_uid="UUID-002", device_id="DEV-001"),
    ]

    result = resolve_device_identities(events)

    assert all(item["identity_id"] is None for item in result)


def test_repeated_identifier_evidence_does_not_create_conflict():
    events = [
        event(device_uid="UUID-001", hardware_id="HW-001"),
        event(device_uid="UUID-001", hardware_id="HW-001"),
        event(device_uid="UUID-001"),
    ]

    result = resolve_device_identities(events)

    assert len({item["identity_id"] for item in result}) == 1
    assert result[0]["identity_id"] is not None


def test_identity_resolution_is_independent_of_event_order():
    events = [
        event(device_uid="UUID-001", hardware_id="HW-001"),
        event(hardware_id="HW-001", device_id="DEV-001"),
        event(device_id="DEV-001"),
    ]

    original = resolve_device_identities(events)
    reordered = resolve_device_identities(list(reversed(events)))

    assert len({item["identity_id"] for item in original}) == 1
    assert len({item["identity_id"] for item in reordered}) == 1
    assert original[0]["identity_id"] == reordered[2]["identity_id"]
