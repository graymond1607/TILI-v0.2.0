import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from tili.parsing import parse_lines, detect_source

def test_detect_hsm_from_signature():
    assert detect_source("0xB2010008 Unable transfer sync packet", "host.log") == "HSM"

def test_fast_parse_german_timestamp():
    from tili.parsing import parse_timestamp

    result = parse_timestamp("07.10.2026 13:38:19.214")

    assert result.year == 2026
    assert result.month == 10
    assert result.day == 7
    assert result.microsecond == 214000


def test_fast_parse_iso_timestamp():
    from tili.parsing import parse_timestamp

    result = parse_timestamp("2026-11-05 09:01:02.100")

    assert result.year == 2026
    assert result.month == 11
    assert result.day == 5
    assert result.microsecond == 100000


def test_fast_parse_iso_timezone():
    from tili.parsing import parse_timestamp

    result = parse_timestamp("2026-11-05T09:01:02.100Z")

    assert result.tzinfo is not None


def test_fast_parse_german_timestamp_without_fraction():
    from tili.parsing import parse_timestamp

    result = parse_timestamp("07.10.2026 13:38:19")

    assert result.second == 19
    assert result.microsecond == 0

def test_parse_timestamp_and_level():
    events = parse_lines("2026-11-05 09:01:02.100 ERROR [TIG] TLS handshake failed", "tig.log")
    assert len(events) == 1
    assert events[0].level == "ERROR"
    assert events[0].timestamp is not None
    assert events[0].component == "TIG"

def test_parse_german_timestamp_and_hsk_hostname():
    events = parse_lines("07.10.2026 13:38:19.214 ERROR [gSMC-K] HSKP012F 0xB2010008 cHSM #0 failed", "hsk.log")
    assert events[0].timestamp is not None
    assert events[0].hostname == "HSKP012F"
    assert events[0].instance_id == "cHSM-0"

def test_parse_all_six_identifier_types():
    log = """
2026-11-05 09:01:02.100 INFO hostname=HSKP012F
2026-11-05 09:01:03.100 INFO device_uid=123e4567-e89b-12d3-a456-426614174000
2026-11-05 09:01:04.100 INFO cHSM #0
2026-11-05 09:01:05.100 INFO konnektor_id=KON123456
2026-11-05 09:01:06.100 INFO hardware_id=HW-98765
2026-11-05 09:01:07.100 INFO instance_id=INST-001
"""
    events = parse_lines(log, "hsk.log")

    assert len(events) == 6
    assert events[0].hostname == "HSKP012F"
    assert events[1].device_uid == "123e4567-e89b-12d3-a456-426614174000"
    assert events[2].instance_id == "cHSM-0"
    assert events[3].konnektor_id == "KON123456"
    assert events[4].hardware_id == "HW-98765"
    assert events[5].instance_id == "INST-001"


def test_multiple_identifier_values_are_kept_per_event():
    log = """
INFO hardwareID-edf234EB
INFO hardwareID-edf297EE
INFO konnektor_id=361/12/34-1234567
INFO konnektor_id=361/56/78-7654321
"""
    events = parse_lines(log, "konnektor.log")

    assert [e.hardware_id for e in events if e.hardware_id != "Unknown"] == [
        "edf234EB", "edf297EE"
    ]

    assert [e.konnektor_id for e in events if e.konnektor_id != "Unknown"] == [
        "361/12/34-1234567", "361/56/78-7654321"
    ]


def test_missing_identifiers_do_not_block_parsing():
    events = parse_lines(
        "2026-11-05 09:01:02.100 ERROR [TIG] Connection failed",
        "tig.log",
    )

    assert len(events) == 1
    assert events[0].hostname == "Unknown"
    assert events[0].device_uid == "Unknown"
    assert events[0].device_id == "Unknown"
    assert events[0].konnektor_id == "Unknown"
    assert events[0].hardware_id == "Unknown"
    assert events[0].instance_id == "Unknown"

def test_detect_explicit_production_environment():
    events = parse_lines(
        "2026-11-05 09:01:02.100 INFO environment=Production",
        "production.log",
    )

    assert events[0].environment == "Production"
    assert events[0].environment_source == "Explicit log metadata"


def test_detect_explicit_test_environment():
    events = parse_lines(
        "2026-11-05 09:01:02.100 INFO env=Test/RU",
        "test.log",
    )

    assert events[0].environment == "Test/RU"
    assert events[0].environment_source == "Explicit log metadata"


def test_parse_without_environment_metadata():
    events = parse_lines(
        "2026-11-05 09:01:02.100 INFO Application started",
        "app.log",
    )

    assert len(events) == 1
    assert events[0].message.endswith("Application started")
    assert events[0].environment == ""
    assert events[0].environment_source == ""


def test_detect_vhsk_from_filename():
    assert detect_source("system startup", "vHSK_server.log") == "vHSK"


def test_detect_vhsk_from_log_content():
    assert detect_source("vHSK virtual host service started", "system.log") == "vHSK"


def test_detect_physical_hsk_from_filename():
    assert detect_source("system startup", "HSKP012F.log") == "HSK"


def test_detect_hsm_from_signature():
    assert detect_source("0xB2010008 Unable transfer sync packet", "host.log") == "HSM"


def test_detect_chsm_as_hsm():
    assert detect_source("cHSM #0 synchronisation failed", "system.log") == "HSM"
