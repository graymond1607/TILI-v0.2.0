import sys
from pathlib import Path
from datetime import date
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from tili.inventory.certificate_monitor import extract_card_validity

def test_expired_card_is_detected():
    docs = [("cards.log", "SMC-B certificate valid until: 01.01.2020 ICCSN=123456789")]
    rows = extract_card_validity(docs, as_of=date(2026, 11, 9))
    assert len(rows) == 1
    assert rows[0].status == "EXPIRED"
    assert "[REDACTED]" in rows[0].evidence

def test_future_expiry_is_valid():
    docs = [("cards.log", "HBA notAfter=2030-12-31T23:59:59Z")]
    rows = extract_card_validity(docs, as_of=date(2026, 11, 9))
    assert rows[0].status == "VALID"

def test_unlabelled_date_is_not_assumed_expiry():
    docs = [("cards.log", "SMC-K card inserted 01.01.2020")]
    assert extract_card_validity(docs, as_of=date(2026, 11, 9)) == []
