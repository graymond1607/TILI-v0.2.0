
from collections import Counter
import time
from .parsing import parse_lines
from .detection import detect_findings
from .identity import resolve_device_identities
from .correlation import (
    correlate_findings,
    build_instance_comparison,
    error_frequency,
    build_root_cause_hypotheses,
)


IDENTIFIER_FIELDS = {
    "Hostname / HSKP": "hostname",
    "Device UUID": "device_uid",
    "cHSM / Instance": "instance_id",
    "Konnektor serial number": "konnektor_id",
    "Hardware ID": "hardware_id",
    "Device ID": "device_id",
}


def build_identifier_inventory(events):
    """Collect distinct identifiers and retain their source evidence."""

    inventory = []

    for label, field in IDENTIFIER_FIELDS.items():
        collected = {}
        seen_evidence = {}

        for event in events:
            value = getattr(event, field, "Unknown")

            if not value or value == "Unknown":
                continue

            timestamp = event.timestamp
            if hasattr(timestamp, "isoformat"):
                timestamp = timestamp.isoformat()

            evidence = {
                "file": event.file_name,
                "line": event.line_number,
                "timestamp": timestamp,
            }

            if value not in collected:
                collected[value] = []
                seen_evidence[value] = set()

            evidence_key = (
                evidence["file"],
                evidence["line"],
                evidence["timestamp"],
            )

            if evidence_key not in seen_evidence[value]:
                collected[value].append(evidence)
                seen_evidence[value].add(evidence_key)

        if not collected:
            inventory.append({
                "identifier_type": label,
                "value": "Not found",
                "occurrences": 0,
                "evidence": [],
            })
            continue

        for value, evidence in collected.items():
            inventory.append({
                "identifier_type": label,
                "value": value,
                "occurrences": len(evidence),
                "evidence": evidence,
            })

    return inventory


def analyse_documents(
    documents,
    correlation_window_minutes=10,
    parsed_documents=None,
):
    timings = {}

    # Parse documents only when pre-parsed events are not provided.
    if parsed_documents is None:
        parse_start = time.perf_counter()
        parsed_documents = []

        for filename, text in documents:
            events = parse_lines(text, filename)
            parsed_documents.append((filename, events))

        timings["parsing"] = time.perf_counter() - parse_start

    all_events = []
    all_findings = []

    # Collect all events before resolving identities across documents.
    for filename, events in parsed_documents:
        all_events.extend(events)

    # Resolve physical device identities using strong identifiers only.
    identity_results = resolve_device_identities(all_events)

    for event, identity in zip(all_events, identity_results):
        event.identity_id = identity["identity_id"]

    # Finding detection, keeping findings separated by document.
    detection_start = time.perf_counter()

    for filename, events in parsed_documents:
        findings = detect_findings(events)

        for finding in findings:
            matching_events = [
                event for event in events
                if (
                    event.file_name == finding.file_name
                    and event.line_number == finding.line_number
                )
            ]

            matching_identities = {
                event.identity_id for event in matching_events
                if event.identity_id is not None
            }

            if len(matching_identities) == 1:
                finding.identity_id = next(iter(matching_identities))

        all_findings.extend(findings)

    timings["finding_detection"] = time.perf_counter() - detection_start

    severity_counts = Counter(f.severity for f in all_findings)
    source_counts = Counter(e.source for e in all_events)

    # Instance comparison.
    instance_start = time.perf_counter()
    instances = build_instance_comparison(all_events, all_findings)
    timings["instance_comparison"] = time.perf_counter() - instance_start

    # Root-cause hypotheses.
    hypothesis_start = time.perf_counter()
    hypotheses = build_root_cause_hypotheses(all_findings, instances)
    timings["root_cause_hypotheses"] = time.perf_counter() - hypothesis_start

    # Identifier inventory.
    inventory_start = time.perf_counter()
    identifier_inventory = build_identifier_inventory(all_events)
    timings["identifier_inventory"] = time.perf_counter() - inventory_start

    # Correlation.
    correlation_start = time.perf_counter()
    correlations = correlate_findings(
        all_findings, correlation_window_minutes
    )
    timings["correlation"] = time.perf_counter() - correlation_start

    # Error frequency.
    frequency_start = time.perf_counter()
    frequency = error_frequency(all_findings)
    timings["error_frequency"] = time.perf_counter() - frequency_start

    return {
        "events": all_events,
        "findings": all_findings,
        "correlations": correlations,
        "instances": instances,
        "identifier_inventory": identifier_inventory,
        "frequency": frequency,
        "hypotheses": hypotheses,
        "timings": timings,
        "summary": {
            "files": len(documents),
            "events": len(all_events),
            "findings": len(all_findings),
            "critical": severity_counts.get("CRITICAL", 0),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0),
            "sources": dict(source_counts),
        },
    }
