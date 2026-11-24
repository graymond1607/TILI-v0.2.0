from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

def correlate_findings(findings, window_minutes=10):
    """
    Correlate findings belonging to the same identified device and instance.

    Naive timestamps are interpreted in Europe/Berlin.
    Unknown identities are not automatically correlated.
    The time window is measured from the first finding in each group.
    """

    if window_minutes < 0:
        raise ValueError("window_minutes cannot be negative.")

    local_timezone = ZoneInfo("Europe/Berlin")

    def normalize_timestamp(timestamp):
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=local_timezone)

        return timestamp.astimezone(timezone.utc)

    def identity_key(finding):
        identity = getattr(finding, "identity_id", None)

        if not identity or identity == "Unknown":
            return None

        instance = finding.instance_id
        instance = (
            instance
            if instance and instance != "Unknown"
            else None
        )

        return identity, instance

    by_identity = defaultdict(list)

    for finding in findings:
        if finding.timestamp is None:
            continue

        key = identity_key(finding)

        if key is not None:
            by_identity[key].append(finding)

    groups = []
    window = timedelta(minutes=window_minutes)

    for identity, items in by_identity.items():
        items.sort(key=lambda item: normalize_timestamp(item.timestamp))

        current = []
        group_start = None

        for finding in items:
            timestamp = normalize_timestamp(finding.timestamp)

            if not current:
                current = [finding]
                group_start = timestamp
                continue

            delta = timestamp - group_start

            if timedelta(0) <= delta <= window:
                current.append(finding)
            else:
                if len(current) > 1:
                    groups.append(current)

                current = [finding]
                group_start = timestamp

        if len(current) > 1:
            groups.append(current)

    groups.sort(
        key=lambda group: normalize_timestamp(group[0].timestamp)
    )

    return [
        {
            "start": group[0].timestamp.isoformat(),
            "end": group[-1].timestamp.isoformat(),
            "sources": sorted({item.source for item in group}),
            "finding_count": len(group),
            "rule_ids": sorted({item.rule_id for item in group}),
            "categories": sorted({item.category for item in group}),
            "devices": sorted({
                item.hostname
                for item in group
                if item.hostname != "Unknown"
            }),
            "evidence": [item.evidence for item in group],
        }
        for group in groups
    ]

def build_instance_comparison(events, findings):
    """
    Compare only instances represented by uploaded logs.

    Physical identity is established exclusively by identity_id.
    instance_id distinguishes logical instances of the same device.
    Unidentified events are kept separate using their file and line.
    Absence of matching errors is not proof of health.
    """

    groups = defaultdict(lambda: {
        "events": [],
        "findings": [],
        "files": set(),
    })

    local_timezone = ZoneInfo("Europe/Berlin")

    def normalize_timestamp(timestamp):
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=local_timezone)

        return timestamp.astimezone(timezone.utc)

    def normalise_instance(value):
        if not value or value == "Unknown":
            return None
        return value

    def event_key(event):
        identity = getattr(event, "identity_id", None)
        instance = normalise_instance(event.instance_id)

        if identity and identity != "Unknown":
            return ("IDENTIFIED", identity, instance)

        return (
            "UNIDENTIFIED",
            event.source,
            event.file_name,
         )

    def finding_key(finding):
        identity = getattr(finding, "identity_id", None)
        instance = normalise_instance(finding.instance_id)

        if identity and identity != "Unknown":
            return ("IDENTIFIED", identity, instance)

        return (
            "UNIDENTIFIED",
            finding.source,
            finding.file_name,
        )

    for event in events:
        key = event_key(event)
        groups[key]["events"].append(event)
        groups[key]["files"].add(event.file_name)

    for finding in findings:
        key = finding_key(finding)
        groups[key]["findings"].append(finding)
        groups[key]["files"].add(finding.file_name)

    rows = []

    for key, data in sorted(groups.items(), key=lambda item: str(item[0])):
        evs = data["events"]
        fs = data["findings"]

        identity_id = key[1] if key[0] == "IDENTIFIED" else None

        instance_ids = sorted({
            normalise_instance(e.instance_id)
            for e in evs
            if normalise_instance(e.instance_id)
        })

        hostnames = sorted({
            e.hostname
            for e in evs
            if e.hostname and e.hostname != "Unknown"
        })

        device_uid = next(
            (
                e.device_uid
                for e in evs
                if e.device_uid and e.device_uid != "Unknown"
            ),
            "Unknown",
        )

        if identity_id:
            display_name = hostnames[0] if hostnames else identity_id
        else:
            display_name = f"Unidentified:{key[1]}:{key[2]}"

        if instance_ids:
            display_name = f"{display_name} / {', '.join(instance_ids)}"

        identified = identity_id is not None

        if fs:
            status = "AFFECTED"
            color = "ORANGE"
        elif identified:
            status = "NO_MATCHED_ERRORS_IN_PROVIDED_LOGS"
            color = "GREEN"
        else:
            status = "UNKNOWN_IDENTITY"
            color = "GREY"

        timestamps = [
            normalize_timestamp(e.timestamp)
            for e in evs
            if e.timestamp is not None
        ]

        rows.append({
            "instance": display_name,
            "identity_id": identity_id,
            "instance_id": ", ".join(instance_ids) if instance_ids else "Unknown",
            "hostname": ", ".join(hostnames) if hostnames else "Unknown",
            "device_uid": device_uid,
            "status": status,
            "color": color,
            "events": len(evs),
            "findings": len(fs),
            "files": sorted(data["files"]),
            "error_categories": sorted({f.category for f in fs}),
            "error_codes": sorted({f.rule_id for f in fs}),
            "first_seen": min(timestamps, default=None),
            "last_seen": max(timestamps, default=None),
        })

    return rows

def error_frequency(findings):
    counts=Counter((f.category,f.rule_id,f.title) for f in findings)
    return [{"category":k[0],"rule_id":k[1],"error":k[2],"occurrences":v} for k,v in counts.most_common()]


def build_root_cause_hypotheses(findings, instance_rows):
    """Generate deterministic investigative leads; never label them as confirmed causes."""
    hypotheses=[]
    by_rule=defaultdict(list)
    by_category=defaultdict(list)
    for f in findings:
        by_rule[f.rule_id].append(f); by_category[f.category].append(f)
    affected={r["instance"] for r in instance_rows if r["status"]=="AFFECTED"}
    for rule_id,items in by_rule.items():
        hosts={f.hostname for f in items if f.hostname!="Unknown"}
        if len(hosts)>=2:
            hypotheses.append({"hypothesis":f"Shared or repeated {items[0].category} failure pattern ({items[0].title})", "basis":f"Same diagnostic rule matched on {len(hosts)} identified instances and {len(items)} event lines.","affected_instances":sorted(hosts),"evidence_count":len(items),"confidence":"Investigative lead — verify shared dependencies and clock alignment","status":"HYPOTHESIS"})
    for category,items in by_category.items():
        hosts={f.hostname for f in items if f.hostname!="Unknown"}
        if len(hosts)>=2 and not any(h["hypothesis"].startswith(f"Shared or repeated {category}") for h in hypotheses):
            hypotheses.append({"hypothesis":f"Cross-instance {category} issue", "basis":f"{len(items)} findings across {len(hosts)} identified instances.","affected_instances":sorted(hosts),"evidence_count":len(items),"confidence":"Investigative lead — category similarity does not prove common cause","status":"HYPOTHESIS"})
    if findings and len(affected)==1:
        hypotheses.append({"hypothesis":"Instance-local issue may be more likely than a fleet-wide issue", "basis":"Matched errors are limited to one identified instance in the supplied logs.","affected_instances":sorted(affected),"evidence_count":len(findings),"confidence":"Weak lead — compare log coverage and shared dependencies before concluding","status":"HYPOTHESIS"})
    return hypotheses
