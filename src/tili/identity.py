from collections import defaultdict
from hashlib import sha256


STRONG_IDENTIFIER_FIELDS = (
    "device_uid",
    "konnektor_id",
    "hardware_id",
    "device_id",
)


def _normalise(value):
    """Return a normalised identifier or None."""
    if value is None:
        return None

    value = str(value).strip()

    if not value or value.lower() in {"unknown", "none", "null", "n/a"}:
        return None

    return value


def resolve_device_identities(events):
    """
    Resolve physical device identities using strong identifiers only.

    Identifiers are linked only when they occur together on the same
    event. Hostnames and instance IDs never establish physical identity.

    Components containing conflicting values of the same identifier
    type are rejected as ambiguous.
    """

    parent = {}
    ambiguous_nodes = set()
    component_identifiers = defaultdict(set)

    def add_node(node):
        if node not in parent:
            parent[node] = node
            component_identifiers[node].add(node)

    def find(node):
        if parent[node] != node:
            parent[node] = find(parent[node])
        return parent[node]

    def component_is_valid(root):
        seen_types = {}

        for field, value in component_identifiers[root]:
            previous = seen_types.get(field)

            if previous is not None and previous != value:
                return False

            seen_types[field] = value

        return True

    def union(left, right):
        left_root = find(left)
        right_root = find(right)

        if left_root == right_root:
            return True

        merged = (
            component_identifiers[left_root]
            | component_identifiers[right_root]
        )

        seen_types = {}

        for field, value in merged:
            previous = seen_types.get(field)

            if previous is not None and previous != value:
                ambiguous_nodes.update(merged)
                return False

            seen_types[field] = value

        if merged & ambiguous_nodes:
            ambiguous_nodes.update(merged)
            return False

        parent[right_root] = left_root
        component_identifiers[left_root] = merged
        del component_identifiers[right_root]

        return True

    event_identifiers = []

    for event in events:
        identifiers = []

        for field in STRONG_IDENTIFIER_FIELDS:
            value = _normalise(getattr(event, field, None))

            if value is None:
                continue

            node = (field, value)
            add_node(node)
            identifiers.append(node)

        event_identifiers.append(identifiers)

        if identifiers:
            anchor = identifiers[0]

            for node in identifiers[1:]:
                union(anchor, node)

    components = defaultdict(list)

    for node in parent:
        components[find(node)].append(node)

    identity_by_node = {}

    for root, nodes in components.items():
        if not component_is_valid(root):
            continue

        if any(node in ambiguous_nodes for node in nodes):
            continue

        canonical = "|".join(
            f"{field}={value}"
            for field, value in sorted(nodes)
        )

        identity = "DEV-" + sha256(
            canonical.encode("utf-8")
        ).hexdigest()[:16].upper()

        for node in nodes:
            identity_by_node[node] = identity

    results = []

    for event, identifiers in zip(events, event_identifiers):
        identities = {
            identity_by_node[node]
            for node in identifiers
            if node in identity_by_node
        }

        # A conflicting or ambiguous event must not receive an identity.
        resolved_identity = (
            next(iter(identities))
            if len(identities) == 1
            else None
        )

        results.append({
            "identity_id": resolved_identity,
            "identified": resolved_identity is not None,
            "hostname": _normalise(
                getattr(event, "hostname", None)
            ) or "Unknown",
            "instance_id": _normalise(
                getattr(event, "instance_id", None)
            ) or "Unknown",
            "identifiers": {
                field: _normalise(getattr(event, field, None))
                for field in STRONG_IDENTIFIER_FIELDS
                if _normalise(getattr(event, field, None)) is not None
            },
        })

    return results
