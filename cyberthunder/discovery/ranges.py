"""Bounded IP interval arithmetic for the scope editor; never enumerates hosts or resolves names."""
from __future__ import annotations

import ipaddress

from .models import MAX_PREFIX, is_private_network, network_normalization

LIMITS = {"max_entries": 128, "max_networks": 256, "max_addresses": 65536}


def _parse(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValueError("each scope entry must be a nonempty string of at most 256 characters")
    if not value.isascii() or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("scope entries must use ASCII IP syntax without control characters")
    value = value.strip()
    if "%" in value:
        raise ValueError("scope entries cannot contain IPv6 zone identifiers")
    try:
        if "-" in value:
            first, last = value.split("-", 1)
            start, end = ipaddress.ip_address(first.strip()), ipaddress.ip_address(last.strip())
            if start.version != end.version or int(start) > int(end):
                raise ValueError("range endpoints must be ordered and use the same IP family")
            return start.version, int(start), int(end)
        net = ipaddress.ip_network(value, strict=False)
        return net.version, int(net.network_address), int(net.broadcast_address)
    except ValueError:
        raise ValueError("scope entries must be single IPs, CIDRs, or ordered start-end IP ranges of one family") from None


def _merge(intervals):
    result = []
    for version, start, end in sorted(intervals):
        if result and result[-1][0] == version and start <= result[-1][2] + 1:
            result[-1] = (version, result[-1][1], max(end, result[-1][2]))
        else:
            result.append((version, start, end))
    return result


def _subtract(included, excluded):
    result = []
    for version, start, end in included:
        cursor = start
        for ev, es, ee in excluded:
            if ev != version or ee < cursor or es > end:
                continue
            if cursor < es:
                result.append((version, cursor, es - 1))
            cursor = max(cursor, ee + 1)
            if cursor > end:
                break
        if cursor <= end:
            result.append((version, cursor, end))
    return result


def preview_ranges(include, exclude=None, *, allow_public=False, scanner_target=None, acknowledge_normalization=False):
    if not isinstance(include, list) or not isinstance(exclude if exclude is not None else [], list):
        raise ValueError("include and exclude must be lists of IP/CIDR/range strings")
    exclude = exclude or []
    if type(allow_public) is not bool:
        raise ValueError("allow_public must be true or false")
    if type(acknowledge_normalization) is not bool:
        raise ValueError("acknowledge_normalization must be true or false")
    if scanner_target is not None and (not isinstance(scanner_target, str) or not scanner_target.strip() or len(scanner_target) > 64):
        raise ValueError("scanner_target must be a target id or null")
    if len(include) + len(exclude) > LIMITS["max_entries"]:
        raise ValueError("at most 128 combined include/exclude entries are allowed")
    included, excluded = _merge([_parse(v) for v in include]), _merge([_parse(v) for v in exclude])
    normalizations = []
    for field, values in (("include", include), ("exclude", exclude)):
        for value in values:
            note = network_normalization(value) if "/" in value else None
            if note:
                normalizations.append({"field": field, **note})
    effective = _subtract(included, excluded)
    input_count = sum(end - start + 1 for _, start, end in included)
    count = sum(end - start + 1 for _, start, end in effective)
    # A bounded number of endpoints produces a bounded number of CIDRs, even for IPv6 /0.
    networks = []
    for version, start, end in effective:
        address = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
        networks.extend(ipaddress.summarize_address_range(address(start), address(end)))
    reasons, warnings = [], []
    if normalizations and not acknowledge_normalization:
        reasons.append("host-bit CIDR normalization requires acknowledge_normalization=true for these submitted inputs")
    if len(networks) > LIMITS["max_networks"]:
        reasons.append("effective scope exceeds 256 normalized networks")
    if count > LIMITS["max_addresses"]:
        reasons.append("effective scope exceeds 65536 total addresses")
    if any(n.prefixlen < MAX_PREFIX[n.version] for n in networks):
        reasons.append("each saved CIDR must be /16 or smaller for IPv4, /112 or smaller for IPv6")
    if not allow_public and any(not is_private_network(n) for n in networks):
        reasons.append("public address space requires explicit allow_public and a save reason")
    if include and not count:
        reasons.append("exclusions remove the entire included scope; use empty inputs to clear scopes explicitly")
    if exclude and not include:
        reasons.append("exclusions require an included scope")
    if exclude and count == input_count:
        warnings.append("exclusions do not intersect the included scope")
    return {"networks": [str(n) for n in networks[:LIMITS["max_networks"]]], "network_count": len(networks),
            "input_address_count": str(input_count), "excluded_address_count": str(input_count - count),
            "address_count": str(count), "truncated": len(networks) > LIMITS["max_networks"],
            "can_save": not reasons, "blocking_reasons": reasons, "warnings": warnings, "limits": dict(LIMITS),
            "normalizations": normalizations, "requires_normalization_acknowledgment": bool(normalizations)}
