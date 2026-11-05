"""Fixed systemd and Windows service queries with strict name and fact allow lists."""
from __future__ import annotations

import re

from .dependencies_io import ReadFailure, read_json

MAX_SERVICES = 4
MAX_RELATIONS = 32
UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@:-]{0,190}\.(?:service|socket|target|mount|automount|timer|path|slice|scope|swap)")
SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
PROPERTIES = ("Id", "LoadState", "ActiveState", "Requires", "Wants", "RequiredBy", "WantedBy")
LOAD_STATES = {"loaded", "not-found", "masked", "error", "bad-setting", "merged", "stub"}
ACTIVE_STATES = {"active", "inactive", "failed", "activating", "deactivating", "reloading", "maintenance", "refreshing"}
WINDOWS_STATES = {"Running", "Stopped", "Paused", "StartPending", "StopPending", "ContinuePending", "PausePending"}


def service_name(value, asset):
    if not isinstance(value, str):
        return None
    if asset == "linux":
        if SERVICE.fullmatch(value) and "." not in value:
            value += ".service"
        return value if UNIT.fullmatch(value) else None
    return value if SERVICE.fullmatch(value) else None


def declared_services(fix, packet):
    before = fix.before_state if isinstance(fix.before_state, dict) else {}
    spec = before.get("spec", {})
    groups = [fix.restarts_services, before.get("services", [])]
    if fix.asset_type == "windows" and isinstance(spec, dict):
        groups.append(spec.get("services", []))
    names = []
    for group in groups:
        if not isinstance(group, list) or len(group) > MAX_RELATIONS:
            packet.unknown("Declared service list is invalid or exceeds the collection bound.")
            continue
        for raw in group:
            name = service_name(raw, fix.asset_type)
            if name is None:
                packet.unknown("A declared service name is unsupported or invalid; it was not queried.")
            elif name not in names:
                names.append(name)
    if len(names) > MAX_SERVICES:
        packet.unknown("Only the first four declared services can be queried; other services remain unknown.")
    return names[:MAX_SERVICES]


def systemd_command(unit):
    if not UNIT.fullmatch(unit):
        raise ValueError("invalid unit")
    # --property excludes ExecStart, Environment and every configuration-bearing field.
    return "systemctl show --no-pager --property=" + ",".join(PROPERTIES) + " -- " + unit


def windows_command(name):
    if not SERVICE.fullmatch(name):
        raise ValueError("invalid service")
    # No wildcard names, arbitrary properties, WMI paths, process arguments or file reads.
    return ("$ErrorActionPreference = 'Stop'\n"
            f"$s = Get-Service -Name '{name}' -ErrorAction Stop\n"
            "$r = @($s.ServicesDependedOn | Select-Object -First 33 | ForEach-Object {\n"
            "  @{name=$_.ServiceName; status=$_.Status.ToString()}\n})\n"
            "$d = @($s.DependentServices | Select-Object -First 33 | ForEach-Object {\n"
            "  @{name=$_.ServiceName; status=$_.Status.ToString()}\n})\n"
            "@{name=$s.ServiceName; status=$s.Status.ToString(); required=$r; dependents=$d} | "
            "ConvertTo-Json -Depth 4 -Compress")


def parse_systemd(text, unit):
    values = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in PROPERTIES:
            if key in values:
                raise ReadFailure("invalid_service_facts")
            values[key] = value
    if set(values) != set(PROPERTIES):
        raise ReadFailure("incomplete_service_facts")
    if not UNIT.fullmatch(values["Id"]) or values["LoadState"] not in LOAD_STATES or values["ActiveState"] not in ACTIVE_STATES:
        raise ReadFailure("invalid_service_facts")
    facts = {"requested_unit": unit, "unit": values["Id"], "load_state": values["LoadState"],
             "active_state": values["ActiveState"]}
    limited = False
    for key in PROPERTIES[3:]:
        names = values[key].split()
        if any(not UNIT.fullmatch(name) for name in names):
            raise ReadFailure("invalid_service_facts")
        limited |= len(names) > MAX_RELATIONS
        facts[key] = sorted(set(names))[:MAX_RELATIONS]
    return facts, limited


def parse_windows(text, name):
    data = read_json(text)
    if data.get("name", "").casefold() != name.casefold() or data.get("status") not in WINDOWS_STATES:
        raise ReadFailure("invalid_service_facts")
    facts = {"name": name, "status": data["status"]}
    limited = False
    for key in ("required", "dependents"):
        rows = data.get(key)
        if not isinstance(rows, list):
            raise ReadFailure("incomplete_service_facts")
        limited |= len(rows) > MAX_RELATIONS
        facts[key] = []
        for row in rows[:MAX_RELATIONS]:
            if (not isinstance(row, dict) or service_name(row.get("name"), "windows") is None
                    or row.get("status") not in WINDOWS_STATES):
                raise ReadFailure("invalid_service_facts")
            facts[key].append({"name": row["name"], "status": row["status"]})
    return facts, limited


def collect_services(packet, names, read):
    asset = packet.target.asset_type
    critical_raw = packet.target.options.get("critical_services", [])
    critical = {service_name(s, asset) for s in critical_raw[:MAX_RELATIONS]} if isinstance(critical_raw, list) else set()
    for name in names:
        command = systemd_command(name) if asset == "linux" else windows_command(name)
        text = read(command)
        if text is None:
            continue
        try:
            facts, limited = parse_systemd(text, name) if asset == "linux" else parse_windows(text, name)
        except (ReadFailure, TypeError, AttributeError):
            packet.unknown("Service dependency response was incomplete or invalid; no topology was inferred.")
            continue
        source = "systemd" if asset == "linux" else "windows-service"
        eid = packet.evidence(source, packet.source(source), name, facts)
        if limited:
            packet.unknown("Service dependency list exceeded 32 entries; the remaining dependencies are unknown.")
        if asset == "linux":
            subject = facts["unit"]
            groups = [("Requires", "requires", False), ("Wants", "wants", False),
                      ("RequiredBy", "requires", True), ("WantedBy", "wants", True)]
            for key, relation, reverse in groups:
                for other in facts[key]:
                    packet.edge(other if reverse else subject, subject if reverse else other, relation, eid)
            dependents = facts["RequiredBy"] + facts["WantedBy"]
            if facts["load_state"] != "loaded":
                packet.unknown("A requested systemd unit is not loaded; its dependency graph may be incomplete.")
            unhealthy = facts["active_state"] != "active"
        else:
            subject = name
            for row in facts["required"]:
                packet.edge(subject, row["name"], "requires", eid)
            for row in facts["dependents"]:
                packet.edge(row["name"], subject, "requires", eid)
            dependents = facts["dependents"]
            unhealthy = facts["status"] != "Running"
        if dependents:
            packet.risk("service-dependents", "high", "Observed dependent services may be disrupted by the declared service change.", [eid])
        if unhealthy:
            packet.risk("service-not-active", "medium", "The affected service is not currently active/running; establish its intended state before approval.", [eid])
        if name in critical or subject in critical:
            declared = packet.evidence("declared-critical-service", "inventory-declared", name, {"critical": True})
            packet.risk("critical-service", "high", "Inventory declares an affected service critical; owner validation is required.", [eid, declared])
    packet.unknown("Service dependencies cover direct manager relationships only; application clients and service redundancy remain unknown.")
    packet.check("Confirm dependent-service health, failover and an out-of-band recovery path before approval.")
