"""Bounded, read-only dependency evidence for the exact proposed fix.

collect_dependencies(engine, proposal_id, *, actor, live=True) returns a versioned
packet. Unknowns/checks/rollback_limits are fixed human-readable strings. A packet
is evidence, never execution authority; complete remains false because these
bounded direct relationships cannot establish a full dependency inventory.

IDs are content-derived SHA-256 prefixes (24 hex characters): evidence e-<hash>
binds kind/source/subject/facts, dependency d-<hash> binds from/to/relation/evidence_ids,
and risk <category>-<hash> binds severity/summary/evidence_ids. Observation timestamps
are excluded from IDs. Severity values are low, medium, high or critical. All risks
are deterministic observations or explicitly possible/declared consequences.
The packet digest includes timestamps and all packet fields except evidence_sha256.
current_target(ctx, target_id) requires current persisted scope on every guard.
target_binding_sha256(target) binds nonsecret declarations and readable local
file metadata, never credential values/content. Rotation/privileges are not attested.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import time

from cyberthunder.control.identity import require_human
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.findings.schema import utcnow
from cyberthunder.inventory.targets import ScopeViolation
from cyberthunder.remediation.engine import EngineError
from cyberthunder.remediation.plan import _bound_fix

from . import dependencies_io as io
from .dependencies_binding import current_target, target_binding_sha256
from .dependencies_services import collect_services, declared_services

RISK_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
MAX_PACKET_BYTES = 65536

def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()


def evidence_digest(packet):
    """Digest the entire assessment input packet except its self-referential digest."""
    return _digest({key: value for key, value in packet.items() if key != "evidence_sha256"})


class _Packet:
    def __init__(self, proposal, target, digest, binding, live):
        self.target = target
        self.simulated = target.simulated or target.transport in {"simulated", "fixture"}
        self.data = {"version": 1, "generated_at": utcnow(), "proposal_id": proposal.id,
                     "target_id": target.id, "target_binding_sha256": binding, "fix_sha256": digest,
                     "evidence_sha256": "", "mode": "live" if live else "stored", "complete": False,
                     "evidence": [], "dependencies": [], "risks": [], "unknowns": [],
                     "required_checks": [], "rollback_limits": []}

    def source(self, source):
        return ("simulated-fixture:" if self.simulated else "live:") + source

    def evidence(self, kind, source, subject, facts):
        eid = "e-" + _digest([kind, source, subject, facts])[:24]
        self.data["evidence"].append({"id": eid, "kind": kind, "source": source,
                                      "observed_at": utcnow(), "subject": subject, "facts": facts})
        return eid

    def unknown(self, detail):
        if detail not in self.data["unknowns"]:
            self.data["unknowns"].append(detail)

    def check(self, detail):
        if detail not in self.data["required_checks"]:
            self.data["required_checks"].append(detail)

    def edge(self, source, target, relation, eid):
        edge = {"from": source, "to": target, "relation": relation, "evidence_ids": [eid]}
        edge["id"] = "d-" + _digest(edge)[:24]
        self.data["dependencies"].append(edge)

    def risk(self, code, severity, summary, evidence_ids):
        if severity not in RISK_SEVERITIES:
            raise ValueError("invalid dependency risk severity")
        rid = code + "-" + _digest([severity, summary, evidence_ids])[:24]
        self.data["risks"].append({"id": rid, "severity": severity,
                                  "summary": summary, "evidence_ids": evidence_ids, "deterministic": True})


def _declared(packet, fix, names):
    # Inspect only bounded, exact fix text for conservative possible-risk categories; never
    # execute it or include payload/configuration paths in operational evidence.
    before = fix.before_state if isinstance(fix.before_state, dict) else {}
    files = before.get("files", [])
    text = (fix.payload[:65536] + " " + " ".join(names)).casefold()
    if isinstance(files, list):
        text += " " + " ".join(v[:512] for v in files[:32] if isinstance(v, str)).casefold()
    categories = [label for label, tokens in (
        ("ssh", ("sshd", "/etc/ssh", "openssh")),
        ("winrm", ("winrm", "wsman")),
        ("network", ("firewall", "iptables", "nftables", "nft ", "networkpolicy", "networkmanager", "sysctl",
                     "ip route", "ip link", "ip addr", "nmcli", "netsh", "netplan", "resolv.conf")),
        ("authentication", ("pam", "sudoers", "shadow", "passwd", "secpol", "authentication", "rolebinding",
                            "serviceaccount", "userdel", "usermod", "chage", "login.defs", "sssd", "krb5")),
    ) if any(token in text for token in tokens)]
    facts = {"disruption": fix.disruption, "reboot": bool(fix.reboot), "reversible": bool(fix.reversible),
             "rollback_kind": fix.rollback_kind, "patch": bool(fix.patch), "services": names,
             "possible_management_impact": categories, "declared_files_exhaustive": False}
    eid = packet.evidence("declared-fix", "bound-fix-declared", packet.target.id, facts)
    if categories:
        packet.risk("management-access", "high", "The bound fix may affect management access, networking or authentication; lockout safety is unverified.", [eid])
        packet.check("Validate SSH/WinRM/API access and an independent recovery path with the target owner.")
    if fix.reboot or fix.disruption in {"medium", "high"} or names:
        packet.risk("declared-disruption", "high" if fix.reboot or fix.disruption == "high" else "medium",
                    "The fix declares a reboot, disruption or affected services; confirm an approved maintenance window.", [eid])
    if not fix.reversible or fix.rollback_kind == "manual" or fix.patch:
        packet.risk("rollback-limit", "high", "Declared rollback is limited, manual, or depends on package availability; recovery has not been tested.", [eid])
    packet.data["rollback_limits"] = [
        "Declared before_state files are not a full list of touched resources.",
        "A declared rollback does not prove recoverability; backups, retained packages and recovery access were not tested.",
        "Rollback may not restore interrupted sessions, in-flight work or external application state.",
    ]
    packet.unknown("This bounded collection is not a full dependency inventory; undeclared and transitive dependencies remain unknown.")
    packet.unknown("Named actor and successful reads do not establish authenticated identity or sufficient change privileges.")
    packet.unknown("Credential contents, credential rotation, effective privileges, external credential plugins, keyring changes and management network paths are not attested by the connection binding.")
    packet.check("Confirm application health, maintenance timing and rollback feasibility with the owner before approval.")
    packet.check("Recheck target/fix binding, evidence age, scope and kill switch before any approval or execution.")


def collect_dependencies(engine, proposal_id: str, *, actor: str, live: bool = True) -> dict:
    """Collect bounded dependency facts without modifying targets or proposal state.

    Identity, kill, scope and binding violations raise. Unavailable/unsupported reads
    return fixed unknowns, never raw errors. Only one summary audit is persisted.
    live=False never constructs a transport or treats stored findings as live facts.
    """
    actor = require_human(actor)
    if type(live) is not bool:
        raise TypeError("live must be a boolean")
    if not isinstance(proposal_id, str) or not 1 <= len(proposal_id) <= 256:
        raise EngineError("invalid proposal identifier")
    ctx = engine.ctx
    action = f"remediation.dependencies:{proposal_id}"
    ctx.killswitch.guard(action, actor)
    proposal = deepcopy(ctx.gate.get(proposal_id))
    target = current_target(ctx, proposal.host)
    if not isinstance(target.id, str) or not 1 <= len(target.id) <= 256:
        raise EngineError("invalid target identifier")

    def current_finding():
        return next((f for f in ctx.store.current_findings() if f.id == proposal.finding_id), None)

    current = current_finding()
    fix, digest, recorded_digest = _bound_fix(engine, proposal, current, target)
    if fix.asset_type != target.asset_type:
        raise EngineError("fix asset type differs from current target")
    binding = target_binding_sha256(target)
    finding_binding = _digest([current.host, current.tags]) if current is not None else None

    def guard():
        require_human(actor)
        ctx.killswitch.guard(action, actor)
        now_target = current_target(ctx, proposal.host)
        if target_binding_sha256(now_target) != binding:
            raise EngineError("target configuration changed during dependency collection; retry")
        now_proposal = ctx.gate.get(proposal_id)
        if (now_proposal.host, now_proposal.finding_id, now_proposal.fix_ref, now_proposal.fix_preview) != (
                proposal.host, proposal.finding_id, proposal.fix_ref, proposal.fix_preview):
            raise EngineError("proposal binding changed during dependency collection; retry")
        now_current = current_finding()
        _, now_digest, _ = _bound_fix(engine, now_proposal, now_current, now_target)
        if now_digest != digest:
            raise EngineError("fix binding changed during dependency collection; retry")
        if target.asset_type == "kubernetes":
            now_binding = _digest([now_current.host, now_current.tags]) if now_current is not None else None
            if now_binding != finding_binding:
                raise EngineError("Kubernetes object binding changed during dependency collection; retry")

    packet = _Packet(proposal, target, digest, binding, live)
    names = declared_services(fix, packet) if target.asset_type in {"linux", "windows"} else []
    _declared(packet, fix, names)
    if recorded_digest is None:
        packet.unknown("Legacy proposal binds only the preview; full fix metadata was not recorded when proposed.")
        packet.check("Create a new proposal with a full fix digest before approval.")
    if current is None or current.host != target.id:
        packet.unknown("A matching current finding is unavailable; historical findings are not current dependency evidence.")
    if packet.simulated:
        packet.unknown("Simulator/fixture evidence is simulated and cannot establish live operational readiness.")

    transport = None
    calls = 0
    deadline = time.monotonic() + io.TOTAL_TIMEOUT

    def read(command):
        nonlocal transport, calls
        guard()
        remaining = deadline - time.monotonic()
        if calls >= io.MAX_CALLS or remaining < 1:
            packet.unknown("Dependency collection reached its call/time bound; remaining reads were skipped.")
            return None
        calls += 1
        try:
            if transport is None:
                if target.transport == "fixture":
                    spec = Path(target.options["fixture_dir"]) / "commands.json"
                    if spec.stat().st_size > 1024 * 1024:
                        raise io.ReadFailure("fixture_limit")
                transport = ctx.transport_for(deepcopy(target))
                guard()
            text = io.read_command(transport, command, timeout=min(io.CALL_TIMEOUT, remaining), guard=guard)
        except (EngineError, ScopeViolation, KillSwitchEngaged):
            raise
        except Exception:
            guard()
            packet.unknown("A bounded dependency read failed, timed out or exceeded its output limit; no absence was inferred.")
            packet.check("Repeat failed dependency preflight with the target owner; confirm read permissions and collection limits.")
            return None
        guard()
        return text

    try:
        if not live:
            packet.unknown("Stored mode uses declared metadata only; no current target dependencies were observed.")
        elif target.transport == "simulated" or (target.simulated and target.transport != "fixture"):
            # Existing simulator constructors can seed/save state, so do not open them here.
            packet.unknown("Simulator was not opened because initialization may persist state; use read-only fixtures for simulated dependency evidence.")
        elif target.asset_type in {"linux", "windows"}:
            if names:
                collect_services(packet, names, read)
            else:
                packet.unknown("No validated affected services are declared; service and application dependencies remain unknown.")
                packet.check("Identify affected services and their owners before collecting service dependencies.")
        elif target.asset_type == "kubernetes":
            from .dependencies_kubernetes import collect_kubernetes
            collect_kubernetes(packet, fix, current, read)
        else:
            packet.unknown("This asset type has no bounded dependency collector; topology remains unknown.")
            packet.check("Obtain device/application dependency and management-access preflight from its owner.")
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                packet.unknown("Read transport cleanup failed; confirm the read session has ended.")
    guard()
    if len(json.dumps(packet.data, ensure_ascii=True).encode("utf-8")) > MAX_PACKET_BYTES - 128:
        # Keep declared risks and a high/critical uncertainty floor. Never emit a silently
        # truncated graph or let loss of evidence imply a lower operational risk.
        floor = "critical" if any(r["severity"] == "critical" for r in packet.data["risks"]) else "high"
        declared = [e for e in packet.data["evidence"] if e["kind"] == "declared-fix"]
        declared_ids = {e["id"] for e in declared}
        packet.data["evidence"] = declared
        packet.data["dependencies"] = []
        packet.data["risks"] = [r for r in packet.data["risks"] if set(r["evidence_ids"]) <= declared_ids]
        packet.unknown("Operational evidence exceeded the packet byte limit and was omitted; dependency impact remains unknown.")
        packet.check("Narrow the collection scope and obtain owner preflight for omitted dependency evidence.")
        packet.risk("evidence-limit", floor, "Unknown dependency impact: operational evidence exceeded the packet limit; owner preflight is required.", [])
    packet.data["evidence_sha256"] = evidence_digest(packet.data)
    ctx.audit.append("remediation.dependencies", actor,
                     {"proposal_id": proposal.id, "target_id": target.id, "fix_sha256": digest,
                      "target_binding_sha256": binding, "evidence_sha256": packet.data["evidence_sha256"],
                      "mode": packet.data["mode"], "complete": False, "calls": calls,
                      "evidence_count": len(packet.data["evidence"]), "unknown_count": len(packet.data["unknowns"])},
                     subject=proposal.id)
    return packet.data
