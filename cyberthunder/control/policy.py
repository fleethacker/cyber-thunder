"""Standing approval (automation) policy.

Default is off: a human approves every change. A policy is a signed statement by a named human that
fixes meeting narrow criteria may be approved on their behalf. Approvals made under a policy are recorded
with actor "policy:<signed_by>" so the audit trail still names the accountable person. Patches, reboots
and service restarts are never auto-eligible unless the policy says so explicitly, and the kill switch
still blocks the apply step regardless of policy.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, time as dtime
from pathlib import Path

from cyberthunder.findings.schema import Finding, utcnow
from cyberthunder.remediation.library import DISRUPTION_RANK, FixEntry


@dataclass
class PolicyRule:
    name: str
    asset_types: list[str] = field(default_factory=list)   # empty = any
    max_disruption: str = "low"                             # low | medium | high
    allow_reboot: bool = False
    allow_patch: bool = False
    allow_service_restart: bool = False
    fix_allowlist: list[str] = field(default_factory=list)  # fix_refs or rule ids; empty = any that meets the other criteria
    target_allowlist: list[str] = field(default_factory=list)  # target ids; empty = any in-scope target
    max_severity: str | None = None                         # only auto-approve findings up to this severity (high|medium|low); None = any
    window_start: str | None = None                         # "HH:MM" local time; None = always
    window_end: str | None = None


@dataclass
class AutomationPolicy:
    enabled: bool = False
    signed_by: str | None = None
    signed_at: str | None = None
    reason: str | None = None
    rules: list[PolicyRule] = field(default_factory=list)
    version: int = 1

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "AutomationPolicy":
        d = dict(d)
        d["rules"] = [PolicyRule(**r) for r in d.get("rules", [])]
        return cls(**d)

    def sign(self, actor: str, reason: str) -> None:
        self.enabled, self.signed_by, self.signed_at, self.reason = True, actor, utcnow(), reason
        self.version += 1

    def disable(self) -> None:
        self.enabled = False
        self.version += 1


@dataclass
class PolicyDecision:
    auto_eligible: bool
    rule: str | None
    reasons: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def _in_window(rule: PolicyRule, now: datetime) -> bool:
    if not rule.window_start or not rule.window_end:
        return True
    s = dtime.fromisoformat(rule.window_start)
    e = dtime.fromisoformat(rule.window_end)
    t = now.time()
    return s <= t <= e if s <= e else (t >= s or t <= e)   # window may cross midnight


def _rule_matches(rule: PolicyRule, fix: FixEntry, finding: Finding, target, now: datetime) -> list[str]:
    """Return the list of reasons the rule does NOT allow this fix; empty list means allowed."""
    why: list[str] = []
    if rule.asset_types and fix.asset_type not in rule.asset_types:
        why.append(f"asset type {fix.asset_type} not covered")
    if rule.target_allowlist and target.id not in rule.target_allowlist:
        why.append(f"target {target.id} not in allowlist")
    if rule.fix_allowlist and not ({fix.fix_ref, finding.rule_id, finding.rule_version} & set(rule.fix_allowlist)):
        why.append("fix not in allowlist")
    if fix.disruption_rank > DISRUPTION_RANK.get(rule.max_disruption, 1):
        why.append(f"disruption {fix.disruption} exceeds {rule.max_disruption}")
    if fix.reboot and not rule.allow_reboot:
        why.append("fix reboots the asset")
    if fix.patch and not rule.allow_patch:
        why.append("patch-class change")
    if fix.restarts_services and not rule.allow_service_restart:
        why.append("restarts services: " + ", ".join(fix.restarts_services))
    if not fix.reversible:
        why.append("fix is not reversible")
    if rule.max_severity and finding.severity.rank > DISRUPTION_RANK.get(rule.max_severity, 3):
        why.append(f"severity {finding.severity.value} above {rule.max_severity}")
    if not _in_window(rule, now):
        why.append(f"outside window {rule.window_start}-{rule.window_end}")
    return why


def evaluate(policy: AutomationPolicy, fix: FixEntry, finding: Finding, target, now: datetime | None = None) -> PolicyDecision:
    now = now or datetime.now()
    if not policy.enabled:
        return PolicyDecision(False, None, ["automation policy disabled; human approval required"])
    if not policy.signed_by:
        return PolicyDecision(False, None, ["policy has no signer"])
    if not getattr(target, "in_scope", False):
        return PolicyDecision(False, None, ["target out of scope"])
    all_reasons: list[str] = []
    for rule in policy.rules:
        why = _rule_matches(rule, fix, finding, target, now)
        if not why:
            return PolicyDecision(True, rule.name, [f"matches standing approval rule '{rule.name}' signed by {policy.signed_by}"])
        all_reasons.extend(f"{rule.name}: {w}" for w in why)
    return PolicyDecision(False, None, all_reasons or ["no rules defined"])


def load_policy(path: str | Path) -> AutomationPolicy:
    p = Path(path)
    if not p.exists():
        return AutomationPolicy()
    return AutomationPolicy.from_dict(json.loads(p.read_text(encoding="utf-8")))


def save_policy(path: str | Path, policy: AutomationPolicy) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(policy.to_dict(), indent=2), encoding="utf-8")
