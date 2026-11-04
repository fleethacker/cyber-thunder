"""Vetted remediation library.

A fix is only ever applied from a FixEntry. The model may select a fix_ref; it never writes a payload.
Adapters contribute entries (ComplianceAsCode fix scripts, hunt remediations, device config snippets,
Kubernetes manifests). Every entry declares its blast radius (disruption, reboot, service restarts),
how it is rolled back, what to capture before applying, and how to verify afterwards.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Iterable

from cyberthunder.findings.schema import Finding

DISRUPTION_RANK = {"low": 1, "medium": 2, "high": 3}
KINDS = ("script", "powershell", "config_snippet", "manifest", "runbook")
ROLLBACK_KINDS = ("restore_files", "config_replace", "manifest", "command", "snapshot", "manual")


@dataclass
class FixEntry:
    fix_ref: str                       # e.g. ssg:sshd_disable_root_login, hunt:linux:remove_uid0_dup, cisco:ndm:service_password_encryption
    title: str
    asset_type: str
    applies_to: list[str]              # rule ids, STIG IDs, hunt check ids, CVE ids this fix resolves
    kind: str = "script"
    payload: str = ""                  # exactly what will run or change; shown verbatim to the approver
    steps: list[str] = field(default_factory=list)      # human steps (runbook, or alongside payload)
    disruption: str = "low"            # low | medium | high
    reboot: bool = False
    restarts_services: list[str] = field(default_factory=list)
    reversible: bool = True
    rollback_kind: str = "restore_files"
    rollback_steps: list[str] = field(default_factory=list)
    before_state: dict = field(default_factory=dict)    # {"files": [...], "commands": {"name": "cmd"}}
    verify: dict = field(default_factory=dict)          # {"rule_ids": [...], "commands": {"name": "cmd"}, "expect": {...}}
    citations: list[str] = field(default_factory=list)
    source: str = "manual"             # ssg | hunt | cisco | kubernetes | windows | manual
    patch: bool = False                # package/patch class change: never auto-eligible, slow to roll back offline
    notes: str = ""

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"{self.fix_ref}: unknown kind {self.kind!r}")
        if self.rollback_kind not in ROLLBACK_KINDS:
            raise ValueError(f"{self.fix_ref}: unknown rollback_kind {self.rollback_kind!r}")
        if self.disruption not in DISRUPTION_RANK:
            raise ValueError(f"{self.fix_ref}: unknown disruption {self.disruption!r}")
        if self.kind == "runbook" and not self.steps:
            raise ValueError(f"{self.fix_ref}: runbook needs steps")

    @property
    def disruption_rank(self) -> int:
        return DISRUPTION_RANK[self.disruption]

    def preview_text(self) -> str:
        parts = []
        if self.payload:
            parts.append(self.payload.strip())
        if self.steps:
            parts.append("\n".join(f"{i+1}. {s}" for i, s in enumerate(self.steps)))
        return "\n\n".join(parts) or "(no payload)"

    def rollback_plan_text(self) -> str:
        if self.rollback_steps:
            return "\n".join(f"{i+1}. {s}" for i, s in enumerate(self.rollback_steps))
        return {
            "restore_files": "Restore the files captured before the change from the before-state archive, then re-run the verify check.",
            "config_replace": "Replace the running configuration with the archived pre-change configuration.",
            "manifest": "Re-apply the previous manifest captured before the change.",
            "command": "Run the recorded inverse command.",
            "snapshot": "Revert to the snapshot taken before the change.",
            "manual": "Manual rollback; see steps.",
        }[self.rollback_kind]

    def risk_tags(self) -> list[str]:
        tags = [f"disruption:{self.disruption}"]
        if self.reboot: tags.append("reboot")
        if self.restarts_services: tags.append("restarts:" + ",".join(self.restarts_services))
        if self.patch: tags.append("patch")
        if not self.reversible: tags.append("not-reversible")
        return tags

    def to_dict(self) -> dict:
        d = asdict(self)
        d["preview"] = self.preview_text()
        d["rollback_plan"] = self.rollback_plan_text()
        d["risk_tags"] = self.risk_tags()
        return d


class FixLibrary:
    def __init__(self, entries: Iterable[FixEntry] | None = None):
        self._by_ref: dict[str, FixEntry] = {}
        self._index: dict[str, list[str]] = {}
        if entries:
            self.extend(entries)

    def add(self, entry: FixEntry) -> None:
        self._by_ref[entry.fix_ref] = entry
        for key in entry.applies_to:
            self._index.setdefault(key, [])
            if entry.fix_ref not in self._index[key]:
                self._index[key].append(entry.fix_ref)

    def extend(self, entries: Iterable[FixEntry]) -> None:
        for e in entries:
            self.add(e)

    def get(self, fix_ref: str) -> FixEntry | None:
        return self._by_ref.get(fix_ref)

    def all(self) -> list[FixEntry]:
        return list(self._by_ref.values())

    def candidates(self, finding: Finding) -> list[FixEntry]:
        """Entries that apply to this finding, most specific first, same asset type preferred."""
        keys = [finding.fix_ref, finding.rule_id, finding.rule_version, finding.group_id] + [r.id for r in finding.references]
        seen: list[str] = []
        for k in keys:
            if not k:
                continue
            if k in self._by_ref and k not in seen:
                seen.append(k)
            for ref in self._index.get(k, []):
                if ref not in seen:
                    seen.append(ref)
        entries = [self._by_ref[r] for r in seen]
        if finding.asset_type:
            entries.sort(key=lambda e: 0 if e.asset_type == finding.asset_type else 1)
        return entries

    def resolve(self, finding: Finding) -> FixEntry | None:
        c = self.candidates(finding)
        return c[0] if c else None

    @classmethod
    def from_adapters(cls, registry) -> "FixLibrary":
        lib = cls()
        for adapter in registry.all():
            try:
                lib.extend(adapter.fixes())
            except Exception as e:  # noqa: BLE001  one adapter's bad entry must not take the library down
                import logging
                logging.getLogger(__name__).warning("fix library: %s adapter failed: %s", adapter.asset_type, e)
        return lib
