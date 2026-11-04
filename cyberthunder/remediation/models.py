"""Result models shared by adapters and the remediation engine."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from cyberthunder.findings.schema import utcnow


@dataclass
class BeforeState:
    """What was captured before a fix ran. Enough to roll back without guessing."""
    target_id: str
    fix_ref: str
    dir: str                                   # local directory holding the captured material
    captured_at: str = field(default_factory=utcnow)
    files: list[str] = field(default_factory=list)          # remote paths captured (archive or copies in dir)
    archive: str | None = None                              # e.g. before.tar.gz inside dir
    commands: dict[str, str] = field(default_factory=dict)  # name -> file in dir holding command output
    notes: str = ""
    extra: dict = field(default_factory=dict)               # adapter specific (unit states, config text, manifests)

    def to_dict(self) -> dict: return asdict(self)
    @classmethod
    def from_dict(cls, d: dict) -> "BeforeState": return cls(**d)


@dataclass
class ApplyResult:
    ok: bool
    output: str = ""
    changed: bool = True
    started_at: str = field(default_factory=utcnow)
    finished_at: str | None = None
    details: dict = field(default_factory=dict)
    def to_dict(self) -> dict: return asdict(self)


@dataclass
class HealthCheck:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class HealthResult:
    ok: bool
    checks: list[HealthCheck] = field(default_factory=list)
    def to_dict(self) -> dict: return asdict(self)


@dataclass
class VerifyResult:
    """rule_passed: the specific rule now passes (None = could not re-check). ok requires rule_passed and health."""
    ok: bool
    rule_passed: bool | None
    health: HealthResult
    evidence: str = ""
    details: dict = field(default_factory=dict)
    checked_at: str = field(default_factory=utcnow)
    def to_dict(self) -> dict:
        d = asdict(self); return d


@dataclass
class RollbackResult:
    ok: bool
    output: str = ""
    details: dict = field(default_factory=dict)
    finished_at: str = field(default_factory=utcnow)
    def to_dict(self) -> dict: return asdict(self)
