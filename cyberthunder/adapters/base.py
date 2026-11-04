"""Adapter contract.

An adapter knows one asset type. It never decides policy: it does not approve, it does not bypass the
kill switch, it does not write the audit log. The engine does those around every call. An adapter:

  discover(target, transport)                    -> AssetFacts        what is this thing
  collect(target, transport, workdir, ...)       -> Collected         pull raw material (scanner output, configs, logs)
  check(target, collected)                       -> [Finding]         deterministic compliance findings (STIG etc.)
  hunt(target, collected)                        -> [Finding]         intrusion / persistence indicators
  cve(target, collected)                         -> [Finding]         known-vulnerability matches (optional)
  fixes()                                        -> [FixEntry]        the vetted remediations it contributes
  capture_before_state(target, transport, fix, finding, dest) -> BeforeState
  apply(target, transport, fix, finding, before) -> ApplyResult      run ONE library fix, nothing else
  verify(target, transport, fix, finding)        -> VerifyResult      re-check that rule + health
  health_check(target, transport)                -> HealthResult      is the asset still serving
  rollback(target, transport, fix, before)       -> RollbackResult
  make_transport(target, settings)               -> Transport|None    adapter-specific transports (simulated, file, kubeconfig)

Findings must cite: use make_finding() so ids, sources and references are consistent across adapters.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Iterable

from cyberthunder.findings.schema import Finding, Reference, Severity, Status, extract_references, utcnow
from cyberthunder.remediation.library import FixEntry
from cyberthunder.remediation.models import ApplyResult, BeforeState, HealthResult, RollbackResult, VerifyResult

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.config import Settings
    from cyberthunder.inventory.targets import Target
    from cyberthunder.transport.base import Transport

log = logging.getLogger(__name__)

MODULES = ("check", "hunt", "cve")


@dataclass
class AssetFacts:
    hostname: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    kernel: str | None = None
    addresses: list[str] = field(default_factory=list)
    model: str | None = None            # device model / distro flavour / cluster version
    extra: dict = field(default_factory=dict)
    def to_dict(self) -> dict: return asdict(self)


@dataclass
class Collected:
    """Raw material from one target. Large things go to files under workdir; small things in `raw`."""
    target_id: str
    asset_type: str
    workdir: str
    collected_at: str = field(default_factory=utcnow)
    facts: AssetFacts | None = None
    artifacts: dict[str, str] = field(default_factory=dict)   # name -> file path (oscap results, configs, trivy json)
    raw: dict = field(default_factory=dict)                    # name -> small text/json outputs
    errors: list[str] = field(default_factory=list)
    modules: list[str] = field(default_factory=lambda: list(MODULES))
    rule_filter: list[str] | None = None                      # only these rule ids were requested (targeted rescan)

    def path(self, name: str) -> Path | None:
        p = self.artifacts.get(name)
        return Path(p) if p else None

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def make_finding(*, target: "Target", source: str, rule_id: str, title: str, severity: str | Severity,
                 status: str | Status = "open", description: str = "", evidence: str | None = None,
                 references: Iterable[str] = (), fix_ref: str | None = None, check_text: str | None = None,
                 fix_text: str | None = None, rule_version: str | None = None, group_id: str | None = None,
                 benchmark: str | None = None, benchmark_release: str | None = None, tags: Iterable[str] = (),
                 raw_ref: str | None = None, collected_at: str | None = None) -> Finding:
    """Build a Finding the same way everywhere. `references` are bare identifiers (STIG IDs, CCIs, CVEs,
    ATT&CK technique ids like T1053.003, IAVM ids); they are typed by pattern."""
    refs = extract_references([*references, rule_id, rule_version or "", group_id or ""])
    for r in references:
        if r and all(x.id != r for x in refs):
            refs.append(Reference("other", r))
    f = Finding(host=target.id, source=source, rule_id=rule_id, title=title, severity=severity, status=status,
                rule_version=rule_version, group_id=group_id, benchmark=benchmark, benchmark_release=benchmark_release,
                description=description, check_text=check_text, fix_text=fix_text, references=refs,
                evidence=evidence, raw_ref=raw_ref, tags=list(tags), asset_type=target.asset_type, fix_ref=fix_ref)
    if collected_at:
        f.collected_at = collected_at
    return f


class Adapter(ABC):
    asset_type: ClassVar[str]
    display_name: ClassVar[str] = ""
    transports: ClassVar[tuple[str, ...]] = ("ssh",)       # generic transport kinds this adapter can use
    own_transports: ClassVar[tuple[str, ...]] = ()         # kinds served by make_transport()

    # -- discovery / collection -------------------------------------------------------
    @abstractmethod
    def discover(self, target: "Target", transport: "Transport") -> AssetFacts: ...

    @abstractmethod
    def collect(self, target: "Target", transport: "Transport", workdir: Path, *,
                modules: Iterable[str] = MODULES, rule_filter: list[str] | None = None) -> Collected: ...

    # -- detection (pure functions of Collected; no network) ---------------------------
    @abstractmethod
    def check(self, target: "Target", collected: Collected) -> list[Finding]: ...

    def hunt(self, target: "Target", collected: Collected) -> list[Finding]:
        return []

    def cve(self, target: "Target", collected: Collected) -> list[Finding]:
        return []

    # -- remediation ------------------------------------------------------------------
    def fixes(self) -> list[FixEntry]:
        return []

    @abstractmethod
    def capture_before_state(self, target: "Target", transport: "Transport", fix: FixEntry, finding: Finding,
                             dest: Path) -> BeforeState: ...

    @abstractmethod
    def apply(self, target: "Target", transport: "Transport", fix: FixEntry, finding: Finding,
              before: BeforeState) -> ApplyResult: ...

    @abstractmethod
    def verify(self, target: "Target", transport: "Transport", fix: FixEntry, finding: Finding) -> VerifyResult: ...

    @abstractmethod
    def health_check(self, target: "Target", transport: "Transport") -> HealthResult: ...

    @abstractmethod
    def rollback(self, target: "Target", transport: "Transport", fix: FixEntry, before: BeforeState) -> RollbackResult: ...

    # -- transports / simulation --------------------------------------------------------
    def make_transport(self, target: "Target", settings: "Settings | None" = None) -> "Transport | None":
        """Adapter-specific transports: 'simulated' (stateful emulator), 'file' (config text), 'kubeconfig'.
        Simulated state persists under <settings.state_dir>/simulated/<target_id>.json so CLI and API share it."""
        return None

    def demo_targets(self) -> list["Target"]:
        """Simulated targets for the offline demo (one or more), seeded to match range/answer_key/<type>.json."""
        return []

    def reset_simulated(self, target: "Target", settings: "Settings | None" = None) -> bool:
        """Return a simulated target to its seeded state. False if this adapter has no simulation."""
        return False

    # -- helpers ----------------------------------------------------------------------
    def run_detection(self, target: "Target", collected: Collected) -> list[Finding]:
        """check + hunt + cve according to collected.modules, each isolated so one failure does not hide the rest."""
        out: list[Finding] = []
        for name in collected.modules:
            fn = getattr(self, name, None)
            if fn is None:
                continue
            try:
                out.extend(fn(target, collected))
            except Exception as e:  # noqa: BLE001
                log.exception("%s.%s failed on %s", self.asset_type, name, target.id)
                collected.errors.append(f"{name}: {e}")
        return out


class AdapterRegistry:
    def __init__(self):
        self._adapters: dict[str, Adapter] = {}

    def register(self, adapter: Adapter | type[Adapter]) -> Adapter:
        inst = adapter() if isinstance(adapter, type) else adapter
        self._adapters[inst.asset_type] = inst
        return inst

    def get(self, asset_type: str) -> Adapter:
        try:
            return self._adapters[asset_type]
        except KeyError:
            raise KeyError(f"no adapter for asset type {asset_type!r}; loaded: {sorted(self._adapters)}") from None

    def has(self, asset_type: str) -> bool:
        return asset_type in self._adapters

    def all(self) -> list[Adapter]:
        return list(self._adapters.values())

    def types(self) -> list[str]:
        return sorted(self._adapters)


registry = AdapterRegistry()


def register(cls: type[Adapter]) -> type[Adapter]:
    """Class decorator: @register on an Adapter subclass adds a singleton to the registry."""
    registry.register(cls)
    return cls
