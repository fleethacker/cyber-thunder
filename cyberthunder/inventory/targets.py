"""Asset inventory. The inventory is also the scope guardrail: the agent may only touch targets listed
here with in_scope=true. Credentials are never stored; `credential_ref` names an environment variable
(CT_CRED_<ref>) or a key file path that the transport resolves at connect time.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from cyberthunder.findings.schema import utcnow

ASSET_TYPES = ("linux", "windows", "cisco_ios", "kubernetes", "containers")
# generic transports are implemented in cyberthunder.transport; adapter-specific ones (simulated, file,
# kubeconfig) are provided by the adapter for that asset type via Adapter.make_transport().
TRANSPORTS = ("ssh", "winrm", "local", "fixture", "simulated", "file", "kubeconfig")


class ScopeViolation(PermissionError):
    pass


@dataclass
class Target:
    id: str
    name: str
    asset_type: str
    transport: str = "ssh"
    address: str | None = None
    port: int | None = None
    username: str | None = None
    credential_ref: str | None = None
    sudo: bool = True
    tags: list[str] = field(default_factory=list)
    in_scope: bool = True
    simulated: bool = False
    options: dict = field(default_factory=dict)   # adapter/transport specific: fixture_dir, config_path, kubeconfig, critical_services ...
    last_scan: str | None = None
    notes: str = ""
    added_at: str = field(default_factory=utcnow)

    def __post_init__(self) -> None:
        if self.asset_type not in ASSET_TYPES:
            raise ValueError(f"unknown asset_type {self.asset_type!r}; expected one of {ASSET_TYPES}")
        if self.transport not in TRANSPORTS:
            raise ValueError(f"unknown transport {self.transport!r}; expected one of {TRANSPORTS}")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Target":
        return cls(**d)

    @property
    def label(self) -> str:
        return f"{self.name} ({self.asset_type}{', simulated' if self.simulated else ''})"


class Inventory:
    def __init__(self, path: str | Path | None = None, targets: list[Target] | None = None):
        self.path = Path(path) if path else None
        self._targets: dict[str, Target] = {t.id: t for t in (targets or [])}

    # -- persistence (YAML preferred, JSON accepted) ------------------------------
    @classmethod
    def load(cls, path: str | Path) -> "Inventory":
        p = Path(path)
        inv = cls(p)
        if not p.exists():
            return inv
        text = p.read_text(encoding="utf-8")
        if p.suffix in (".yaml", ".yml"):
            import yaml  # pyyaml, in requirements
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text or "{}")
        for d in data.get("targets", []):
            t = Target.from_dict(d)
            inv._targets[t.id] = t
        return inv

    def save(self, path: str | Path | None = None) -> None:
        p = Path(path) if path else self.path
        if p is None:
            raise ValueError("no inventory path")
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {"targets": [t.to_dict() for t in self._targets.values()]}
        if p.suffix in (".yaml", ".yml"):
            import yaml
            p.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
        else:
            p.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # -- access --------------------------------------------------------------------
    def all(self) -> list[Target]:
        return list(self._targets.values())

    def get(self, target_id: str) -> Target:
        try:
            return self._targets[target_id]
        except KeyError:
            raise KeyError(f"unknown target {target_id!r}") from None

    def by_type(self, asset_type: str) -> list[Target]:
        return [t for t in self._targets.values() if t.asset_type == asset_type]

    def add(self, target: Target) -> Target:
        self._targets[target.id] = target
        return target

    def update(self, target_id: str, **changes) -> Target:
        t = self.get(target_id)
        for k, v in changes.items():
            if not hasattr(t, k):
                raise KeyError(f"unknown field {k}")
            setattr(t, k, v)
        return t

    def remove(self, target_id: str) -> None:
        self._targets.pop(target_id, None)

    # -- scope guardrail -----------------------------------------------------------
    def in_scope(self, target_id: str) -> bool:
        t = self._targets.get(target_id)
        return bool(t and t.in_scope)

    def assert_in_scope(self, target_id: str) -> Target:
        """Raise ScopeViolation unless the target exists and is in scope. Call before any collect or apply."""
        t = self._targets.get(target_id)
        if t is None:
            raise ScopeViolation(f"target {target_id!r} is not in the inventory")
        if not t.in_scope:
            raise ScopeViolation(f"target {target_id!r} is marked out of scope")
        return t
