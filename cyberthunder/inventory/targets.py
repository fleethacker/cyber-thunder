"""Asset inventory. The inventory is also the scope guardrail: the agent may only touch targets listed
here with in_scope=true. Credentials are never stored; `credential_ref` names an environment variable
(CT_CRED_<ref>) or a key file path that the transport resolves at connect time.
"""
from __future__ import annotations

import contextlib
import copy
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from cyberthunder.audit.chain import file_lock
from cyberthunder.findings.schema import utcnow
from cyberthunder.state.json_files import read_text_retry, replace_file

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
    """Targets file shared by every process (API server, CLI, scans). Reads notice when another process has
    changed the file (a cheap stat) and merge its changes in; save() merges under a cross-process lock
    before writing, so a stale copy never overwrites a newer file. Merge rule per field: a value changed
    on disk since this copy last synced wins (scope flags included); otherwise the local value stays."""

    def __init__(self, path: str | Path | None = None, targets: list[Target] | None = None):
        self.path = Path(path) if path else None
        self._targets: dict[str, Target] = {t.id: t for t in (targets or [])}
        self._base: dict[str, dict] = {}            # target dicts as last read from / written to the file
        self._sig: tuple[int, int] | None = None

    # -- persistence (YAML preferred, JSON accepted) ------------------------------
    @classmethod
    def load(cls, path: str | Path) -> "Inventory":
        inv = cls(Path(path))
        inv._merge_from_disk()
        return inv

    @staticmethod
    def _read(p: Path) -> dict[str, dict]:
        text = read_text_retry(p)
        if p.suffix in (".yaml", ".yml"):
            import yaml  # pyyaml, in requirements
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text or "{}")
        return {d["id"]: d for d in data.get("targets", [])}

    def _file_sig(self) -> tuple[int, int] | None:
        try:
            st = self.path.stat()
        except (FileNotFoundError, AttributeError, TypeError):
            return None
        return st.st_mtime_ns, st.st_size

    def _merge_from_disk(self) -> None:
        sig = self._file_sig()
        if sig is None:
            return
        disk = self._read(self.path)
        for tid, d in disk.items():
            cur, base = self._targets.get(tid), self._base.get(tid)
            if cur is None:
                if base is None:                     # added elsewhere
                    self._targets[tid] = Target.from_dict(copy.deepcopy(d))
                continue                             # else removed here and not yet saved
            if base is None:                         # same id added on both sides: the file decides scope
                if "in_scope" in d:
                    cur.in_scope = bool(d["in_scope"])
                continue
            for k, v in d.items():
                if hasattr(cur, k) and v != base.get(k):
                    setattr(cur, k, copy.deepcopy(v))
        for tid in [t for t in self._targets if t not in disk and t in self._base]:
            del self._targets[tid]                   # removed elsewhere
        self._base, self._sig = copy.deepcopy(disk), sig

    def _refresh(self) -> None:
        if self.path is not None and self._file_sig() != self._sig:
            self._merge_from_disk()

    def save(self, path: str | Path | None = None) -> None:
        p = Path(path) if path else self.path
        if p is None:
            raise ValueError("no inventory path")
        p.parent.mkdir(parents=True, exist_ok=True)
        own = self.path is not None and p.resolve() == self.path.resolve()
        lock = file_lock(p.with_name(p.name + ".lock")) if own else contextlib.nullcontext()
        with lock:
            if own:
                self._merge_from_disk()
            data = {"targets": [t.to_dict() for t in self._targets.values()]}
            if p.suffix in (".yaml", ".yml"):
                import yaml
                text = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
            else:
                text = json.dumps(data, indent=2)
            tmp = p.with_name(p.name + ".tmp")
            tmp.write_text(text, encoding="utf-8")
            replace_file(tmp, p)               # another process may be reading the file at this moment (Windows)
            if own:
                self._base = {d["id"]: copy.deepcopy(d) for d in data["targets"]}
                self._sig = self._file_sig()

    # -- access --------------------------------------------------------------------
    def all(self) -> list[Target]:
        self._refresh()
        return list(self._targets.values())

    def get(self, target_id: str) -> Target:
        self._refresh()
        try:
            return self._targets[target_id]
        except KeyError:
            raise KeyError(f"unknown target {target_id!r}") from None

    def by_type(self, asset_type: str) -> list[Target]:
        self._refresh()
        return [t for t in self._targets.values() if t.asset_type == asset_type]

    def add(self, target: Target) -> Target:
        self._refresh()
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
        self._refresh()
        self._targets.pop(target_id, None)

    # -- scope guardrail -----------------------------------------------------------
    def in_scope(self, target_id: str) -> bool:
        self._refresh()
        t = self._targets.get(target_id)
        return bool(t and t.in_scope)

    def assert_in_scope(self, target_id: str) -> Target:
        """Raise ScopeViolation unless the target exists and is in scope. Call before any collect or apply.
        Reads the file first if another process changed it, so a scope-out made elsewhere holds here."""
        self._refresh()
        t = self._targets.get(target_id)
        if t is None:
            raise ScopeViolation(f"target {target_id!r} is not in the inventory")
        if not t.in_scope:
            raise ScopeViolation(f"target {target_id!r} is marked out of scope")
        return t
