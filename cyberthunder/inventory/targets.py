"""Asset inventory. The inventory is also the scope guardrail: the agent may only touch targets listed
here with in_scope=true. Credentials are never stored; `credential_ref` names an environment variable
(CT_CRED_<ref>) or a key file path that the transport resolves at connect time.
"""
from __future__ import annotations

import contextlib
import copy
import json
import os
import re
import stat
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from cyberthunder.audit.chain import file_lock
from cyberthunder.findings.schema import utcnow
from cyberthunder.state.json_files import read_text_retry, replace_file

ASSET_TYPES = ("linux", "windows", "cisco_ios", "kubernetes", "containers")
# generic transports are implemented in cyberthunder.transport; adapter-specific ones (simulated, file,
# kubeconfig) are provided by the adapter for that asset type via Adapter.make_transport().
TRANSPORTS = ("ssh", "winrm", "local", "fixture", "simulated", "file", "kubeconfig", "vsphere")


class ScopeViolation(PermissionError):
    pass


class _InventoryChanged(Exception):
    """A completed read no longer describes the file currently at its path."""


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
    environment: str = "default"
    authorization_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def __post_init__(self) -> None:
        if not isinstance(self.authorization_id, str) or not re.fullmatch(r"[a-f0-9]{32,64}", self.authorization_id):
            raise ValueError("invalid target authorization identity")
        if (not isinstance(self.environment, str) or not self.environment or len(self.environment) > 128
                or self.environment != self.environment.strip() or any(ord(c) < 33 for c in self.environment)):
            raise ValueError("environment must be a non-empty name without whitespace (128 characters at most)")
        if self.asset_type not in ASSET_TYPES:
            raise ValueError(f"unknown asset_type {self.asset_type!r}; expected one of {ASSET_TYPES}")
        if self.transport not in TRANSPORTS:
            raise ValueError(f"unknown transport {self.transport!r}; expected one of {TRANSPORTS}")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Target":
        if "authorization_id" not in d:
            import hashlib
            # A stable identity for legacy inventories; no legacy artifact is
            # classified merely by loading this target. New registrations use UUIDs.
            identity = {k: d.get(k) for k in ("id", "added_at", "address", "environment", "asset_type", "transport")}
            d = {**d, "authorization_id": hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()}
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

    @staticmethod
    def read_persisted(p: Path) -> dict[str, dict]:
        """Read current declarations, retrying at most eight changed snapshots.

        Concurrent atomic inventory saves can invalidate an otherwise well-formed
        snapshot. Every retry reopens and validates the current file; missing or
        invalid declarations fail immediately and never fall back to cached scope.
        """
        for attempt in range(8):
            try:
                return Inventory._read_persisted_once(p)
            except _InventoryChanged:
                if attempt < 7:
                    time.sleep(0.01)
        raise ScopeViolation("persisted inventory is missing, unreadable or invalid")

    @staticmethod
    def _read_persisted_once(p: Path) -> dict[str, dict]:
        try:
            flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
            with os.fdopen(os.open(p, flags), "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                    raise ValueError("invalid inventory file")
                raw = stream.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise ValueError("inventory too large")
            if p.suffix in {".yaml", ".yml"}:
                import yaml
                depth = 0
                for i, event in enumerate(yaml.parse(raw)):
                    if i > 32768 or isinstance(event, yaml.AliasEvent):
                        raise ValueError("inventory complexity")
                    if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                        depth += 1
                    elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                        depth -= 1
                    if depth > 16:
                        raise ValueError("inventory depth")
                document = yaml.safe_load(raw)
            else:
                document = json.loads(raw)
            if not isinstance(document, dict) or not isinstance(document.get("targets"), list):
                raise ValueError("inventory shape")
            rows = document["targets"]
            if any(not isinstance(row, dict) or not isinstance(row.get("id"), str)
                   or type(row.get("in_scope")) is not bool for row in rows):
                raise ValueError("target or explicit scope flag missing/invalid")
            if len({row["id"] for row in rows}) != len(rows):
                raise ValueError("duplicate target")
            for row in rows:
                Target.from_dict(row)
            after = p.stat()
            if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise _InventoryChanged()
            return {row["id"]: row for row in rows}
        except _InventoryChanged:
            raise
        except Exception:
            raise ScopeViolation("persisted inventory is missing, unreadable or invalid") from None

    def _file_sig(self) -> tuple[int, int] | None:
        try:
            st = self.path.stat()
        except (FileNotFoundError, AttributeError, TypeError):
            return None
        return st.st_mtime_ns, st.st_size

    def _merge_from_disk(self, disk: dict[str, dict] | None = None) -> None:
        sig = self._file_sig()
        if sig is None:
            return
        disk = self._read(self.path) if disk is None else disk
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
            self._save_locked(p, own=own)

    def _save_locked(self, p: Path, *, own: bool) -> None:
        if own:
            for tid, target in self._targets.items():
                previous = self._base.get(tid)
                if previous is not None:
                    before = Target.from_dict(previous)
                    if any(getattr(before, field) != getattr(target, field)
                           for field in ("environment", "address", "asset_type", "transport")):
                        # Moving away and back must not reactivate decisions or exceptions
                        # recorded for the prior authorization boundary or endpoint.
                        target.authorization_id = uuid.uuid4().hex
        data = {"targets": [t.to_dict() for t in self._targets.values()]}
        if p.suffix in (".yaml", ".yml"):
            import yaml
            text = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
        else:
            text = json.dumps(data, indent=2)
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        replace_file(tmp, p)
        if own:
            self._base = {d["id"]: copy.deepcopy(d) for d in data["targets"]}
            self._sig = self._file_sig()

    def add_new(self, target: Target) -> Target:
        """Create once under the same cross-process lock used by save; preserve other writers."""
        target.authorization_id = uuid.uuid4().hex
        if self.path is None:
            if target.id in self._targets:
                raise FileExistsError("target id already exists")
            self._targets[target.id] = target
            return target
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with file_lock(self.path.with_name(self.path.name + ".lock")):
            if not self.path.exists() and (self._base or self._targets):
                raise ScopeViolation("persisted inventory disappeared; reload before registering a target")
            disk = self.read_persisted(self.path) if self.path.exists() else {}
            if target.id in disk:
                raise FileExistsError("target id already exists")
            self._merge_from_disk(disk)
            if target.id in self._targets:
                raise FileExistsError("target id already exists")
            self._targets[target.id] = target
            self._save_locked(self.path, own=True)
        return target

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
