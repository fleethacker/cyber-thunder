"""Current persisted scope and nonsecret connection bindings for advisory evidence.

Bindings attest declarations and readable file identity/metadata, not credential
contents, credential rotation, authenticated identity, or effective privileges.
No environment credential or file-content digest is computed or published.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from cyberthunder.inventory.targets import ScopeViolation, Target
from cyberthunder.remediation.engine import EngineError

MAX_FILE_BYTES = 1024 * 1024
MAX_INVENTORY_BYTES = 1024 * 1024
_LABEL = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_OPTIONS = ("key_file", "kubeconfig", "ca_trust_path", "context", "kubectl",
            "transport", "ssl", "cert_validation", "fixture_dir", "critical_services")
_FIELDS = ("id", "asset_type", "transport", "address", "port", "username",
           "credential_ref", "sudo", "tags", "in_scope", "simulated")


def _identity(info):
    # Windows stat/fstat disagree on ctime (creation vs change time) on some
    # Python/filesystem combinations. Only compare portable identity fields.
    return {"device": info.st_dev, "inode": info.st_ino, "size": info.st_size,
            "mtime_ns": info.st_mtime_ns}


def _nonlink_stat(path):
    # Reject symlinks and Windows reparse points, including directory junctions.
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("linked path")
    return info


def _read_file(value, limit, *, content=False):
    """Read at most limit+1 bytes; reject nonregular, linked, or changing files.

    File bytes are used only to establish readability unless parsing inventory.
    O_NONBLOCK prevents a raced FIFO from blocking open on POSIX; O_NOFOLLOW
    additionally protects the leaf. Identity is rechecked after reading.
    """
    if not isinstance(value, (str, Path)) or not str(value) or len(str(value)) > 4096:
        raise ValueError("invalid path")
    path = Path(os.path.abspath(Path(value).expanduser()))
    before = _nonlink_stat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError("unsupported file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    raw, count = bytearray(), 0
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(before):
            raise ValueError("changed file")
        while block := os.read(fd, min(65536, limit + 1 - count)):
            count += len(block)
            if count > limit:
                raise ValueError("oversized file")
            if content:
                raw.extend(block)
        if count != opened.st_size or _identity(os.fstat(fd)) != _identity(opened):
            raise ValueError("changed file")
        if _identity(_nonlink_stat(path)) != _identity(opened):
            raise ValueError("changed file")
    finally:
        os.close(fd)
    return {"path": str(path), **_identity(opened)}, bytes(raw)


def _bounded_values(value, depth=0, budget=None):
    """Reject pathological nested inventory data before constructing targets."""
    budget = [32768] if budget is None else budget
    budget[0] -= 1
    if depth > 16 or budget[0] < 0:
        raise ValueError("inventory complexity")
    if isinstance(value, dict):
        if any(not isinstance(k, str) for k in value):
            raise ValueError("invalid keys")
        for item in value.values():
            _bounded_values(item, depth + 1, budget)
    elif isinstance(value, list):
        for item in value:
            _bounded_values(item, depth + 1, budget)
    elif value is not None and type(value) not in (str, int, float, bool):
        raise ValueError("invalid value")


def _validate_target(target):
    data = target.to_dict()
    _bounded_values(data)
    if not isinstance(target.id, str) or not 1 <= len(target.id) <= 256:
        raise ValueError("invalid target")
    if not isinstance(target.name, str) or not isinstance(target.options, dict):
        raise ValueError("invalid target")
    if any(type(getattr(target, k)) is not bool for k in ("in_scope", "simulated", "sudo")):
        raise ValueError("invalid scope")
    if any(v is not None and (not isinstance(v, str) or len(v) > 4096)
           for v in (target.address, target.username, target.credential_ref)):
        raise ValueError("invalid connection")
    if target.port is not None and (type(target.port) is not int or not 1 <= target.port <= 65535):
        raise ValueError("invalid port")
    if not isinstance(target.tags, list) or any(not isinstance(t, str) for t in target.tags):
        raise ValueError("invalid tags")
    for key in _OPTIONS:
        value = target.options.get(key)
        if value is None:
            continue
        if key == "ssl":
            valid = type(value) is bool
        elif key == "critical_services":
            valid = isinstance(value, list) and all(isinstance(v, str) for v in value)
        else:
            valid = isinstance(value, str) and len(value) <= 4096
        if not valid:
            raise ValueError("invalid connection option")
    return data


def _declarations(target):
    data = _validate_target(target)
    return {**{key: data[key] for key in _FIELDS},
            "options": {key: target.options[key] for key in _OPTIONS if key in target.options}}


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate inventory key")
        result[key] = value
    return result


def current_target(ctx, target_id):
    """Return a detached target from a strict persisted snapshot on EVERY call.

    Missing, unreadable, linked, oversized, malformed, or ambiguous inventory
    raises ScopeViolation. Missing/out-of-scope cached targets also fail closed;
    a cache/disk connection-declaration mismatch raises EngineError. The cache
    never supplies authority and is never silently substituted for disk scope.
    Callers must still call target_binding_sha256 on the result for file checks.
    """
    try:
        path = ctx.inventory.path
        _, raw = _read_file(path, MAX_INVENTORY_BYTES, content=True)
        if Path(path).suffix.lower() in (".yaml", ".yml"):
            import yaml
            # Reject aliases and deep/large structures before materializing YAML.
            depth = 0
            for count, event in enumerate(yaml.parse(raw)):
                if isinstance(event, yaml.AliasEvent) or count > 32768:
                    raise ValueError("ambiguous inventory")
                if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                    depth += 1
                elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                    depth -= 1
                if depth > 16:
                    raise ValueError("inventory complexity")
            class UniqueLoader(yaml.SafeLoader):
                def construct_mapping(self, node, deep=False):
                    return _pairs((self.construct_object(k, deep=deep), self.construct_object(v, deep=deep))
                                  for k, v in node.value)
            data = yaml.load(raw, Loader=UniqueLoader)
        else:
            data = json.loads(raw, object_pairs_hook=_pairs,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid number")))
        _bounded_values(data)
        if not isinstance(data, dict) or set(data) != {"targets"} or not isinstance(data["targets"], list):
            raise ValueError("invalid inventory")
        if len(data["targets"]) > 4096:
            raise ValueError("inventory limit")
        targets = {}
        for item in data["targets"]:
            if not isinstance(item, dict) or type(item.get("in_scope")) is not bool:
                raise ValueError("missing explicit scope")
            target = Target.from_dict(item)
            _validate_target(target)
            if target.id in targets:
                raise ValueError("duplicate target")
            targets[target.id] = target
    except Exception:
        # Parser/OS messages may contain file paths or inventory values.
        raise ScopeViolation("current persisted inventory is unverifiable") from None
    target = targets.get(target_id)
    cached = ctx.inventory._targets.get(target_id)
    if target is None or not target.in_scope or cached is None or cached.in_scope is not True:
        raise ScopeViolation("target is not currently in persisted inventory scope")
    try:
        if _declarations(cached) != _declarations(target):
            raise ValueError("cache differs")
    except Exception:
        raise EngineError("cached and persisted target configuration differ; reload inventory") from None
    return deepcopy(target)


def target_binding_sha256(target):
    """Hash allowlisted nonsecret declarations and readable file identity/metadata.

    Environment passwords and all file contents (including kubeconfig auth data)
    are excluded. Credential rotation and privileges are explicitly NOT attested.
    Required files must be regular, nonlinked, readable, stable, and <=1 MiB.
    Ordinary CT_CRED labels are declarations, not required file paths.
    """
    try:
        data = _declarations(target)
        paths = {key: target.options[key] for key in ("key_file", "kubeconfig", "ca_trust_path")
                 if target.options.get(key) is not None}
        if target.transport == "kubeconfig" and not paths.get("kubeconfig"):
            raise ValueError("required kubeconfig missing")
        ref = target.credential_ref
        if ref and target.transport == "ssh" and not paths.get("key_file"):
            if not _LABEL.fullmatch(ref):
                paths["credential_ref"] = ref
            elif os.path.lexists(Path(ref).expanduser()):
                # SSH otherwise treats a coincidentally existing label as a key.
                raise ValueError("ambiguous credential label; use explicit key_file")
        refs = {key: _read_file(value, MAX_FILE_BYTES)[0] for key, value in paths.items()}
        return hashlib.sha256(json.dumps({"version": 2, "target": data, "references": refs},
                                        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                                        allow_nan=False).encode("utf-8")).hexdigest()
    except Exception:
        raise EngineError("target connection binding is unverifiable") from None
