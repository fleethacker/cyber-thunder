"""Bounded server-managed resource ACLs; no implicit role or claim grants."""
from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import time
from dataclasses import dataclass, replace
from pathlib import Path

from cyberthunder.security.credentials import (
    BindingProvenance, CredentialBinding, CredentialError, bind_target, target_identity,
)


MAX_POLICY_BYTES = 256 * 1024
MAX_ENTRIES = 256
MAX_GRANTS = 2048
MAX_ITEMS = 128
MAX_DEPTH = 12
# Deliberately enumerated independently of roles: new actions require review here.
ACTIONS = frozenset({"read", "scan", "discover", "propose", "explain", "plan", "import",
                     "approve", "deny", "cancel", "apply", "rollback", "verify", "review",
                     "admin", "policy", "audit", "export", "kill.engage", "kill.release"})


class AccessDenied(PermissionError):
    """Sanitized authorization failure suitable for a server boundary."""


def _text(value):
    if (not isinstance(value, str) or not value or len(value) > 512 or value != value.strip()
            or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value)):
        raise ValueError("invalid policy text")
    return value


def _identifier(value):
    value = _text(value)
    if any(c in value for c in "*?[]"):
        raise ValueError("patterns are not selectors")
    return value


def _fields(value, required, optional=frozenset()):
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise ValueError("invalid policy fields")


def _strings(value, *, actions=False, scope=False, empty=False):
    if not isinstance(value, list) or len(value) > MAX_ITEMS or (not value and not empty):
        raise ValueError("invalid policy list")
    values = tuple(_text(v) for v in value)
    if len(set(values)) != len(values):
        raise ValueError("duplicate policy item")
    if actions:
        if set(values) - ACTIONS:
            raise ValueError("unknown policy action")
    elif scope and values == ("*",):
        return values
    else:
        for v in values:
            _identifier(v)
    return tuple(sorted(values))


def _object(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("duplicate JSON key")
        result[k] = v
    return result


def _constant(_):
    raise ValueError("non-finite JSON number")


def _depth(raw):
    depth = 0
    quoted = escaped = False
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        elif char == 34:
            quoted = True
        elif char in (91, 123):
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("policy nesting limit")
        elif char in (93, 125):
            depth -= 1


def _signature(info):
    # Windows Python can report different ctime meanings for path and fd stats.
    # Compare ctime only between observations obtained through the same interface.
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


@dataclass(frozen=True)
class _Grant:
    actions: tuple[str, ...]
    target_ids: tuple[str, ...] | None
    environments: tuple[str, ...] | None
    credential: CredentialBinding | None

    def matches(self, action, tid, environment):
        return (action in self.actions
                and (self.target_ids is None or self.target_ids == ("*",) or tid in self.target_ids)
                and (self.environments is None or self.environments == ("*",) or environment in self.environments))


@dataclass(frozen=True)
class _Entry:
    issuer: str
    kind: str
    selector: str
    node_actions: tuple[str, ...]
    grants: tuple[_Grant, ...]

    @property
    def identity(self):
        return self.issuer, self.kind, self.selector


def _parse(raw):
    _depth(raw)
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=_object, parse_constant=_constant)
    _fields(document, {"version", "entries"})
    if type(document["version"]) is not int or document["version"] != 1:
        raise ValueError("unsupported policy version")
    rows = document["entries"]
    if not isinstance(rows, list) or len(rows) > MAX_ENTRIES:
        raise ValueError("invalid policy entries")
    entries, selectors, total = [], set(), 0
    for row in rows:
        _fields(row, {"issuer", "node_actions", "grants"}, {"subject", "group"})
        if ("subject" in row) == ("group" in row):
            raise ValueError("one account selector is required")
        kind = "subject" if "subject" in row else "group"
        issuer, selector = _text(row["issuer"]), _identifier(row[kind])
        if "*" in issuer:
            raise ValueError("issuer must be exact")
        identity = issuer, kind, selector
        if identity in selectors:
            raise ValueError("duplicate account selector")
        selectors.add(identity)
        node_actions = _strings(row["node_actions"], actions=True, empty=True)
        source_grants = row["grants"]
        if not isinstance(source_grants, list) or len(source_grants) > 64:
            raise ValueError("invalid resource grants")
        total += len(source_grants)
        if total > MAX_GRANTS:
            raise ValueError("policy grant limit")
        grants, seen = [], set()
        for g in source_grants:
            _fields(g, {"actions"}, {"target_ids", "environments", "credential"})
            if "target_ids" not in g and "environments" not in g:
                raise ValueError("resource selector is required")
            actions = _strings(g["actions"], actions=True)
            targets = _strings(g["target_ids"], scope=True) if "target_ids" in g else None
            environments = _strings(g["environments"], scope=True) if "environments" in g else None
            signature = actions, targets, environments
            if signature in seen:
                raise ValueError("duplicate resource grant")
            seen.add(signature)
            credential = None
            if "credential" in g:
                c = g["credential"]
                _fields(c, {"username", "credential_ref", "sudo", "options"})
                credential = CredentialBinding(**c)
            grants.append(_Grant(actions, targets, environments, credential))
        entries.append(_Entry(issuer, kind, selector, node_actions, tuple(grants)))
    return tuple(entries)


def _principal(principal):
    if getattr(principal, "verified", None) is not True:
        raise ValueError("verified principal required")
    issuer = _text(principal.issuer)
    subject = _identifier(principal.subject)
    groups = principal.groups
    if not isinstance(groups, (tuple, list)) or len(groups) > 64:
        raise ValueError("invalid trusted groups")
    groups = tuple(_identifier(g) for g in groups)
    if len(set(groups)) != len(groups):
        raise ValueError("duplicate trusted group")
    expiry = principal.expires_at
    if (type(expiry) not in {int, float} or not math.isfinite(expiry) or expiry <= time.time()):
        raise ValueError("expired principal")
    return issuer, subject, groups


class AccessPolicy:
    """Read-only ACL facade; construct with a server-controlled absolute policy path."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _load(self):
        try:
            before = self.path.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_POLICY_BYTES:
                raise ValueError("invalid policy file")
            flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
            with os.fdopen(os.open(self.path, flags), "rb") as stream:
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode) or _signature(before) != _signature(opened):
                    raise ValueError("policy replaced while opening")
                raw = stream.read(MAX_POLICY_BYTES + 1)
                read = os.fstat(stream.fileno())
                if (len(raw) > MAX_POLICY_BYTES or _signature(opened) != _signature(read)
                        or opened.st_ctime_ns != read.st_ctime_ns):
                    raise ValueError("policy changed while reading")
            entries = _parse(raw)
            after = self.path.lstat()
            if _signature(opened) != _signature(after) or before.st_ctime_ns != after.st_ctime_ns:
                raise ValueError("policy replaced during decision")
            return entries, hashlib.sha256(raw).hexdigest()
        except (OSError, ValueError, TypeError, RecursionError):
            raise AccessDenied("access policy is unavailable or invalid") from None

    def _matching(self, principal, action, target):
        entries, digest = self._load()
        try:
            if not isinstance(action, str) or action not in ACTIONS:
                raise ValueError("unknown action")
            issuer, subject, groups = _principal(principal)
            tid = environment = None
            if target is not None:
                tid, environment = _identifier(target.id), _identifier(getattr(target, "environment", "default"))
                if getattr(target, "in_scope", None) is not True:
                    raise ValueError("target is outside inventory scope")
            matched = []
            for entry in entries:
                if entry.issuer != issuer:
                    continue
                if not ((entry.kind == "subject" and entry.selector == subject)
                        or (entry.kind == "group" and entry.selector in groups)):
                    continue
                if target is None:
                    if action in entry.node_actions:
                        matched.append((entry, None))
                else:
                    matched.extend((entry, grant) for grant in entry.grants
                                   if grant.matches(action, tid, environment))
            if not matched:
                raise ValueError("no grant")
            return matched, digest, issuer, subject
        except (AttributeError, TypeError, ValueError, OverflowError):
            raise AccessDenied("principal has no access to this action and resource") from None

    def allows(self, principal, action: str, target=None) -> bool:
        try:
            self.require(principal, action, target)
            return True
        except AccessDenied:
            return False

    def require(self, principal, action: str, target=None) -> None:
        self._matching(principal, action, target)

    def visible_targets(self, principal, targets) -> list:
        return [target for target in targets if self.allows(principal, "read", target)]

    def credential(self, principal, action: str, target) -> CredentialBinding:
        try:
            identity = target_identity(target)
        except (AttributeError, TypeError, ValueError):
            raise AccessDenied("invalid target for credential selection") from None
        matched, digest, issuer, subject = self._matching(principal, action, target)
        try:
            if identity != target_identity(target):
                raise CredentialError("target changed during credential selection")
            bindings = [g.credential for _, g in matched if g is not None and g.credential is not None]
            if not bindings:
                if target.transport != "simulated":
                    raise CredentialError("no account binding for this action and target")
                binding = CredentialBinding(None, None, False, {})
                selectors = tuple(sorted({e.identity for e, _ in matched}))
            else:
                binding = bindings[0]
                if any(b != binding for b in bindings[1:]):
                    raise CredentialError("multiple distinct account bindings match")
                selectors = tuple(sorted({e.identity for e, g in matched if g.credential is not None}))
            provenance = BindingProvenance(issuer, subject, action, identity, digest, selectors)
            binding = replace(binding, provenance=provenance)
            bind_target(target, binding)  # Validate source/transport without resolving any credential.
            return binding
        except (AttributeError, TypeError, ValueError, CredentialError):
            raise AccessDenied("no unambiguous credential binding for this action and target") from None
