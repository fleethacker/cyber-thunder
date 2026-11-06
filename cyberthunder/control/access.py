"""Bounded server-managed resource ACLs; no implicit role or claim grants."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
from contextlib import ExitStack, contextmanager
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
MAX_PATH_PARTS = 128
# Deliberately enumerated independently of roles: new actions require review here.
ACTIONS = frozenset({"read", "read.all", "scan", "discover", "propose", "explain", "plan", "import",
                     "approve", "deny", "cancel", "apply", "rollback", "verify", "review", "risk.accept", "maintenance.override",
                     "admin", "policy", "audit", "export", "kill.engage", "kill.release"})
NODE_ONLY_ACTIONS = frozenset({"read.all"})


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
    return (_node_identity(info), info.st_nlink, info.st_size, info.st_mtime_ns)


def _node_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
            getattr(info, "st_reparse_tag", 0))


def _check_node(info, *, directory=False):
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or getattr(info, "st_reparse_tag", 0)):
        raise ValueError("policy path redirects")
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("policy parent is not a directory")
    elif (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
          or not 0 <= info.st_size <= MAX_POLICY_BYTES):
        raise ValueError("invalid policy file")
    if os.name == "posix":
        if info.st_uid not in {0, os.geteuid()}:
            raise ValueError("untrusted policy owner")
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            # Root-owned sticky ancestors (e.g. /tmp) protect each trusted-owned
            # child against replacement by another user. Never exempt the file.
            if not (directory and info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
                raise ValueError("policy path is writable by other accounts")
    # Windows ownership and DACL checks run on the pinned native handles below.


def _parents(path):
    if not path.is_absolute() or ".." in path.parts or len(path.parts) > MAX_PATH_PARTS:
        raise ValueError("policy requires a bounded absolute path")
    parents = []
    # Do not resolve(): that would erase evidence of a redirected component.
    for parent in reversed(path.parents):
        info = parent.lstat()
        _check_node(info, directory=True)
        parents.append((parent, _node_identity(info)))
    return tuple(parents)


@contextmanager
def _open_policy(path, parents):
    if os.name == "nt":
        from cyberthunder.security.file_trust import open_protected
        with open_protected(path) as stream:
            yield stream
        return
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    with ExitStack() as stack:
        if os.name == "posix":
            # Anchor traversal to checked descriptors so swapping a pathname
            # cannot redirect a later component between lstat and open.
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
            parent_fd = None
            for parent, identity in parents:
                fd = os.open(parent if parent_fd is None else parent.name, directory_flags, dir_fd=parent_fd)
                stack.callback(os.close, fd)
                info = os.fstat(fd)
                _check_node(info, directory=True)
                if _node_identity(info) != identity:
                    raise ValueError("policy parent replaced while opening")
                parent_fd = fd
            fd = os.open(path.name, flags, dir_fd=parent_fd)
        else:
            fd = os.open(path, flags)
        try:
            stream = os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise
        with stream:
            yield stream


@dataclass(frozen=True)
class _Grant:
    actions: tuple[str, ...]
    target_ids: tuple[str, ...] | None
    environments: tuple[str, ...] | None
    credential: CredentialBinding | None

    def matches(self, action, tid, environment):
        if action in {"risk.accept", "maintenance.override"} and (not self.target_ids or not self.environments
                                       or "*" in self.target_ids or "*" in self.environments):
            return False
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
    person_id: str | None = None

    @property
    def identity(self):
        return self.issuer, self.kind, self.selector


def person_identifier(value):
    """An opaque policy identifier, never a name, email or identity claim."""
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value) is None:
        raise ValueError("invalid person association identifier")
    return value


@dataclass(frozen=True)
class ApprovalIdentitySource:
    """One protected file observation; associations confer no account permissions."""

    policy_version: int
    policy_sha256: str
    namespace: str | None = None
    revision: int | None = None
    mappings: tuple[tuple[str, str, str], ...] = ()

    @property
    def basis(self):
        if self.policy_version == 1:
            return {"mode": "account", "policy_version": 1}
        return {"mode": "person", "policy_version": 2, "version": 1,
                "namespace": self.namespace, "revision": self.revision,
                "policy_sha256": self.policy_sha256}

    def association(self, issuer, subject):
        matches = [person for iss, sub, person in self.mappings if (iss, sub) == (issuer, subject)]
        if self.policy_version != 2 or len(matches) != 1:
            raise AccessDenied("an exact protected person association is required")
        return {"issuer": issuer, "subject": subject, "person_id": matches[0], "source": self.basis}


@dataclass(frozen=True)
class _Policy:
    entries: tuple[_Entry, ...]
    version: int
    namespace: str | None
    revision: int | None


def _parse(raw):
    _depth(raw)
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=_object, parse_constant=_constant)
    _fields(document, {"version", "entries"}, {"approval_identity"})
    version = document["version"]
    if type(version) is not int or version not in {1, 2}:
        raise ValueError("unsupported policy version")
    namespace = revision = None
    if version == 1:
        if "approval_identity" in document:
            raise ValueError("person association requires policy version 2")
    else:
        config = document.get("approval_identity")
        _fields(config, {"mode", "version", "namespace", "revision"})
        if config["mode"] != "person" or type(config["version"]) is not int or config["version"] != 1:
            raise ValueError("unsupported person association mode")
        namespace = person_identifier(config["namespace"])
        revision = config["revision"]
        if type(revision) is not int or not 1 <= revision <= 2**53 - 1:
            raise ValueError("invalid person association revision")
    rows = document["entries"]
    if not isinstance(rows, list) or len(rows) > MAX_ENTRIES:
        raise ValueError("invalid policy entries")
    entries, selectors, total = [], set(), 0
    for row in rows:
        _fields(row, {"issuer", "node_actions", "grants"},
                {"subject", "group", "person_id"} if version == 2 else {"subject", "group"})
        if ("subject" in row) == ("group" in row):
            raise ValueError("one account selector is required")
        kind = "subject" if "subject" in row else "group"
        person_id = None
        if "person_id" in row:
            if kind != "subject":
                raise ValueError("groups cannot identify a person")
            person_id = person_identifier(row["person_id"])
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
            if NODE_ONLY_ACTIONS.intersection(actions):
                raise ValueError("node-only actions cannot appear in resource grants")
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
        entries.append(_Entry(issuer, kind, selector, node_actions, tuple(grants), person_id))
    return _Policy(tuple(entries), version, namespace, revision)


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


def read_protected_policy(path, parser):
    try:
        parents = _parents(path)
        before = path.lstat()
        _check_node(before)
        with _open_policy(path, parents) as stream:
            opened = os.fstat(stream.fileno())
            _check_node(opened)
            if _signature(before) != _signature(opened):
                raise ValueError("policy replaced while opening")
            raw = stream.read(MAX_POLICY_BYTES + 1)
            read = os.fstat(stream.fileno())
            _check_node(read)
            if (len(raw) > MAX_POLICY_BYTES or _signature(opened) != _signature(read)
                    or opened.st_ctime_ns != read.st_ctime_ns):
                raise ValueError("policy changed while reading")
            policy = parser(raw)
            after = path.lstat()
            _check_node(after)
            if (_signature(opened) != _signature(after) or before.st_ctime_ns != after.st_ctime_ns
                    or parents != _parents(path)):
                raise ValueError("policy replaced during decision")
            return policy, hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError, TypeError, RecursionError):
        raise AccessDenied("access policy is unavailable or invalid") from None


class AccessPolicy:
    """Read-only ACL facade; construct with a server-controlled absolute policy path."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _read(self):
        return read_protected_policy(self.path, _parse)

    def _load(self):
        policy, digest = self._read()
        return policy.entries, digest

    def approval_identity_source(self) -> ApprovalIdentitySource:
        policy, digest = self._read()
        return ApprovalIdentitySource(policy.version, digest, policy.namespace, policy.revision,
                                      tuple((e.issuer, e.selector, e.person_id) for e in policy.entries
                                            if e.kind == "subject" and e.person_id is not None))

    def _matching(self, principal, action, target):
        entries, digest = self._load()
        try:
            if not isinstance(action, str) or action not in ACTIONS:
                raise ValueError("unknown action")
            issuer, subject, groups = _principal(principal)
            tid = environment = None
            if target is not None:
                tid, environment = _identifier(target.id), _identifier(getattr(target, "environment", "default"))
                in_scope = getattr(target, "in_scope", None)
                if type(in_scope) is not bool or (not in_scope and action in {
                        "scan", "discover", "propose", "approve", "plan", "apply", "rollback", "verify", "maintenance.override"}):
                    raise ValueError("target is outside inventory scope")
            matched = []
            for entry in entries:
                if entry.issuer != issuer:
                    continue
                # Risk acceptance is an explicit account/environment/target grant.
                # Group membership, person association and node grants cannot supply it.
                if action in {"risk.accept", "maintenance.override"} and (target is None or entry.kind != "subject"):
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
