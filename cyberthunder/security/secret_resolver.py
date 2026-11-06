"""Explicit account-bound secret sources and short-lived, redacted value leases.

Configuration contains references only. The caller supplies fresh authorization
and a durable event sink; neither a reference nor a lease establishes authority.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from types import MappingProxyType
import uuid

from cyberthunder.control.principal import Principal
from .credentials import BindingProvenance, CredentialBinding, target_identity


MAX_SECRET_BYTES = 16384
MAX_REGISTRY_BYTES = 262144
MAX_REGISTRY_ENTRIES = 256
_ALIAS = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}")
_KEY = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}")
_PURPOSES = frozenset({"scan", "discover", "plan", "apply", "rollback", "verify"})


class SecretResolutionError(PermissionError):
    """Fixed, public diagnostics without provider exceptions or secret material."""


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _source_identity(source):
    if isinstance(source, EnvironmentSecret):
        return ("env", source.name)
    if isinstance(source, MountedSecret):
        return ("mounted", source.root, source.key, source.layout, source.reader_gid)
    if isinstance(source, WindowsCredential):
        return ("wincred", source.target_name)
    raise ValueError("unsupported credential backend")


def _alias(value):
    if not isinstance(value, str) or not _ALIAS.fullmatch(value):
        raise ValueError("invalid credential alias")
    return value


def _path(value):
    if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(c) < 32 for c in value):
        raise ValueError("invalid secret mount")
    path = Path(value)
    if (not path.is_absolute() or len(path.parts) > 128 or ".." in path.parts
            or value.startswith(("//", "\\\\")) or any(c in value for c in "$%*?~")):
        raise ValueError("invalid secret mount")
    return path


@dataclass(frozen=True)
class EnvironmentSecret:
    """Explicit development source; never reads an unprefixed environment name."""
    name: str = field(repr=False)

    def __post_init__(self):
        _alias(self.name)


@dataclass(frozen=True)
class MountedSecret:
    """One administrator-selected root/key; Kubernetes projection is opt-in."""
    root: str = field(repr=False)
    key: str = field(repr=False)
    layout: str = "regular"
    reader_gid: int | None = None

    def __post_init__(self):
        _path(self.root)
        if not isinstance(self.key, str) or not _KEY.fullmatch(self.key):
            raise ValueError("invalid secret key")
        if self.layout not in {"regular", "kubernetes"}:
            raise ValueError("unsupported secret mount layout")
        if self.reader_gid is not None and (self.layout != "kubernetes"
                or type(self.reader_gid) is not int or self.reader_gid < 0):
            raise ValueError("invalid secret reader group")


@dataclass(frozen=True)
class WindowsCredential:
    """Exact generic credential target; no enumeration or alias fallback."""
    target_name: str = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.target_name, str) or not re.fullmatch(
                r"CyberThunder/v1/[a-f0-9]{64}/[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}", self.target_name):
            raise ValueError("invalid native credential target")


def windows_target_name(binding: CredentialBinding, principal: Principal, target) -> str:
    """Deterministic provisioning name, scoped to subject, action and target generation."""
    alias = _alias(binding.credential_ref)
    p = binding.provenance
    if (not isinstance(p, BindingProvenance) or p.target != target_identity(target)
            or (p.issuer, p.subject) != (principal.issuer, principal.subject)):
        raise ValueError("invalid credential scope")
    generation = getattr(target, "authorization_id", None)
    if not isinstance(generation, str) or not re.fullmatch(r"[a-f0-9]{32,64}", generation):
        raise ValueError("invalid target generation")
    scope = (p.issuer, p.subject, p.action, p.target, generation, binding.username)
    return "CyberThunder/v1/" + _digest(scope) + "/" + alias


@dataclass(frozen=True)
class CredentialEvent:
    action: str
    backend: str
    purpose: str
    target: str
    target_fingerprint: str
    account_fingerprint: str
    reference_fingerprint: str
    lease_id: str
    reason: str | None = None

    def to_dict(self):
        return dict(self.__dict__)


class Secret:
    """Access only within its lease. Python/provider copies cannot be zeroized reliably."""
    __slots__ = ("_buffer", "_lease")

    def __init__(self, value, lease):
        self._buffer, self._lease = bytearray(value), lease

    def __repr__(self):
        return "Secret(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol):
        raise TypeError("secrets cannot be serialized")

    def reveal(self) -> str:
        self._lease.check()
        return self._buffer.decode("utf-8")

    def _clear(self):
        self._buffer[:] = b"\0" * len(self._buffer)
        self._buffer.clear()


class Lease:
    __slots__ = ("_use", "_secret", "_deadline", "_entered", "_closed", "lease_id")

    def __init__(self, use):
        self._use, self._secret = use, None
        self._deadline, self._entered, self._closed = 0.0, False, False
        self.lease_id = uuid.uuid4().hex

    def __repr__(self):
        return "Lease(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, protocol):
        raise TypeError("credential leases cannot be serialized")

    def __enter__(self):
        if self._entered or self._closed:
            raise SecretResolutionError("Credential lease is unavailable")
        self._entered = True
        self._deadline = time.monotonic() + self._use.lease_seconds
        failed = False
        try:
            self.check()
            raw = self._use._read()
            if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_SECRET_BYTES:
                raise ValueError
            text = raw.decode("utf-8")
            if "\0" in text:
                raise ValueError
            del text
            self._secret = Secret(raw, self)
            del raw
            self.check()
            self._use._event("credential.resolve", self.lease_id)
            self.check()
        except Exception:
            failed = True
        except BaseException:
            self.close()
            raise
        if failed:
            self.close()
            self._use._event("credential.failed", self.lease_id, "resolution")
            raise SecretResolutionError("Credential resolution was refused") from None
        return self

    def check(self):
        if not self._entered or self._closed or time.monotonic() >= self._deadline:
            self.close()
            raise SecretResolutionError("Credential lease is unavailable or expired")
        try:
            self._use.check()
            # Authorization may involve blocking policy/registry I/O. Its
            # return must not release a value after this lease's deadline.
            if self._closed or time.monotonic() >= self._deadline:
                raise SecretResolutionError("Credential lease is unavailable or expired")
        except BaseException:
            self.close()
            raise

    @property
    def secret(self):
        self.check()
        if self._secret is None:
            raise SecretResolutionError("Credential lease is unavailable")
        return self._secret

    def remaining(self):
        self.check()
        return max(0.0, self._deadline - time.monotonic())

    def authentication_failed(self):
        self._use._event("credential.failed", self.lease_id, "authentication")

    def close(self):
        self._closed = True
        if self._secret is not None:
            self._secret._clear()
            self._secret = None

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self.check()
        finally:
            self.close()


@dataclass(frozen=True, repr=False)
class CredentialUse:
    binding: CredentialBinding
    principal: Principal
    target_generation: str
    backend: str
    security_mode: str
    source: object = field(repr=False)
    lease_seconds: int
    guard: object = field(repr=False)
    on_event: object = field(repr=False)

    def __post_init__(self):
        if (not isinstance(self.binding, CredentialBinding) or not isinstance(self.principal, Principal)
                or not isinstance(self.binding.provenance, BindingProvenance)
                or _source_identity(self.source)[0] != self.backend
                or self.security_mode not in {"range", "fleet"}
                or self.backend == "env" and self.security_mode == "fleet"
                or self.backend != "env" and (not self.principal.verified or self.principal.expires_at is None)
                or type(self.lease_seconds) is not int or not 1 <= self.lease_seconds <= 60
                or not callable(self.guard) or not callable(self.on_event)):
            raise ValueError("invalid credential use")

    def __repr__(self):
        return "CredentialUse(<references redacted>)"

    def check(self):
        failed = False
        try:
            if self.principal.expires_at is not None and self.principal.expires_at <= time.time():
                raise ValueError
            self.guard()
            if self.principal.expires_at is not None and self.principal.expires_at <= time.time():
                raise ValueError
        except Exception:
            failed = True
        if failed:
            raise SecretResolutionError("Credential use is no longer authorized") from None

    def matches_target(self, target):
        self.check()
        b = self.binding
        if (target_identity(target) != b.provenance.target
                or target.authorization_id != self.target_generation
                or (target.username, target.credential_ref, target.sudo) != (b.username, b.credential_ref, b.sudo)):
            raise SecretResolutionError("Credential use does not match this target")

    def lease(self) -> Lease:
        return Lease(self)

    def _event(self, action, lease_id, reason=None):
        p = self.binding.provenance
        event = CredentialEvent(action, self.backend, p.action, p.target[0],
            _digest((p.target, self.target_generation)), _digest((p.issuer, p.subject, self.binding.username)),
            _digest((_source_identity(self.source), self.binding.credential_ref)), lease_id, reason)
        failed = False
        try:
            self.on_event(event)
        except Exception:
            failed = True
        if failed:
            raise SecretResolutionError("Credential event could not be recorded") from None

    def event_details(self, event):
        """Allowlisted sink metadata, tied to this captured binding, never values."""
        p = self.binding.provenance
        if (type(event) is not CredentialEvent or event.action not in {"credential.resolve", "credential.failed"}
                or event.backend != self.backend or event.purpose != p.action or event.target != p.target[0]
                or event.target_fingerprint != _digest((p.target, self.target_generation))
                or event.account_fingerprint != _digest((p.issuer, p.subject, self.binding.username))
                or event.reference_fingerprint != _digest((_source_identity(self.source), self.binding.credential_ref))
                or not isinstance(event.lease_id, str) or not re.fullmatch(r"[a-f0-9]{32}", event.lease_id)
                or (event.reason is not None if event.action == "credential.resolve"
                    else event.reason not in {"resolution", "authentication"})):
            raise SecretResolutionError("Credential event was refused")
        return {"backend": event.backend, "purpose": event.purpose, "target": event.target,
                "target_fingerprint": event.target_fingerprint, "account_fingerprint": event.account_fingerprint,
                "reference_fingerprint": event.reference_fingerprint, "lease_id": event.lease_id,
                "reason": event.reason}

    def _read(self):
        if isinstance(self.source, EnvironmentSecret):
            value = os.environ.get("CT_CRED_" + self.source.name)
            return value.encode("utf-8") if value is not None else b""
        if isinstance(self.source, MountedSecret):
            return _read_mounted(self.source)
        if isinstance(self.source, WindowsCredential):
            from ._wincred import read_password
            return read_password(self.source.target_name, self.binding.username)
        raise ValueError


class SecretResolver:
    """Immutable server-side alias registry. Inventory cannot configure providers."""
    def __init__(self, sources, *, security_mode: str, auth_mode: str, lease_seconds: int = 30):
        if (security_mode not in {"range", "fleet"} or auth_mode not in {"dev", "oidc", "mesh"}
                or security_mode == "fleet" and auth_mode == "dev"
                or type(lease_seconds) is not int or not 1 <= lease_seconds <= 60):
            raise ValueError("invalid credential resolver profile")
        entries = dict(sources)
        if not 1 <= len(entries) <= MAX_REGISTRY_ENTRIES:
            raise ValueError("invalid credential registry size")
        for name, source in entries.items():
            _alias(name)
            if type(source) not in {EnvironmentSecret, MountedSecret, WindowsCredential}:
                raise ValueError("unsupported credential backend")
            if isinstance(source, EnvironmentSecret) and (security_mode != "range" or auth_mode != "dev"):
                raise ValueError("environment credentials require the development range profile")
        self._sources = MappingProxyType(entries)
        self.lease_seconds = lease_seconds
        self.security_mode = security_mode
        self.fingerprint = _digest({name: _source_identity(source) for name, source in entries.items()})

    def resolve(self, binding: CredentialBinding, *, principal: Principal, target, purpose: str,
                guard, on_event) -> Lease:
        return self.bind(binding, principal=principal, target=target, purpose=purpose,
                         guard=guard, on_event=on_event).lease()

    def bind(self, binding: CredentialBinding, *, principal: Principal, target, purpose: str,
             guard, on_event) -> CredentialUse:
        failed = False
        try:
            if (not isinstance(binding, CredentialBinding) or not isinstance(principal, Principal)
                    or not isinstance(binding.provenance, BindingProvenance)
                    or purpose not in _PURPOSES or not callable(guard) or not callable(on_event)):
                raise ValueError
            p = binding.provenance
            if (p.action != purpose or (p.issuer, p.subject) != (principal.issuer, principal.subject)
                    or p.target != target_identity(target) or p.target[3] not in {"ssh", "winrm"}
                    or not target.in_scope or not binding.username or binding.options.keys() - {"transport"}):
                raise ValueError
            source = self._sources[_alias(binding.credential_ref)]
            if not isinstance(source, EnvironmentSecret) and (not principal.verified or principal.expires_at is None):
                raise ValueError
            expected = windows_target_name(binding, principal, target)
            if isinstance(source, WindowsCredential) and source.target_name != expected:
                raise ValueError
            backend = {EnvironmentSecret: "env", MountedSecret: "mounted", WindowsCredential: "wincred"}[type(source)]
            use = CredentialUse(binding, principal, target.authorization_id, backend, self.security_mode, source,
                                self.lease_seconds, guard, on_event)
            use.check()
        except Exception:
            failed = True
        if failed:
            raise SecretResolutionError("Credential binding or backend is unavailable") from None
        return use


def _identity(info, *, contents=False):
    identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)
    return identity + (info.st_size, info.st_mtime_ns, info.st_ctime_ns) if contents else identity


def _protect(info, *, directory=False, projected=False, readonly=False, reader_gid=None,
             private=True, maximum=MAX_SECRET_BYTES):
    if info.st_uid not in {0, os.geteuid()}:
        raise ValueError
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError
        if info.st_mode & 0o022 and not (
                info.st_uid == 0 and (info.st_mode & stat.S_ISVTX or projected and readonly)):
            raise ValueError
    else:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= maximum:
            raise ValueError
        forbidden = 0o077 if private else 0o022
        if projected and reader_gid is not None and info.st_gid == reader_gid == os.getegid():
            forbidden = 0o037  # An explicitly dedicated reader group may only read.
        if info.st_mode & forbidden:
            raise ValueError


def _read_mounted(source, *, private=True, maximum=MAX_SECRET_BYTES):
    root = _path(source.root)
    path = root / source.key
    if os.name == "nt":
        if source.layout != "regular":
            raise ValueError
        from .file_trust import open_protected
        with open_protected(path, private=private) as stream:
            before = os.fstat(stream.fileno())
            if not 0 < before.st_size <= maximum:
                raise ValueError
            value = stream.read(maximum + 1)
            if (_identity(before, contents=True) != _identity(os.fstat(stream.fileno()), contents=True)
                    or len(value) != before.st_size):
                raise ValueError
        return value
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError
    # dir_fd traversal pins every directory and rejects redirects before opening
    # the next component. Never resolve() an untrusted pathname.
    with ExitStack() as stack:
        chain = []
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        parent = os.open(root.anchor, flags)
        stack.callback(os.close, parent)
        _protect(os.fstat(parent), directory=True)
        for index, part in enumerate(root.parts[1:]):
            fd = os.open(part, flags, dir_fd=parent)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            projected = source.layout == "kubernetes" and index == len(root.parts) - 2
            _protect(info, directory=True, projected=projected,
                     readonly=bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY))
            chain.append((parent, part, fd, _identity(info)))
            parent = fd
        mount = parent
        links = []
        if source.layout == "kubernetes":
            for name in (source.key, "..data"):
                info = os.stat(name, dir_fd=mount, follow_symlinks=False)
                if not stat.S_ISLNK(info.st_mode) or info.st_uid not in {0, os.geteuid()}:
                    raise ValueError
                value = os.readlink(name, dir_fd=mount)
                links.append((name, value, _identity(info, contents=True)))
            if links[0][1] != "..data/" + source.key:
                raise ValueError
            generation = links[1][1]
            if (not re.fullmatch(r"\.\.[A-Za-z0-9_.-]{1,128}", generation)
                    or generation in {"...", "..data", "..data_tmp"}):
                raise ValueError
            fd = os.open(generation, flags, dir_fd=mount)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            _protect(info, directory=True, projected=True,
                     readonly=bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY))
            chain.append((mount, generation, fd, _identity(info)))
            parent = fd
        fd = os.open(source.key, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        stack.callback(os.close, fd)
        before = os.fstat(fd)
        _protect(before, projected=source.layout == "kubernetes", reader_gid=source.reader_gid,
                 private=private, maximum=maximum)
        value = os.read(fd, maximum + 1)
        if (_identity(before, contents=True) != _identity(os.fstat(fd), contents=True)
                or _identity(before, contents=True) != _identity(os.stat(source.key, dir_fd=parent,
                                                                       follow_symlinks=False), contents=True)
                or len(value) != before.st_size):
            raise ValueError
        for name, destination, stamp in links:
            if (os.readlink(name, dir_fd=mount) != destination
                    or _identity(os.stat(name, dir_fd=mount, follow_symlinks=False), contents=True) != stamp):
                raise ValueError
        for ancestor, name, fd, stamp in chain:
            if (_identity(os.fstat(fd)) != stamp
                    or _identity(os.stat(name, dir_fd=ancestor, follow_symlinks=False)) != stamp):
                raise ValueError
        return value


def load_registry(path, *, security_mode, auth_mode):
    """Read a protected v1 registry afresh. No credential provider is accessed.

    None is the sole unconfigured value. Explicit empty/relative paths, failed
    reads and unsupported declarations never enable legacy fallback.
    """
    if path is None:
        return None
    failed = False
    try:
        if auth_mode not in {"oidc", "mesh"}:
            raise ValueError
        location = _path(os.fspath(path))
        raw = _read_mounted(MountedSecret(str(location.parent), location.name),
                            private=False, maximum=MAX_REGISTRY_BYTES)

        def object_pairs(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result

        def constant(_value):
            raise ValueError

        document = json.loads(raw.decode("utf-8"), object_pairs_hook=object_pairs, parse_constant=constant)
        if (type(document) is not dict or set(document) != {"version", "sources"}
                or type(document["version"]) is not int or document["version"] != 1
                or type(document["sources"]) is not dict
                or not 1 <= len(document["sources"]) <= MAX_REGISTRY_ENTRIES):
            raise ValueError
        sources = {}
        for alias, declaration in document["sources"].items():
            _alias(alias)
            if type(declaration) is not dict:
                raise ValueError
            provider = declaration.get("provider")
            if provider == "mounted":
                if (not {"provider", "root", "key"} <= declaration.keys()
                        or declaration.keys() - {"provider", "root", "key", "layout", "reader_gid"}
                        or "reader_gid" in declaration and type(declaration["reader_gid"]) is not int):
                    raise ValueError
                source = MountedSecret(declaration["root"], declaration["key"],
                    declaration.get("layout", "regular"), declaration.get("reader_gid"))
            elif provider == "wincred":
                if set(declaration) != {"provider", "target_name"}:
                    raise ValueError
                source = WindowsCredential(declaration["target_name"])
            else:
                raise ValueError
            sources[alias] = source
        resolver = SecretResolver(sources, security_mode=security_mode, auth_mode=auth_mode)
        # Pin the complete document, including version and future settings, as
        # well as the source declarations. Formatting alone does not revoke use.
        resolver.fingerprint = _digest(document)
    except Exception:
        failed = True
    if failed:
        raise SecretResolutionError("Credential source registry is unavailable or unsafe") from None
    return resolver
