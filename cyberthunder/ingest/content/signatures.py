"""Operator attestations for offline content, using a restricted flattened JWS profile.

This is never evidence of a DISA signature. Trust comes only from configured keys.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from urllib.parse import urlsplit
from types import MappingProxyType
from typing import Mapping

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MAX_DOCUMENT = 512 * 1024
MAX_ENVELOPE = 1024 * 1024
MAX_FILES = 512
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_BUNDLE_BYTES = 2 * 1024 * 1024 * 1024
TYPE = "application/vnd.cyberthunder.content+jws"
_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_HASH = re.compile(r"[a-f0-9]{64}\Z")
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_receipt = ContextVar("content_attestation", default=None)


class AuthenticityError(ValueError):
    """Fixed diagnostics: never include keys, passwords or untrusted document values."""


def _fail():
    raise AuthenticityError("Content attestation is invalid or unavailable") from None


def _text(value, maximum=2048):
    if (not isinstance(value, str) or not value or len(value) > maximum
            or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value)):
        _fail()
    return value


def filename(value):
    from .fetch import disk_name
    if (not isinstance(value, str) or not value or len(value) > 200
            or disk_name(value) != value or value.endswith((".", " "))):
        _fail()
    return value


def _object(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            _fail()
        result[k] = v
    return result


def canonical(value):
    """Profile: sorted keys, ASCII JSON escapes, compact separators, no floats."""
    def check(v, depth=0):
        if depth > 12:
            _fail()
        if v is None or type(v) is bool:
            return
        if type(v) is int and 0 <= v <= 2**53 - 1:
            return
        if isinstance(v, str) and len(v) <= 4096:
            if any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in v):
                _fail()
            return
        if isinstance(v, list) and len(v) <= MAX_FILES:
            for item in v:
                check(item, depth + 1)
            return
        if isinstance(v, dict) and len(v) <= 32 and all(isinstance(k, str) and k.isascii() for k in v):
            for item in v.values():
                check(item, depth + 1)
            return
        _fail()
    check(value)
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    if len(raw) > MAX_DOCUMENT:
        _fail()
    return raw


def parse(raw, maximum=MAX_ENVELOPE):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= maximum:
        _fail()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                           parse_constant=lambda _: _fail(), parse_float=lambda _: _fail())
        if not isinstance(value, dict):
            _fail()
        return value
    except (ValueError, UnicodeError, RecursionError):
        _fail()


def _b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64(value, maximum):
    if (not isinstance(value, str) or not 0 < len(value) <= maximum
            or not re.fullmatch(r"[A-Za-z0-9_-]+", value)):
        _fail()
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError:
        _fail()
    if _b64(raw) != value:
        _fail()
    return raw


def validate_document(doc, kind):
    if not isinstance(doc, dict):
        _fail()
    canonical(doc)
    if kind not in {"request", "lock"}:
        _fail()
    fields = ({"items", "generated_at", "generated_by", "node", "index_source"} if kind == "request" else
              {"files", "generated_at", "manifest", "failed"})
    key = "items" if kind == "request" else "files"
    if set(doc) - fields or not isinstance(doc.get(key), list) or len(doc[key]) > MAX_FILES:
        _fail()
    for name in fields - {key, "manifest", "failed"}:
        if doc.get(name) is not None:
            _text(doc[name], 512)
    names, paths, total = set(), set(), 0
    for row in doc[key]:
        common = {"filename", "url", "kind", "product_key", "version", "version_label"}
        allowed = common | ({"expected_bytes", "expected_etag"} if kind == "request" else
                            {"disk_name", "sha256", "bytes", "etag", "fetched_at", "note"})
        required = {"filename", "url"} if kind == "request" else {"filename", "disk_name", "sha256", "bytes", "url"}
        if not isinstance(row, dict) or set(row) - allowed or not required <= row.keys():
            _fail()
        name = filename(row["filename"])
        path = filename(row.get("disk_name", name))
        if (name.casefold() in names or path.casefold() in paths
                or name.casefold() in {"manifest.json", "manifest.lock.json"}
                or name.casefold().endswith((".part", ".part.json", ".why.json"))):
            _fail()
        names.add(name.casefold())
        paths.add(path.casefold())
        try:
            url = row["url"]
            if not isinstance(url, str) or kind == "request" and not url:
                _fail()
            parsed = urlsplit(url)
            if url and (parsed.scheme not in {"https", "http"} or not parsed.hostname
                        or parsed.username is not None or parsed.password is not None or parsed.fragment):
                _fail()
        except ValueError:
            _fail()
        if kind == "lock" and path != name:
            _fail()
        for name in allowed - {"filename", "disk_name", "version", "bytes", "expected_bytes", "sha256"}:
            if row.get(name) is not None and row[name] != "":
                _text(row[name])
        row_kind = row.get("kind")
        if row_kind is not None and (not isinstance(row_kind, str) or row_kind not in {
                "manual_stig", "scap_benchmark", "srg", "automation", "compilation", "other"}):
            _fail()
        version = row.get("version")
        if version is not None and (not isinstance(version, list) or len(version) != 2
                                    or any(type(v) is not int or not 0 <= v <= 999999 for v in version)):
            _fail()
        size = row.get("bytes" if kind == "lock" else "expected_bytes")
        if (kind == "lock" or size is not None) and (type(size) is not int or not 0 < size <= MAX_FILE_BYTES):
            _fail()
        total += size or 0
        if total > MAX_BUNDLE_BYTES or kind == "lock" and not _HASH.fullmatch(str(row["sha256"])):
            _fail()
    if kind == "lock":
        manifest = doc.get("manifest")
        if manifest is not None:
            if (not isinstance(manifest, dict) or set(manifest) - {"node", "generated_at", "sha256"}
                    or not _HASH.fullmatch(str(manifest.get("sha256")))):
                _fail()
            for name in ("node", "generated_at"):
                if manifest.get(name) is not None:
                    _text(manifest[name], 512)
        if not isinstance(doc.get("failed", []), list) or doc.get("failed"):
            # A partial fetch is not a complete importable bundle.
            _fail()
    return doc


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_uid, info.st_gid,
            info.st_mode, info.st_nlink, getattr(info, "st_file_attributes", 0))


def _node(info, directory=False):
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & _REPARSE:
        _fail()
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            _fail()
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        _fail()


def _windows_acl(path, *, private=False, directory=False):
    """Conservative allow-ACE check; no effective-access or deny-ACE guessing."""
    import ctypes as c
    from ctypes import wintypes as w
    adv = c.WinDLL("advapi32", use_last_error=True)
    kernel = c.WinDLL("kernel32", use_last_error=True)
    ptr = c.c_void_p
    adv.GetNamedSecurityInfoW.argtypes = [w.LPWSTR, w.DWORD, w.DWORD, c.POINTER(ptr), ptr,
                                         c.POINTER(ptr), ptr, c.POINTER(ptr)]
    adv.GetNamedSecurityInfoW.restype = w.DWORD
    adv.ConvertSidToStringSidW.argtypes = [ptr, c.POINTER(w.LPWSTR)]
    adv.ConvertSidToStringSidW.restype = w.BOOL
    adv.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    adv.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, ptr, w.DWORD, c.POINTER(w.DWORD)]
    adv.GetAce.argtypes = [ptr, w.DWORD, c.POINTER(ptr)]
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.LocalFree.argtypes = [ptr]
    kernel.CloseHandle.argtypes = [w.HANDLE]
    def sid(value):
        output = w.LPWSTR()
        if not adv.ConvertSidToStringSidW(value, c.byref(output)):
            _fail()
        try:
            return output.value
        finally:
            kernel.LocalFree(c.cast(output, ptr))
    token = w.HANDLE()
    if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, c.byref(token)):
        _fail()
    try:
        needed = w.DWORD()
        adv.GetTokenInformation(token, 1, None, 0, c.byref(needed))
        buffer = c.create_string_buffer(needed.value)
        if not adv.GetTokenInformation(token, 1, buffer, len(buffer), c.byref(needed)):
            _fail()
        user = sid(c.cast(buffer, c.POINTER(ptr))[0])
    finally:
        kernel.CloseHandle(token)
    trusted = {user, "S-1-5-18", "S-1-5-32-544",
               "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"}
    owner, acl, descriptor = ptr(), ptr(), ptr()
    if adv.GetNamedSecurityInfoW(str(path), 1, 5, c.byref(owner), None, c.byref(acl), None, c.byref(descriptor)):
        _fail()
    try:
        if not owner or not acl or sid(owner) not in trusted:
            _fail()
        trusted.add("S-1-3-4")  # OWNER RIGHTS applies only to the checked, trusted owner.
        count = c.cast(acl, c.POINTER(c.c_ushort))[2]
        if count > 1024:
            _fail()
        # Directory create-child rights cannot replace an already existing checked child.
        forbidden = 0xD0150 if directory else (0xD01FF if private else 0xD0116)
        for i in range(count):
            ace = ptr()
            if not adv.GetAce(acl, i, c.byref(ace)):
                _fail()
            kind, flags = c.string_at(ace, 2)
            if flags & 8:  # inherit-only ACE does not govern this object
                continue
            if kind == 1:  # deny ACE cannot expand access
                continue
            if kind != 0:
                _fail()
            mask = c.cast(ace.value + 4, c.POINTER(w.DWORD))[0]
            if sid(ace.value + 8) not in trusted and mask & (forbidden | 0x50000000 | (0x80000000 if private else 0)):
                _fail()
    finally:
        kernel.LocalFree(descriptor)


def _parents(path, protected=False):
    if ".." in path.parts:
        _fail()
    identities = []
    for parent in reversed(path.parents):
        info = parent.lstat()
        _node(info, directory=True)
        if protected:
            if os.name == "nt":
                _windows_acl(parent, directory=True)
            elif (info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022
                  and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)):
                _fail()
        identities.append((info.st_dev, info.st_ino, info.st_mode))
    return identities


def copy_checked(path, destination=None, *, maximum=MAX_DOCUMENT, protected=False, private=False):
    """Stable bounded read/copy without following symlinks, devices or hardlinks."""
    path = Path(path).absolute()
    parents = _parents(path, protected)
    before = path.lstat()
    _node(before)
    if not 0 < before.st_size <= maximum:
        _fail()
    if protected:
        if os.name == "nt":
            _windows_acl(path, private=private)
        elif before.st_uid not in {0, os.geteuid()} or before.st_mode & (0o077 if private else 0o022):
            _fail()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    digest, chunks, size = hashlib.sha256(), [], 0
    with os.fdopen(os.open(path, flags), "rb") as source:
        opened = os.fstat(source.fileno())
        if _stamp(opened) != _stamp(before):
            _fail()
        with open(destination, "xb") if destination is not None else _null_writer() as target:
            while data := source.read(min(65536, maximum + 1 - size)):
                size += len(data)
                if size > maximum:
                    _fail()
                digest.update(data)
                if target is None:
                    chunks.append(data)
                else:
                    target.write(data)
            finished = os.fstat(source.fileno())
            if _stamp(finished) != _stamp(opened) or finished.st_ctime_ns != opened.st_ctime_ns:
                _fail()
    after = path.lstat()
    if (_stamp(after) != _stamp(before) or after.st_ctime_ns != before.st_ctime_ns
            or _parents(path, protected) != parents):
        _fail()
    if protected and os.name == "nt":
        _windows_acl(path, private=private)
    return (b"".join(chunks) if destination is None else digest.hexdigest()), size


@contextmanager
def _null_writer():
    yield None


def read_document_file(path):
    try:
        return copy_checked(path, maximum=MAX_ENVELOPE)[0]
    except (OSError, ValueError):
        _fail()


@dataclass(frozen=True)
class ContentSignatureConfig:
    trusted_keys: Mapping[str, str | Path] = field(default_factory=dict, repr=False)
    scope: str = "disa-content"
    signing_key: Path | None = field(default=None, repr=False)
    signing_key_id: str | None = None
    signing_password_ref: str | None = field(default=None, repr=False)

    def __post_init__(self):
        if (not isinstance(self.scope, str) or not _ID.fullmatch(self.scope)
                or not isinstance(self.trusted_keys, Mapping) or len(self.trusted_keys) > 32):
            _fail()
        for key, path in self.trusted_keys.items():
            if (not isinstance(key, str) or not _ID.fullmatch(key) or not isinstance(path, (str, Path))
                    or not Path(path).is_absolute()):
                _fail()
        object.__setattr__(self, "trusted_keys", MappingProxyType(dict(self.trusted_keys)))
        if self.signing_key is not None:
            if (not isinstance(self.signing_key, (str, Path)) or not Path(self.signing_key).is_absolute() or not isinstance(self.signing_key_id, str)
                    or not _ID.fullmatch(self.signing_key_id)):
                _fail()
        elif self.signing_key_id is not None or self.signing_password_ref is not None:
            _fail()
        if self.signing_password_ref is not None and (not isinstance(self.signing_password_ref, str)
                or not re.fullmatch(r"[A-Za-z0-9_]{1,64}", self.signing_password_ref)):
            _fail()


def config_for(ctx):
    config = getattr(ctx, "content_signature_config", None)
    if config is None:
        return ContentSignatureConfig()
    if not isinstance(config, ContentSignatureConfig):
        _fail()
    return config


def load_config(path) -> ContentSignatureConfig:
    """Load operator-controlled trust settings; never accept this path from an API body."""
    try:
        if not isinstance(path, (str, Path)) or not Path(path).is_absolute():
            _fail()
        raw, _ = copy_checked(path, maximum=65536, protected=True)
        doc = parse(raw, 65536)
        allowed = {"version", "scope", "trusted_keys", "signing_key", "signing_key_id", "signing_password_ref"}
        if (set(doc) - allowed or not {"version", "scope", "trusted_keys"} <= doc.keys()
                or type(doc["version"]) is not int or doc["version"] != 1):
            _fail()
        config = ContentSignatureConfig(**{k: v for k, v in doc.items() if k != "version"})
        for public_path in config.trusted_keys.values():
            pem, _ = copy_checked(public_path, maximum=16384, protected=True)
            if not isinstance(serialization.load_pem_public_key(pem), Ed25519PublicKey):
                _fail()
        if config.signing_key is not None:
            copy_checked(config.signing_key, maximum=16384, protected=True, private=True)
        return config
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm):
        _fail()


def required(ctx):
    settings = getattr(ctx, "settings", None)
    return getattr(settings, "auth_mode", "dev") != "dev" or getattr(settings, "security_mode", "range") == "fleet"


def sign_document(doc, kind, config):
    validate_document(doc, kind)
    if config.signing_key is None:
        _fail()
    try:
        raw, _ = copy_checked(config.signing_key, maximum=16384, protected=True, private=True)
        password = None
        if config.signing_password_ref:
            password = _text(os.environ.get("CT_CRED_" + config.signing_password_ref), 4096).encode()
        key = serialization.load_pem_private_key(raw, password=password)
        if not isinstance(key, Ed25519PrivateKey):
            _fail()
        header = _b64(canonical({"alg": "EdDSA", "kid": config.signing_key_id, "typ": TYPE}))
        payload = _b64(canonical({"version": 1, "kind": kind, "scope": config.scope, "document": doc}))
        signature = key.sign((header + "." + payload).encode("ascii"))
        return {"protected": header, "payload": payload, "signature": _b64(signature)}
    except (OSError, TypeError, ValueError, UnsupportedAlgorithm):
        _fail()


def verify_document(raw, kind, config):
    value = parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    evidence = {"status": "unsigned", "operator_attested": False, "disa_signature": False,
                "document_sha256": digest, "scope": config.scope}
    if not ({"protected", "payload", "signature"} & value.keys()):
        return validate_document(value, kind), evidence
    if set(value) != {"protected", "payload", "signature"}:
        _fail()
    header_raw = _unb64(value["protected"], 1024)
    header = parse(header_raw, 1024)
    if (set(header) != {"alg", "kid", "typ"} or header.get("alg") != "EdDSA" or header.get("typ") != TYPE
            or not isinstance(header.get("kid"), str) or not _ID.fullmatch(header["kid"])
            or canonical(header) != header_raw):
        _fail()
    payload_raw = _unb64(value["payload"], MAX_ENVELOPE)
    payload = parse(payload_raw, MAX_DOCUMENT)
    if (set(payload) != {"version", "kind", "scope", "document"} or type(payload["version"]) is not int
            or payload["version"] != 1 or payload["kind"] != kind or payload["scope"] != config.scope
            or canonical(payload) != payload_raw):
        _fail()
    doc = validate_document(payload["document"], kind)
    signature = _unb64(value["signature"], 128)
    if len(signature) != 64:
        _fail()
    evidence["signer"] = header["kid"]
    if header["kid"] not in config.trusted_keys:
        return doc, dict(evidence, status="unknown_signer")
    try:
        public, _ = copy_checked(config.trusted_keys[header["kid"]], maximum=16384, protected=True)
        key = serialization.load_pem_public_key(public)
        if not isinstance(key, Ed25519PublicKey):
            _fail()
        key.verify(signature, (value["protected"] + "." + value["payload"]).encode("ascii"))
    except (InvalidSignature, UnsupportedAlgorithm, OSError, ValueError, TypeError):
        _fail()
    return doc, dict(evidence, status="operator_attested", operator_attested=True)


def decide(ctx, evidence, actor, override_reason=None):
    from cyberthunder.control.principal import require_current
    if evidence["status"] == "trusted_https_source":
        # Only the internal downloader receipt can reach this branch. This is
        # the existing live-updater admin permission, not an offline exception.
        if required(ctx):
            require_current("admin", actor)
            ctx.authorize("admin", actor=actor)
        return dict(evidence)
    if required(ctx):
        require_current("import", actor)
        ctx.authorize("import", actor=actor)
    if evidence["status"] == "operator_attested":
        return dict(evidence)
    if override_reason is not None:
        if getattr(ctx.settings, "auth_mode", "dev") not in {"oidc", "mesh"}:
            _fail()
        reason = _text(override_reason, 512).strip()
        if not reason:
            _fail()
        require_current("import", actor)
        principal = require_current("admin", actor)
        if principal.kind != "human":
            _fail()
        ctx.authorize("import", actor=principal.actor)
        ctx.authorize("admin", actor=principal.actor)
        return dict(evidence, status="human_override", operator_attested=False,
                    unverified_status=evidence["status"], override_by=principal.actor, override_reason=reason)
    if not required(ctx) and evidence["status"] == "unsigned":
        return dict(evidence, status="unsigned_dev")
    raise AuthenticityError("Content requires a trusted operator attestation or an authorized human override")


@contextmanager
def receipt(ctx, actor, digests, evidence, override_reason=None, *, recheck=None):
    token = _receipt.set((ctx, actor, frozenset(digests), dict(evidence), override_reason, recheck))
    try:
        yield
    finally:
        _receipt.reset(token)


def acceptance(ctx, actor, digest, size):
    active = _receipt.get()
    if active is None:
        return decide(ctx, {"status": "unsigned", "operator_attested": False, "disa_signature": False}, actor)
    owner, expected_actor, digests, evidence, reason, recheck = active
    if owner is not ctx or actor != expected_actor or (digest, size) not in digests:
        _fail()
    # Recheck the current principal/session and policy, including on background threads.
    base = dict(recheck() if recheck is not None else evidence)
    if base["status"] in {"human_override", "unsigned_dev"}:
        base["status"] = "unsigned"
    return decide(ctx, base, actor, reason)


def atomic_document(path, doc):
    """Portable-file artifact even when application documents use SQLite."""
    path = Path(path).absolute()
    path.parent.mkdir(parents=True, exist_ok=True)
    _parents(path)
    if path.exists() or path.is_symlink():
        _node(path.lstat())
    raw = json.dumps(doc, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(raw) > MAX_ENVELOPE:
        _fail()
    fd, name = tempfile.mkstemp(prefix=".content-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)
    return hashlib.sha256(raw).hexdigest()
