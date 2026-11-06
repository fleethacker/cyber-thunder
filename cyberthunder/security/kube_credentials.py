"""Validate selected Kubernetes credentials and guard subprocess inputs without caching secrets."""
from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence
from urllib.parse import urlsplit

import yaml
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

from .credentials import BindingProvenance, CredentialBinding


MAX_CONFIG_BYTES = 256 * 1024
MAX_PUBLIC_BYTES = 128 * 1024
MAX_KEY_BYTES = 32 * 1024
MAX_YAML_EVENTS = 4096
MAX_YAML_DEPTH = 12
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_CERT = re.compile(br"-{5}BEGIN CERTIFICATE-{5}\r?\n[A-Za-z0-9+/=\r\n]+-{5}END CERTIFICATE-{5}")
_KEY = re.compile(br"-{5}BEGIN (PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-{5}\r?\n"
                  br"[A-Za-z0-9+/=\r\n]+-----END \1-----\s*")
_FAILURES = (OSError, ValueError, TypeError, AttributeError, RecursionError, yaml.YAMLError,
             UnsupportedAlgorithm, x509.DuplicateExtension, x509.UnsupportedGeneralNameType)


class KubeCredentialError(PermissionError):
    """A sanitized failure; neither command text nor credential contents are included."""


def _text(value, maximum=512):
    if (not isinstance(value, str) or not value or len(value) > maximum or value != value.strip()
            or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value)):
        raise ValueError
    return value


def _fields(value, required, optional=frozenset()):
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise ValueError


def _native_path(value):
    value = _text(os.fspath(value), 2048)
    path = Path(value)
    if (not path.is_absolute() or value.startswith(("\\\\", "//"))
            or any(c in value for c in "$%*?~") or ".." in path.parts):
        raise ValueError
    if os.name == "nt" and any(":" in part for part in path.parts[1:]):
        raise ValueError
    return path


def _owner(trusted_uid):
    if trusted_uid is not None and (type(trusted_uid) is not int or trusted_uid < 0):
        raise ValueError
    return os.geteuid() if trusted_uid is None and os.name == "posix" else trusted_uid


def _protection(info, *, private, owner, directory=False):
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & _REPARSE:
        raise ValueError
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError
    if os.name == "posix":
        if info.st_uid not in {0, owner}:
            raise ValueError
        forbidden = 0o077 if private and not directory else 0o022
        # A trusted sticky directory such as /tmp cannot remove another owner's child.
        sticky = directory and bool(info.st_mode & stat.S_ISVTX)
        if info.st_mode & forbidden and not sticky:
            raise ValueError


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_mode,
            info.st_uid, info.st_gid, info.st_nlink, getattr(info, "st_file_attributes", 0))


def _parents(path, owner):
    result = []
    for parent in reversed(path.parents):
        info = parent.lstat()
        _protection(info, private=False, owner=owner, directory=True)
        result.append((info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                       getattr(info, "st_file_attributes", 0)))
    return tuple(result)


@dataclass(frozen=True)
class FileIdentity:
    path: str = field(repr=False)
    role: str
    sha256: str
    private: bool
    maximum: int
    stamp: tuple = field(repr=False)
    path_ctime_ns: int = field(repr=False)
    parents: tuple = field(repr=False)


def _read(path, role, private, maximum, owner):
    path = _native_path(path)
    parents = _parents(path, owner)
    before = path.lstat()
    _protection(before, private=private, owner=owner)
    if not 0 < before.st_size <= maximum:
        raise ValueError
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        _protection(opened, private=private, owner=owner)
        if _stamp(before) != _stamp(opened):
            raise ValueError
        raw = stream.read(maximum + 1)
        after_read = os.fstat(stream.fileno())
        if (len(raw) > maximum or _stamp(opened) != _stamp(after_read)
                or opened.st_ctime_ns != after_read.st_ctime_ns):
            raise ValueError
    after = path.lstat()
    if (_stamp(before) != _stamp(after) or before.st_ctime_ns != after.st_ctime_ns
            or parents != _parents(path, owner)):
        raise ValueError
    identity = FileIdentity(str(path), role, hashlib.sha256(raw).hexdigest(), private, maximum,
                            _stamp(after), after.st_ctime_ns, parents)
    return raw, identity


class _Loader(yaml.SafeLoader):
    pass


def _mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise ValueError
        result[key] = loader.construct_object(value_node)
    return result


_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _document(raw):
    text = raw.decode("utf-8")
    depth = documents = 0
    for number, event in enumerate(yaml.parse(text, Loader=_Loader)):
        if (number >= MAX_YAML_EVENTS or isinstance(event, yaml.AliasEvent)
                or getattr(event, "anchor", None) is not None or getattr(event, "tag", None) is not None):
            raise ValueError
        if isinstance(event, yaml.DocumentStartEvent):
            documents += 1
        if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
            depth += 1
        elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
            depth -= 1
        if depth > MAX_YAML_DEPTH or documents > 1:
            raise ValueError
    return yaml.load(text, Loader=_Loader)


def _one(rows, kind):
    if not isinstance(rows, list) or len(rows) != 1:
        raise ValueError
    row = rows[0]
    _fields(row, {"name", kind})
    return _text(row["name"]), row[kind]


def _base64(value, maximum):
    value = _text(value, (maximum + 2) // 3 * 4)
    raw = base64.b64decode(value, validate=True)
    if not raw or len(raw) > maximum:
        raise ValueError
    return raw


def _certificates(raw, *, ca=False):
    blocks = _CERT.findall(raw)
    if not 1 <= len(blocks) <= 16 or _CERT.sub(b"", raw).strip():
        raise ValueError
    certificates = [x509.load_pem_x509_certificate(block) for block in blocks]
    if ca:
        for cert in certificates:
            try:
                valid_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            except x509.ExtensionNotFound:
                valid_ca = False
            if not valid_ca:
                raise ValueError
    return certificates


def _server(value):
    value = _text(value, 2048)
    url = urlsplit(value)
    if (not value.startswith("https://") or not url.hostname or url.username is not None
            or url.password is not None or "?" in value or "#" in value or "\\" in value
            or any(c.isspace() for c in value) or "%" in url.netloc
            or url.port is not None and not 1 <= url.port <= 65535):
        raise ValueError
    return value


@dataclass(frozen=True)
class KubeconfigBinding:
    path: str = field(repr=False)
    context: str
    cluster: str
    user: str
    server: str
    auth_kind: str
    files: tuple[FileIdentity, ...]
    provenance: BindingProvenance = field(repr=False)
    trusted_uid: int | None = field(repr=False)
    protection: str

    def kubectl_args(self) -> tuple[str, ...]:
        return ("--kubeconfig", self.path, "--context", self.context,
                "--cluster", self.cluster, "--user", self.user)

    def evidence(self) -> dict:
        return {"context": self.context, "cluster": self.cluster, "user": self.user,
                "server": self.server, "auth_kind": self.auth_kind, "protection": self.protection,
                "files": [{"role": f.role, "sha256": f.sha256} for f in self.files],
                "issuer": self.provenance.issuer, "subject": self.provenance.subject,
                "action": self.provenance.action, "target_id": self.provenance.target[0],
                "policy_sha256": self.provenance.policy_sha256}


def validate_kubeconfig(binding: CredentialBinding, *, trusted_uid: int | None = None) -> KubeconfigBinding:
    """Validate one policy-selected config; never write a sanitized secret-bearing copy."""
    try:
        return _validate(binding, _owner(trusted_uid))
    except _FAILURES:
        pass
    # Outside the handler: library/parser exceptions cannot survive as a chained secret-bearing error.
    raise KubeCredentialError("account kubeconfig is unavailable or unsafe")


def _validate(binding, owner):
    if (not isinstance(binding, CredentialBinding) or not isinstance(binding.provenance, BindingProvenance)
            or not isinstance(binding.provenance.target, tuple) or len(binding.provenance.target) != 8
            or binding.provenance.target[2:4] != ("kubernetes", "kubeconfig")
            or binding.provenance.target[7] is not True
            or set(binding.options) != {"kubeconfig", "context"}):
        raise ValueError
    selected = _text(binding.options["context"])
    raw, config = _read(binding.options["kubeconfig"], "kubeconfig", True, MAX_CONFIG_BYTES, owner)
    document = _document(raw)
    _fields(document, {"apiVersion", "kind", "contexts", "clusters", "users"}, {"current-context", "preferences"})
    if (document["apiVersion"] != "v1" or document["kind"] != "Config"
            or "preferences" in document and document["preferences"] != {}
            or "current-context" in document and document["current-context"] != selected):
        raise ValueError
    context_name, context = _one(document["contexts"], "context")
    cluster_name, cluster = _one(document["clusters"], "cluster")
    user_name, user = _one(document["users"], "user")
    _fields(context, {"cluster", "user"}, {"namespace"})
    if context_name != selected or context["cluster"] != cluster_name or context["user"] != user_name:
        raise ValueError
    if "namespace" in context and not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", _text(context["namespace"])):
        raise ValueError
    _fields(cluster, {"server"}, {"certificate-authority", "certificate-authority-data"})
    server = _server(cluster["server"])
    files = [config]

    def material(fields, name, role, private, maximum):
        if (name in fields) == (name + "-data" in fields):
            raise ValueError
        if name + "-data" in fields:
            return _base64(fields[name + "-data"], maximum)
        content, identity = _read(fields[name], role, private, maximum, owner)
        files.append(identity)
        return content

    _certificates(material(cluster, "certificate-authority", "ca", False, MAX_PUBLIC_BYTES), ca=True)
    _fields(user, set(), {"token", "client-certificate", "client-certificate-data", "client-key", "client-key-data"})
    if set(user) == {"token"}:
        if not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", _text(user["token"], 16384)):
            raise ValueError
        auth_kind = "token"
    else:
        if "token" in user:
            raise ValueError
        certs = _certificates(material(user, "client-certificate", "client_certificate", False, MAX_PUBLIC_BYTES))
        key_data = material(user, "client-key", "client_key", True, MAX_KEY_BYTES)
        if not _KEY.fullmatch(key_data):
            raise ValueError
        key = serialization.load_pem_private_key(key_data, password=None)
        public_format = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        if key.public_key().public_bytes(*public_format) != certs[0].public_key().public_bytes(*public_format):
            raise ValueError
        auth_kind = "client_certificate"
    result = KubeconfigBinding(config.path, selected, cluster_name, user_name, server, auth_kind,
                               tuple(files), binding.provenance, owner,
                               "posix_owner_mode" if os.name == "posix" else "windows_dacl_not_verified")
    _guard(result)
    return result


def guard_kubeconfig(binding: KubeconfigBinding) -> None:
    """Recheck all source files immediately before each subprocess; path reopen races remain."""
    try:
        _guard(binding)
        return
    except _FAILURES:
        pass
    raise KubeCredentialError("selected Kubernetes credential files changed or are unsafe")


def _guard(binding):
    if not isinstance(binding, KubeconfigBinding) or not binding.files or len(binding.files) > 4:
        raise ValueError
    for expected in binding.files:
        _, current = _read(expected.path, expected.role, expected.private, expected.maximum, binding.trusted_uid)
        if current != expected:
            raise ValueError


# A reviewed subset used by the adapters. Unknown flags fail closed, including
# aliases, logging/profile outputs, preference files and future auth overrides.
_COMMON = {"--namespace": "text", "-n": "text", "--output": "output", "-o": "output",
           "--request-timeout": "duration"}
_FLAGS = {
    "get": {"-A": "bool", "--all-namespaces": "bool", "--raw": "raw", "--ignore-not-found": "bool",
            "-l": "text", "--selector": "text", "--field-selector": "text", "--chunk-size": "number",
            "--show-kind": "bool", "--show-labels": "bool", "--no-headers": "bool"},
    "describe": {"-A": "bool", "--all-namespaces": "bool", "-l": "text", "--selector": "text",
                 "--show-events": "bool"},
    "version": {"--client": "bool"},
    "api-resources": {"--namespaced": "bool", "--verbs": "text", "--api-group": "text", "--cached": "bool"},
    "api-versions": {},
    "apply": {"-f": "stdin", "--filename": "stdin", "--server-side": "bool", "--force-conflicts": "bool",
              "--field-manager": "text", "--dry-run": "dry_run", "--validate": "validation"},
    "replace": {"-f": "stdin", "--filename": "stdin", "--force": "bool", "--dry-run": "dry_run",
                "--validate": "validation"},
    "patch": {"--type": "patch_type", "-p": "text", "--patch": "text", "--dry-run": "dry_run"},
    "delete": {"-f": "stdin", "--filename": "stdin", "--ignore-not-found": "bool", "--wait": "bool",
               "--force": "bool", "--grace-period": "number", "--timeout": "duration"},
    "rollout status": {"--timeout": "duration", "--watch": "bool", "--revision": "number"},
    "auth can-i": {"--list": "bool", "--quiet": "bool", "--subresource": "text", "--all-namespaces": "bool"},
}


def _flag_value(kind, value):
    _text(value, 32768)
    if value.startswith("-") and not (kind == "stdin" and value == "-"):
        raise ValueError
    choices = {"bool": {"true", "false"}, "output": {"json", "yaml", "name", "wide"},
               "stdin": {"-"}, "dry_run": {"none", "client", "server"},
               "patch_type": {"json", "merge", "strategic"},
               "validation": {"true", "false", "strict", "warn", "ignore"}}
    if kind in choices and value not in choices[kind]:
        raise ValueError
    if kind == "number" and (not re.fullmatch(r"[0-9]{1,6}", value) or int(value) > 100000):
        raise ValueError
    if kind == "duration" and not re.fullmatch(r"[0-9]{1,5}(?:ms|s|m|h)", value):
        raise ValueError
    if kind == "raw":
        if (not re.fullmatch(r"/[A-Za-z0-9._~/-]*(?:\?[A-Za-z0-9_.=&~-]*)?", value)
                or value.startswith("//") or ".." in urlsplit(value).path.split("/")):
            raise ValueError


def validate_kubectl_args(args: Sequence[str]) -> tuple[str, ...]:
    """Validate only operation arguments, excluding executable and bound connection flags."""
    try:
        return _argv(args)
    except _FAILURES:
        pass
    raise KubeCredentialError("unsafe Kubernetes command arguments")


def _argv(args):
    if not isinstance(args, (tuple, list)) or not 1 <= len(args) <= 128:
        raise ValueError
    args = tuple(_text(arg, 32768) for arg in args)
    if sum(map(len, args)) > 65536:
        raise ValueError
    command, start = args[0], 1
    if command in {"rollout", "auth"}:
        if len(args) < 2:
            raise ValueError
        command, start = " ".join(args[:2]), 2
    if command not in _FLAGS:
        raise ValueError
    allowed = _COMMON | _FLAGS[command]
    positional = []
    index = start
    while index < len(args):
        arg = args[index]
        index += 1
        if not arg.startswith("-"):
            if not re.fullmatch(r"[A-Za-z0-9*][A-Za-z0-9._/*,:-]*", arg):
                raise ValueError
            positional.append(arg)
            continue
        flag, equals, value = arg.partition("=")
        kind = allowed.get(flag)
        if kind is None or flag.startswith("-") and not flag.startswith("--") and equals:
            raise ValueError
        if kind == "bool" and not equals:
            continue
        if not equals:
            if index >= len(args):
                raise ValueError
            value = args[index]
            index += 1
        _flag_value(kind, value)
    if command in {"apply", "replace", "version", "api-resources", "api-versions"} and positional:
        raise ValueError
    return args


def kube_subprocess_env(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a minimal environment; pass it directly to subprocess, never merge ambient values back."""
    try:
        source = os.environ if environ is None else environ
        if not isinstance(source, Mapping):
            raise ValueError
        names = {"path": "PATH", "systemroot": "SystemRoot", "windir": "WINDIR",
                 "temp": "TEMP", "tmp": "TMP", "tmpdir": "TMPDIR", "lang": "LANG",
                 "lc_all": "LC_ALL", "lc_ctype": "LC_CTYPE", "tz": "TZ"}
        result = {"KUBECTL_KUBERC": "false", "KUBERC": "off"}
        for name, value in source.items():
            canonical = names.get(name.casefold()) if isinstance(name, str) else None
            if canonical is not None:
                if canonical in result or not isinstance(value, str) or "\x00" in value or len(value) > 32768:
                    raise ValueError
                result[canonical] = value
        return result
    except _FAILURES:
        pass
    raise KubeCredentialError("unsafe Kubernetes subprocess environment")
