"""Explicit local Ed25519 checkpoint operations; no automatic signing or delivery."""
from __future__ import annotations

import base64
from functools import wraps
import hashlib
import json
import math
import re

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from cyberthunder.audit import _anchor_files as files
from cyberthunder.audit.chain import GENESIS, head_path, record_hash

SCHEMA = "cyber-thunder.audit.checkpoint.v1"
STORE_SCHEMA = "cyber-thunder.audit.anchors.v1"
DOMAIN = b"Cyber Thunder audit checkpoint signature v1\x00"
ID_DOMAIN = b"Cyber Thunder audit checkpoint identifier v1\x00"
MAX_CONFIG = 64 * 1024
MAX_BUNDLE = 4096
MAX_STORE = 512 * 1024
MAX_LOG = 256 * 1024 * 1024
MAX_RECORD = 1024 * 1024
MAX_RECORDS = 1_000_000
MAX_SEQUENCE = 2**53 - 1
_HASH = re.compile(r"[0-9a-f]{64}")
_INSTANCE = re.compile(r"[0-9a-f]{32}")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


class AnchorError(PermissionError):
    """Safe diagnostic: no file paths, key contents or audit payloads."""


def _guard(operation):
    @wraps(operation)
    def guarded(*args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except AnchorError:
            raise
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError,
                InvalidSignature, UnsupportedAlgorithm):
            raise AnchorError("Audit anchor operation refused: check inputs, protection, trust and continuity") from None
    return guarded


def _fields(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError


def _text(value):
    if (not isinstance(value, str) or not 0 < len(value) <= 128 or value != value.strip()
            or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value)):
        raise ValueError
    return value


def _hash(value):
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ValueError
    return value


def _sequence(value):
    if type(value) is not int or not 0 <= value <= MAX_SEQUENCE:
        raise ValueError
    return value


def _scope(value):
    node = _text(value["node"])
    instance = value["log_instance"]
    if not isinstance(instance, str) or not _INSTANCE.fullmatch(instance):
        raise ValueError
    return node, instance


def _key_id(value):
    if not isinstance(value, str) or not _KEY_ID.fullmatch(value):
        raise ValueError
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _constant(_):
    raise ValueError


def _json(raw, maximum):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= maximum:
        raise ValueError
    # Bound nesting before calling the recursive JSON parser; floats remain legal in
    # audit details, but never in schema versions, counters or checkpoint fields.
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
            if depth > 32:
                raise ValueError
        elif char in (93, 125):
            depth -= 1
    def number(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError
        return result
    result = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant, parse_float=number)
    if not isinstance(result, dict):
        raise ValueError
    return result


class _Reads:
    """Operation-local input identities, rechecked before a persistent mutation."""
    def __init__(self):
        self.inputs = {}

    def read(self, path, maximum, private=False):
        path = files.native_path(path)
        raw = files.read(path, maximum, private=private)
        stamp = (maximum, private, hashlib.sha256(raw).digest())
        if path in self.inputs and self.inputs[path] != stamp:
            raise ValueError
        self.inputs[path] = stamp
        return raw

    def check(self):
        for path, (maximum, private, digest) in self.inputs.items():
            if hashlib.sha256(files.read(path, maximum, private=private)).digest() != digest:
                raise ValueError


class _Trust:
    def __init__(self, path, reads):
        self.reads, self.keys = reads, {}
        value = _json(reads.read(path, MAX_CONFIG), MAX_CONFIG)
        _fields(value, {"version", "streams"})
        if type(value["version"]) is not int or value["version"] != 1:
            raise ValueError
        entries = value["streams"]
        if not isinstance(entries, list) or not 0 < len(entries) <= 64:
            raise ValueError
        for entry in entries:
            _fields(entry, {"node", "log_instance", "keys"})
            scope = _scope(entry)
            keys = entry["keys"]
            if scope in self.keys or not isinstance(keys, dict) or not 0 < len(keys) <= 8:
                raise ValueError
            self.keys[scope] = {_key_id(k): files.native_path(v) for k, v in keys.items()}

    def public_key(self, checkpoint):
        path = self.keys[_scope(checkpoint)][_key_id(checkpoint["key_id"])]
        raw = self.reads.read(path, 8192)
        if not re.fullmatch(br"-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\s*", raw):
            raise ValueError
        key = serialization.load_pem_public_key(raw)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError
        return key


def _checkpoint(value):
    _fields(value, {"schema", "algorithm", "key_id", "node", "log_instance", "sequence", "head_hash", "previous"})
    if value["schema"] != SCHEMA or value["algorithm"] != "Ed25519":
        raise ValueError
    _scope(value)
    _key_id(value["key_id"])
    seq, head = _sequence(value["sequence"]), _hash(value["head_hash"])
    if (seq == 0) != (head == GENESIS):
        raise ValueError
    previous = value["previous"]
    if previous is not None:
        _fields(previous, {"sequence", "head_hash", "checkpoint_id"})
        old = _sequence(previous["sequence"])
        if old >= seq or (old == 0) != (_hash(previous["head_hash"]) == GENESIS):
            raise ValueError
        _hash(previous["checkpoint_id"])
    return value


def _identifier(checkpoint):
    return hashlib.sha256(ID_DOMAIN + canonical(checkpoint)).hexdigest()


def _reference(checkpoint):
    return {"sequence": checkpoint["sequence"], "head_hash": checkpoint["head_hash"],
            "checkpoint_id": _identifier(checkpoint)}


def _verify(bundle, trust):
    _fields(bundle, {"checkpoint", "signature"})
    checkpoint = _checkpoint(bundle["checkpoint"])
    encoded = bundle["signature"]
    if not isinstance(encoded, str) or not re.fullmatch(r"[A-Za-z0-9_-]{86}", encoded):
        raise ValueError
    signature = base64.b64decode(encoded + "==", altchars=b"-_", validate=True)
    if len(signature) != 64 or base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii") != encoded:
        raise ValueError
    trust.public_key(checkpoint).verify(signature, DOMAIN + canonical(checkpoint))
    return checkpoint


def _load_bundle(path, reads, trust):
    bundle = _json(reads.read(path, MAX_BUNDLE), MAX_BUNDLE)
    _verify(bundle, trust)
    return bundle


def _receipt(checkpoint, operation, **extra):
    return {"operation": operation, "node": checkpoint["node"], "log_instance": checkpoint["log_instance"],
            **_reference(checkpoint), "signature": "verified", "off_node_delivery": "not_established", **extra}


def _full_log(path, node, anchor=None):
    """Caller holds the audit writer lock. Never invoke AuditLog.append/verify here."""
    count, head, total = 0, GENESIS, 0
    matched = anchor is None or anchor["sequence"] == 0 and anchor["head_hash"] == GENESIS
    required = {"seq", "ts", "node", "actor", "action", "subject", "outcome", "details", "prev_hash", "hash"}
    with files.stream(path, MAX_LOG) as source:
        while raw := source.readline(MAX_RECORD + 1):
            total += len(raw)
            if total > MAX_LOG or len(raw) > MAX_RECORD or not raw.endswith(b"\n"):
                raise ValueError
            if not raw.strip():
                raise ValueError
            record = _json(raw, MAX_RECORD)
            if not required <= record.keys() or record.keys() - required - {"v", "principal"}:
                raise ValueError
            if (type(record["seq"]) is not int or record["seq"] != count + 1 or record["node"] != node
                    or record["prev_hash"] != head or record_hash(record) != _hash(record["hash"])
                    or not isinstance(record["details"], dict)):
                raise ValueError
            if (any(not isinstance(record[name], str) for name in ("ts", "actor", "action", "outcome"))
                    or record["subject"] is not None and not isinstance(record["subject"], str)):
                raise ValueError
            if "v" in record:
                if type(record["v"]) is not int or record["v"] != 2 or not isinstance(record.get("principal"), dict):
                    raise ValueError
            elif "principal" in record:
                raise ValueError
            count, head = count + 1, record["hash"]
            if count > MAX_RECORDS:
                raise ValueError
            if anchor is not None and count == anchor["sequence"]:
                matched = head == anchor["head_hash"]
    if not matched:
        raise AnchorError("Audit log does not extend the trusted checkpoint")
    try:
        cp = _json(files.read(head_path(path), 4096), 4096)
    except FileNotFoundError:
        if count:
            raise ValueError
    else:
        _fields(cp, {"seq", "hash", "ts"})
        if (_sequence(cp["seq"]) != count or _hash(cp["hash"]) != head
                or not isinstance(cp["ts"], str) or count and cp["ts"] != record["ts"]):
            raise ValueError
    return count, head


@_guard
def export_checkpoint(signing_config, trust_config, output, *, previous=None):
    """Verify a complete locked log and publish one new detached signed bundle."""
    reads = _Reads()
    trust = _Trust(trust_config, reads)
    config = _json(reads.read(signing_config, MAX_CONFIG), MAX_CONFIG)
    _fields(config, {"version", "node", "log_instance", "key_id", "log_path", "private_key"})
    if type(config["version"]) is not int or config["version"] != 1:
        raise ValueError
    _scope(config)
    _key_id(config["key_id"])
    path = files.native_path(config["log_path"])
    private = reads.read(config["private_key"], 16384, private=True)
    if not re.fullmatch(br"-----BEGIN PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PRIVATE KEY-----\s*", private):
        raise ValueError
    key = serialization.load_pem_private_key(private, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError
    public = trust.public_key(config)
    if key.public_key().public_bytes_raw() != public.public_bytes_raw():
        raise ValueError
    old = _load_bundle(previous, reads, trust)["checkpoint"] if previous is not None else None
    if old is not None and _scope(old) != _scope(config):
        raise ValueError
    with files.locked(path.with_name(path.name + ".lock")):
        seq, head = _full_log(path, config["node"], old)
        checkpoint = _checkpoint({"schema": SCHEMA, "algorithm": "Ed25519", "key_id": config["key_id"],
            "node": config["node"], "log_instance": config["log_instance"], "sequence": seq, "head_hash": head,
            "previous": _reference(old) if old is not None else None})
        signature = base64.urlsafe_b64encode(key.sign(DOMAIN + canonical(checkpoint))).rstrip(b"=").decode("ascii")
        bundle = {"checkpoint": checkpoint, "signature": signature}
        _verify(bundle, trust)
        raw = canonical(bundle)
        if len(raw) > MAX_BUNDLE:
            raise ValueError
        reads.check()
        files.write(output, raw)
    return _receipt(checkpoint, "export", log_verification="complete_at_export")


@_guard
def verify_checkpoint(bundle_path, trust_config):
    """Verify configured trust and signature only; this is not a log/delivery check."""
    reads = _Reads()
    trust = _Trust(trust_config, reads)
    checkpoint = _load_bundle(bundle_path, reads, trust)["checkpoint"]
    reads.check()
    return _receipt(checkpoint, "verify", log_verification="not_performed")


@_guard
def check_log(log_path, bundle_path, trust_config):
    """Verify the complete locked local log and its exact signed checkpoint prefix."""
    reads = _Reads()
    trust = _Trust(trust_config, reads)
    checkpoint = _load_bundle(bundle_path, reads, trust)["checkpoint"]
    path = files.native_path(log_path)
    with files.locked(path.with_name(path.name + ".lock")):
        seq, head = _full_log(path, checkpoint["node"], checkpoint)
        reads.check()
    return _receipt(checkpoint, "check-log", log_verification="complete_and_extends_checkpoint",
                    log_sequence=seq, log_head_hash=head)


@_guard
def initialize_store(store_path, trust_config):
    """Explicitly establish an empty local anchor store, refusing an existing file."""
    reads = _Reads()
    _Trust(trust_config, reads)
    path = files.native_path(store_path)
    with files.locked(path.with_name(path.name + ".lock")):
        reads.check()
        files.write(path, canonical({"schema": STORE_SCHEMA, "anchors": []}))
    return {"operation": "init", "local_anchor_state": "initialized", "off_node_delivery": "not_established"}


@_guard
def import_checkpoint(bundle_path, trust_config, store_path):
    """Atomically advance local monotonic state; require the exact accepted predecessor."""
    reads = _Reads()
    trust = _Trust(trust_config, reads)
    bundle = _load_bundle(bundle_path, reads, trust)
    incoming = bundle["checkpoint"]
    path = files.native_path(store_path)
    with files.locked(path.with_name(path.name + ".lock")):
        raw = files.read(path, MAX_STORE)  # Missing state never silently initializes a new trust baseline.
        state = _json(raw, MAX_STORE)
        _fields(state, {"schema", "anchors"})
        if state["schema"] != STORE_SCHEMA or not isinstance(state["anchors"], list) or len(state["anchors"]) > 64:
            raise ValueError
        by_scope = {}
        for saved in state["anchors"]:
            checkpoint = _verify(saved, trust)
            scope = _scope(checkpoint)
            if scope in by_scope:
                raise ValueError
            by_scope[scope] = saved
        scope = _scope(incoming)
        saved = by_scope.get(scope)
        if saved is None:
            if incoming["previous"] is not None or len(by_scope) >= 64:
                raise AnchorError("An initial checkpoint without a predecessor is required")
        else:
            current = saved["checkpoint"]
            if incoming["sequence"] < current["sequence"]:
                raise AnchorError("Audit anchor rollback refused")
            if incoming["sequence"] == current["sequence"]:
                if canonical(incoming) != canonical(current):
                    raise AnchorError("Conflicting audit checkpoint refused")
                reads.check()
                return _receipt(incoming, "import", local_anchor_state="unchanged")
            if incoming["previous"] != _reference(current):
                raise AnchorError("Audit checkpoint does not extend the accepted anchor")
        by_scope[scope] = bundle
        updated = canonical({"schema": STORE_SCHEMA, "anchors": [by_scope[key] for key in sorted(by_scope)]})
        if len(updated) > MAX_STORE:
            raise ValueError
        reads.check()
        files.write(path, updated, expected=raw)
    return _receipt(incoming, "import", local_anchor_state="advanced")


def main(argv=None):
    """Native-operator utility, deliberately separate from application actor/session CLI commands."""
    import argparse
    import sys
    class SafeParser(argparse.ArgumentParser):
        def error(self, message):
            self.exit(2, "Invalid audit anchor arguments; use --help\n")
    parser = SafeParser(allow_abbrev=False,
        description="Local audit checkpoints; signing/import do not establish off-node delivery")
    commands = parser.add_subparsers(dest="operation", required=True)
    for operation in ("export", "verify", "check-log", "init", "import"):
        cmd = commands.add_parser(operation, allow_abbrev=False)
        cmd.add_argument("--trust", required=True, help="absolute protected trust configuration path")
        if operation == "export":
            cmd.add_argument("--signer", required=True, help="absolute protected signing configuration path")
            cmd.add_argument("--out", required=True, help="new absolute checkpoint artifact path")
            cmd.add_argument("--previous", help="previous signed checkpoint artifact")
        if operation in {"verify", "check-log", "import"}:
            cmd.add_argument("--bundle", required=True)
        if operation == "check-log":
            cmd.add_argument("--log", required=True)
        if operation in {"init", "import"}:
            cmd.add_argument("--store", required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "export":
            result = export_checkpoint(args.signer, args.trust, args.out, previous=args.previous)
        elif args.operation == "verify":
            result = verify_checkpoint(args.bundle, args.trust)
        elif args.operation == "check-log":
            result = check_log(args.log, args.bundle, args.trust)
        elif args.operation == "init":
            result = initialize_store(args.store, args.trust)
        else:
            result = import_checkpoint(args.bundle, args.trust, args.store)
    except AnchorError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
