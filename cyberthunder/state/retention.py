"""Bounded, read-only retention planning and verified scan evidence export.

There is deliberately no deletion API. Snapshot comparisons detect observed changes;
they do not freeze writers across document, proposal, snapshot and queue owners.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import struct
import zipfile

from cyberthunder.findings.schema import findings_from_doc
from cyberthunder.state import StateError, is_document, validate_backend
from cyberthunder.store import StateStore, is_partial_run


class RetentionError(StateError):
    """A source, reference or output boundary could not be established."""


@dataclass(frozen=True)
class Limits:
    files: int = 10000
    file_bytes: int = 16 * 1024 * 1024
    total_bytes: int = 128 * 1024 * 1024
    archive_bytes: int = 160 * 1024 * 1024

    def __post_init__(self):
        ceilings = (10000, 16 * 1024 * 1024, 128 * 1024 * 1024, 160 * 1024 * 1024)
        if any(type(v) is not int or not 0 < v <= top
               for v, top in zip(self.__dict__.values(), ceilings)):
            raise RetentionError("invalid retention limits")


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ACTIVE = {"pending", "queued", "running", "applying", "cancelling", "starting"}
_TERMINAL = {"done", "partial", "error", "skipped", "cancelled", "stopped", "timed_out"}
# These are never opened, copied or changed. Their metadata still guards the plan.
_EXCLUDED = {"audit.jsonl", "audit.jsonl.head", "targets.yaml", "policy.json", "KILL", "killswitch.json"}
_SENSITIVE = {"credentials", "sessions", "tokens", "secrets", "auth", "identity"}


def _fail(message):
    raise RetentionError(message) from None


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _fail("duplicate JSON key")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: _fail("non-finite JSON value"))
    except (ValueError, UnicodeError, RecursionError):
        _fail("invalid state JSON")


def _utc(value):
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.utcoffset() != timedelta(0):
            raise ValueError
        return stamp
    except (AttributeError, TypeError, ValueError):
        _fail("an explicit UTC timestamp is required")


def _logical(value):
    if (not isinstance(value, str) or not value or len(value) > 1024
            or "\\" in value or any(ord(c) < 32 for c in value)):
        _fail("unsafe logical path")
    parts = value.split("/")
    if any(p in {"", ".", ".."} or p.endswith((".", " ")) or
           any(c in p for c in ':*?<>|"') or
           re.fullmatch(r"(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", p)
           for p in parts):
        _fail("unsafe logical path")
    return value


def _absolute(value):
    p = Path(value)
    if not p.is_absolute() or ".." in p.parts:
        _fail("an absolute local path without traversal is required")
    for part in p.parts[1:]:
        _logical(part)
    return p


def _stamp(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns)


def _kind(p):
    st = p.lstat()
    if (stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400
            or not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode))
            or (stat.S_ISREG(st.st_mode) and st.st_nlink != 1)):
        _fail("redirected, linked or special state path")
    return st


@contextmanager
def _parent(path, *, creating=False):
    """Pin ancestors. POSIX uses dir_fd; Windows uses the existing native ACL boundary."""
    if os.name == "nt":
        from cyberthunder.security.file_trust import protected_parent
        with protected_parent(path, creating=creating):
            yield None
        return
    if os.name != "posix":
        _fail("unsupported file protection platform")
    opened = []
    try:
        for parent in reversed(path.parents):
            fd = os.open(parent.name if opened else str(parent),
                         os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=opened[-1][0] if opened else None)
            st = os.fstat(fd)
            opened.append((fd, parent, st))
            sticky_root = st.st_uid == 0 and bool(st.st_mode & stat.S_ISVTX)
            if (st.st_uid not in {0, os.geteuid()} or (st.st_mode & 0o022 and not sticky_root)
                    or (creating and parent == path.parent and
                        (st.st_uid != os.geteuid() or st.st_mode & 0o077))):
                _fail("unsafe directory permissions")
        yield opened[-1][0]
        for fd, parent, before in opened:
            after = parent.lstat()
            if (after.st_dev, after.st_ino, after.st_mode, after.st_uid) != (
                    before.st_dev, before.st_ino, before.st_mode, before.st_uid):
                _fail("directory changed during access")
    finally:
        for fd, _, _ in reversed(opened):
            os.close(fd)


def _read(path, maximum, *, private=False, sqlite_shared=False):
    if os.name == "nt" and sqlite_shared:
        # SQLite holds write-capable handles even while idle. Read-share those
        # handles, checking native identity/DACL before reading and after it.
        # Source comparisons still apply; this is not a writer exclusion lock.
        from cyberthunder.security.file_trust import check_open_file
        with _parent(path), open(path, "rb") as stream:
            before = check_open_file(stream.fileno(), path)
            data = stream.read(maximum + 1)
            if check_open_file(stream.fileno(), path) != before:
                _fail("SQLite source changed during read")
    elif os.name == "nt":
        from cyberthunder.security.file_trust import open_protected
        with open_protected(path, private=private) as stream:
            before = _stamp(os.fstat(stream.fileno()))
            data = stream.read(maximum + 1)
            if _stamp(os.fstat(stream.fileno())) != before:
                _fail("source changed during read")
    else:
        with _parent(path) as parent:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(fd, "rb") as stream:
                st = os.fstat(stream.fileno())
                if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or
                        st.st_uid not in {0, os.geteuid()} or st.st_mode & (0o077 if private else 0o022)):
                    _fail("unsafe file permissions or type")
                before = _stamp(st)
                data = stream.read(maximum + 1)
                if _stamp(os.fstat(stream.fileno())) != before or _stamp(path.lstat()) != before:
                    _fail("source changed during read")
    if len(data) > maximum:
        _fail("retention byte limit exceeded")
    return data


def _walk(root, limits):
    result = {}
    with _parent(root / "retention-probe"):
        pending = [root]
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    key = _logical(path.relative_to(root).as_posix())
                    st = _kind(path)
                    result[key] = _stamp(st)
                    if len(result) > limits.files:
                        _fail("retention file limit exceeded")
                    if stat.S_ISDIR(st.st_mode):
                        pending.append(path)
    # Case collisions cannot round-trip safely across the supported platforms.
    if len({p.casefold() for p in result}) != len(result):
        _fail("case-colliding state paths")
    return result


def _excluded(path):
    parts = PurePosixPath(path).parts
    return (path in _EXCLUDED or path.endswith(".lock") or
            any(p.lower() in _SENSITIVE for p in parts) or
            any(word in p.lower() for p in parts for word in ("credential", "session", "token", "secret")) or
            parts[-1].lower() in {"shadow", "gshadow", "kubeconfig", "id_rsa", "id_ed25519", ".env"} or
            parts[-1].lower().endswith((".key", ".pem", ".pfx", ".p12")))


def _active(value):
    if isinstance(value, dict):
        if any(value.get(k) in _ACTIVE for k in ("status", "state") if isinstance(value.get(k), str)):
            _fail("active work prevents retention planning")
        for child in value.values():
            _active(child)
    elif isinstance(value, list):
        for child in value:
            _active(child)


class _View(StateStore):
    """Use the owning observation projection against captured bytes, without opening a store."""
    def __init__(self, root, docs, runs):
        self.root, self.documents, self.runs = root, docs, runs

    def list_scan_runs(self):
        return sorted(self.runs.values(), key=lambda r: r["started_at"], reverse=True)

    def read_json(self, path, default=None):
        return self.documents.get(Path(path).relative_to(self.root).as_posix(), default)


@dataclass
class _Snapshot:
    root: Path
    docs: dict
    payload: dict
    origins: dict
    fingerprint: str
    opaque: bool


def _snapshot(root, backend, limits):
    root = _absolute(root)
    if not stat.S_ISDIR(_kind(root).st_mode):
        _fail("state root is not a directory")
    tree = _walk(root, limits)
    payload, docs, origins, guards = {}, {}, {}, {}
    total = 0
    opaque = False

    def add(key, data, origin):
        nonlocal total
        total += len(data)
        if len(data) > limits.file_bytes or total > limits.total_bytes or len(payload) >= limits.files:
            _fail("retention source limit exceeded")
        payload[key], origins[key] = data, origin
        guards[key] = _sha(data)
        if is_document(key) or key == "proposals.json":
            docs[key] = _json(data)
            _active(docs[key])

    if backend == "json" and any(k.startswith("state.db") for k in tree):
        _fail("mixed or unsupported state backends")
    for key, stamp in sorted(tree.items()):
        if stat.S_ISDIR(stamp[2]) or key in {"state.db", "state.db-wal", "state.db-shm"}:
            continue
        if _excluded(key):
            if key.startswith("scans/"):
                _fail("protected material in scan evidence")
            continue
        if backend == "sqlite" and is_document(key):
            _fail("mixed or unsupported state backends")
        if key.startswith("scans/") or is_document(key) or key == "proposals.json":
            add(key, _read(root / key, limits.file_bytes), "file")
        else:
            # Opaque rollback/queue/plugin payloads are not interpreted or exported.
            opaque = True
    if backend == "sqlite":
        db = root / "state.db"
        if "state.db" not in tree:
            _fail("missing SQLite source")
        # Apply native type/owner/permission checks to the DB and WAL as well as
        # logical documents; physical hashes also catch commits later reversed.
        for key in ("state.db", "state.db-wal"):
            if key in tree:
                guards[key] = _sha(_read(root / key, limits.total_bytes, sqlite_shared=True))
        # Never instantiate SqliteBackend: its constructor creates/updates schema.
        # query_only + mode=ro preserve documents. SQLite may manage its SHM read marks.
        with _parent(db):
            connection = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True, timeout=0.2)
            try:
                connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, limits.file_bytes + 4096)
                connection.execute("PRAGMA query_only=ON")
                connection.execute("BEGIN")
                if connection.execute("SELECT value FROM meta WHERE key='schema'").fetchone() != ("1",):
                    _fail("unsupported SQLite schema")
                tables = {r[0] for r in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
                if tables != {"documents", "meta"}:
                    _fail("unsupported SQLite tables")
                if connection.execute("SELECT 1 FROM sqlite_master WHERE type IN ('view', 'trigger')").fetchone():
                    _fail("unsupported SQLite views or triggers")
                if [row[1:3] for row in connection.execute("PRAGMA table_info(documents)")] != [
                        ("path", "TEXT"), ("body", "TEXT"), ("updated_at", "REAL")]:
                    _fail("unsupported SQLite columns")
                for key, body, updated in connection.execute("SELECT path, body, updated_at FROM documents ORDER BY path"):
                    _logical(key)
                    if not is_document(key) or not isinstance(body, str):
                        _fail("unsupported SQLite document")
                    add(key, body.encode("utf-8"), "sqlite-body-utf8")
                    guards[key] = [guards[key], updated]
            finally:
                connection.close()
    after = _walk(root, limits)
    if len({key.casefold() for key in payload}) != len(payload):
        _fail("case-colliding document paths")
    # SHM read marks are not evidence; row content and DB/WAL identity remain guarded.
    tree.pop("state.db-shm", None)
    after.pop("state.db-shm", None)
    if tree != after:
        _fail("source changed during capture")
    fingerprint = _sha(_json_bytes({"root": str(root), "identity": _stamp(_kind(root))[:2],
                                   "tree": tree, "documents": guards, "backend": backend}))
    return _Snapshot(root, docs, payload, origins, fingerprint, opaque)


def _reference(value, snapshot, scan_id):
    """Only raw files belonging to this run are exportable. Never follow a foreign path."""
    if not isinstance(value, str):
        _fail("unsupported raw reference")
    path = Path(value)
    if path.is_absolute():
        try:
            value = path.relative_to(snapshot.root).as_posix()
        except ValueError:
            _fail("foreign raw reference")
    _logical(value)
    if not value.startswith(f"scans/{scan_id}/raw/") or value not in snapshot.payload:
        _fail("missing or foreign raw reference")
    return value


def _references(value, snapshot, runs, reasons, source_sid=None):
    """Conservative handling of reference fields, including future nested producers."""
    if isinstance(value, list):
        for item in value:
            _references(item, snapshot, runs, reasons, source_sid)
    elif isinstance(value, dict):
        for key, item in value.items():
            if item is not None and (key == "scan_id" or key.endswith("_scan_id")):
                if not isinstance(item, str) or item not in runs:
                    _fail("foreign or unknown scan reference")
                if item != source_sid:
                    reasons[item].add("scan-reference")
            elif item and key == "raw_ref":
                if source_sid is None:
                    _fail("unclassified raw reference")
                _reference(item, snapshot, source_sid)
            elif item and (key.endswith(("_ref", "_refs", "_reference", "_references")) or
                           key.endswith("scan_ids") or key == "artifacts"):
                # fix_ref is a remediation-library identifier, not retained state.
                if key != "fix_ref":
                    snapshot.opaque = True
            _references(item, snapshot, runs, reasons, source_sid)


def _plan(snapshot, backend, cutoff, limits):
    from cyberthunder.adapters.base import Collected
    from cyberthunder.scan import ScanRun
    from cyberthunder.control.approvals import Proposal
    runs, findings, reasons = {}, {}, {}
    for key, doc in snapshot.docs.items():
        if not key.startswith("scans/"):
            continue
        parts = key.split("/")
        if len(parts) != 3 or not _ID.fullmatch(parts[1]):
            _fail("unsupported scan path")
        sid = parts[1]
        if parts[2] == "run.json":
            if (not isinstance(doc, dict) or doc.get("id") != sid or
                    doc.keys() - {f.name for f in fields(ScanRun)}):
                _fail("unsupported scan record")
            ScanRun.from_dict(doc)
            if doc.get("status") not in _TERMINAL:
                _fail("active or unsupported scan state")
            if not isinstance(doc.get("targets"), list) or not all(isinstance(t, str) for t in doc["targets"]):
                _fail("unsupported scan targets")
            if len(set(doc["targets"])) != len(doc["targets"]):
                _fail("duplicate scan targets")
            if doc.get("coverage_incomplete") is not None and type(doc["coverage_incomplete"]) is not bool:
                _fail("unsupported scan coverage")
            for target, result in doc.get("results", {}).items():
                if (target not in doc["targets"] or result.get("target_id") != target
                        or result.get("status") not in _TERMINAL):
                    _fail("active or unsupported target result")
            _utc(doc.get("started_at"))
            if doc.get("status") == "done":
                if _utc(doc.get("finished_at")) < _utc(doc["started_at"]):
                    _fail("invalid scan completion time")
            runs[sid], reasons[sid] = doc, set()
        elif parts[2] == "findings.json":
            if not isinstance(doc, dict) or doc.keys() - {"schema_version", "generated_at", "meta", "findings"}:
                _fail("unsupported findings record")
            findings[sid] = findings_from_doc(doc)
    if set(runs) != set(findings):
        _fail("missing run or findings source")
    for key, doc in snapshot.docs.items():
        _references(doc, snapshot, runs, reasons, key.split("/")[1] if key.startswith("scans/") else None)
    for key in snapshot.payload:
        if not key.startswith("scans/"):
            continue
        parts = key.split("/")
        if len(parts) < 3 or parts[1] not in runs or not (
                len(parts) == 3 and parts[2] in {"run.json", "findings.json"} or
                len(parts) > 3 and parts[2] == "raw"):
            _fail("unsupported scan artifact")
        if _excluded(key):
            _fail("protected material in scan evidence")
        if parts[-1] == "collected.json" and len(parts) > 3:
            collected = _json(snapshot.payload[key])
            if (len(parts) != 5 or not isinstance(collected, dict) or
                    collected.keys() - {f.name for f in fields(Collected)} or
                    collected.get("target_id") != parts[3] or parts[3] not in runs[parts[1]]["targets"] or
                    not isinstance(collected.get("artifacts"), dict)):
                _fail("unsupported collector manifest")
            _active(collected)
            if _reference(str(collected.get("workdir")) + "/collected.json", snapshot, parts[1]) != key:
                _fail("foreign collector working directory")
            for value in collected["artifacts"].values():
                _reference(value, snapshot, parts[1])
            _references({k: v for k, v in collected.items() if k != "artifacts"},
                        snapshot, runs, reasons, parts[1])
    owners = {}
    for sid, rows in findings.items():
        for finding in rows:
            owners.setdefault(finding.id, set()).add(sid)
            if finding.scan_id not in {None, sid}:
                _fail("foreign finding scan reference")
            if finding.scan_id is None:
                reasons[sid].add("unclassified-observation")
            if finding.raw_ref:
                _reference(finding.raw_ref, snapshot, sid)
    for sid, run in runs.items():
        if run["status"] != "done":
            reasons[sid].add("incomplete-scan")
        elif _utc(run["finished_at"]) >= cutoff:
            reasons[sid].add("cutoff")
        if run.get("coverage_incomplete") is True or run.get("error") or any(
                item.get("status") != "done" or item.get("errors") for item in run.get("results", {}).values()):
            reasons[sid].add("incomplete-coverage-or-results")
    ordered = sorted(runs, key=lambda sid: (_utc(runs[sid]["started_at"]), sid), reverse=True)
    if ordered:
        reasons[ordered[0]].add("latest-scan")
    full = [sid for sid in ordered if not is_partial_run(runs[sid])]
    if full:
        reasons[full[0]].add("latest-full-scan")
    seen = set()
    for sid in ordered:
        for target in runs[sid]["targets"]:
            key = target, runs[sid].get("trigger", "manual")
            if key not in seen:
                reasons[sid].add("latest-target-producer")
                seen.add(key)
    view = _View(snapshot.root, snapshot.docs, runs)
    current, _ = view.projected_observations()
    for fid in current:
        for sid in owners.get(fid, ()):
            reasons[sid].add("current-observation")
    proposals = snapshot.docs.get("proposals.json", [])
    if not isinstance(proposals, list):
        _fail("unsupported proposals record")
    for record in proposals:
        proposal = Proposal.from_dict(record)
        if proposal.finding_id not in owners:
            _fail("unknown proposal finding reference")
        for sid in owners[proposal.finding_id]:
            reasons[sid].add("proposal-reference")
        if proposal.before_state_ref:
            # Snapshot formats belong to adapters. Without a complete reference index,
            # any rollback handle conservatively pins the whole scan history.
            snapshot.opaque = True
    if snapshot.opaque or any(not k.startswith("scans/") and k != "proposals.json" for k in snapshot.docs):
        for value in reasons.values():
            value.add("unknown-reference-or-rollback")
    eligible = sorted(sid for sid, value in reasons.items() if not value)
    entries = []
    for key, data in sorted(snapshot.payload.items()):
        parts = key.split("/")
        if parts[0] == "scans" and parts[1] in eligible:
            entries.append({"path": key, "bytes": len(data), "sha256": _sha(data),
                            "origin": snapshot.origins[key]})
    return {"format": "scan-retention-plan-v1", "backend": backend,
            "cutoff_utc": cutoff.isoformat(), "source_fingerprint": snapshot.fingerprint,
            "eligible": eligible, "pinned": {sid: sorted(v) for sid, v in sorted(reasons.items()) if v},
            "source_manifest": entries, "limits": limits.__dict__, "deletion_enabled": False}


@contextmanager
def _errors():
    try:
        yield
    except RetentionError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError, sqlite3.Error,
            zipfile.BadZipFile, NotImplementedError, OverflowError, struct.error):
        _fail("retention refused: unsafe, missing, changed or unsupported source/output")


def plan(root, backend, *, cutoff_utc=None, age_days=None, now_utc=None, limits=Limits()):
    """Return a dry-run manifest. Exactly one UTC cutoff or positive integer age is required."""
    with _errors():
        backend = validate_backend(backend)
        now = _utc(now_utc) if now_utc else datetime.now(timezone.utc)
        if (cutoff_utc is None) == (age_days is None):
            _fail("choose exactly one UTC cutoff or age")
        if age_days is not None and (type(age_days) is not int or not 0 < age_days <= 365000):
            _fail("age must be a positive bounded number of days")
        cutoff = _utc(cutoff_utc) if cutoff_utc is not None else now - timedelta(days=age_days)
        if cutoff > now:
            _fail("cutoff must not be in the future")
        snap = _snapshot(root, backend, limits)
        result = _plan(snap, backend, cutoff, limits)
        if _snapshot(root, backend, limits).fingerprint != snap.fingerprint:
            _fail("source changed during planning")
        return result


def read_plan(path):
    with _errors():
        return _json(_read(_absolute(path), Limits().file_bytes, private=True))


def _verify(data, expected_sha256, limits):
    if not isinstance(expected_sha256, str) or not _HASH.fullmatch(expected_sha256) or _sha(data) != expected_sha256:
        _fail("archive digest mismatch")
    # Our bounded exports need neither ZIP64 nor comments/multi-volume records.
    # Check the central-directory count before ZipFile allocates member objects.
    if len(data) < 22 or data[-22:-18] != b"PK\x05\x06":
        _fail("unsupported archive envelope")
    disk, start_disk, count, total_count, size, offset, comment = struct.unpack("<4H2LH", data[-18:])
    if (disk or start_disk or comment or count != total_count or not 1 <= count <= limits.files + 1
            or offset + size != len(data) - 22 or size > (limits.files + 1) * 2048):
        _fail("unsupported archive directory")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if not 1 <= len(infos) <= limits.files + 1 or len({i.filename.casefold() for i in infos}) != len(infos):
            _fail("invalid archive member count or duplicates")
        total = 0
        for entry in infos:
            _logical(entry.filename)
            total += entry.file_size
            if (entry.compress_type != zipfile.ZIP_STORED or entry.flag_bits & 1 or entry.is_dir()
                    or entry.file_size > limits.file_bytes or total > limits.total_bytes
                    or stat.S_IFMT(entry.external_attr >> 16) != stat.S_IFREG):
                _fail("unsupported or oversized archive member")
        manifest = _json(archive.read("manifest.json"))
        if manifest.get("format") != "scan-retention-archive-v1" or set(manifest) != {"format", "plan"}:
            _fail("unsupported archive manifest")
        selected = manifest["plan"]
        if selected.get("format") != "scan-retention-plan-v1" or selected.get("deletion_enabled") is not False:
            _fail("unsupported archive plan")
        entries = selected["source_manifest"]
        if {i.filename for i in infos} != {"manifest.json", *(e["path"] for e in entries)} or len(entries) != len(infos) - 1:
            _fail("archive members do not match manifest")
        eligible = selected["eligible"]
        if not eligible or any(not _ID.fullmatch(sid) for sid in eligible):
            _fail("invalid archived selection")
        for entry in entries:
            path = _logical(entry["path"])
            parts = path.split("/")
            if (len(parts) < 3 or parts[0] != "scans" or parts[1] not in eligible or _excluded(path)
                    or not (len(parts) == 3 and parts[2] in {"run.json", "findings.json"}
                            or len(parts) > 3 and parts[2] == "raw")):
                _fail("archive contains non-scan material")
            content = archive.read(path)
            if len(content) != entry["bytes"] or _sha(content) != entry["sha256"]:
                _fail("archive member integrity mismatch")
        for sid in eligible:
            if not {f"scans/{sid}/run.json", f"scans/{sid}/findings.json"} <= {e["path"] for e in entries}:
                _fail("archive is missing selected documents")
    return {"verified": True, "archive_sha256": expected_sha256, "bytes": len(data),
            "members": len(entries), "scans": eligible, "manifest": manifest}


def inspect_archive(path, expected_sha256, *, limits=Limits()):
    """Verify a private archive against a separately retained digest; never extract files."""
    with _errors():
        return _verify(_read(_absolute(path), limits.archive_bytes, private=True), expected_sha256, limits)


def archive(root, selected, output):
    """Export exactly a still-current plan to a new private file, then verify it.

    Failure can leave a private partial/unaccepted output. Never overwrite, delete,
    or clean up a user path, including after a race. Only a successful receipt accepts it.
    """
    with _errors():
        root, output = _absolute(root), _absolute(output)
        if output == root or root in output.parents or output in root.parents:
            _fail("archive destination must be outside the state tree")
        limits = Limits(**selected["limits"])
        backend = validate_backend(selected["backend"])
        cutoff = _utc(selected["cutoff_utc"])
        if cutoff > datetime.now(timezone.utc):
            _fail("cutoff must not be in the future")
        snap = _snapshot(root, backend, limits)
        if _plan(snap, backend, cutoff, limits) != selected:
            _fail("plan or source changed; create and review a new plan")
        if not selected["eligible"]:
            _fail("plan has no eligible scans")
        manifest = _json_bytes({"format": "scan-retention-archive-v1", "plan": selected})
        if len(manifest) > limits.file_bytes:
            _fail("manifest limit exceeded")
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as bundle:
            for path, data in [("manifest.json", manifest), *(
                    (e["path"], snap.payload[e["path"]]) for e in selected["source_manifest"])]:
                entry = zipfile.ZipInfo(path)
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | 0o600) << 16
                bundle.writestr(entry, data)
        data = buffer.getvalue()
        if len(data) > limits.archive_bytes:
            _fail("archive byte limit exceeded")
        digest = _sha(data)
        _verify(data, digest, limits)
        with _parent(output, creating=True) as parent:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
            fd = os.open(output if os.name == "nt" else output.name, flags, 0o600, dir_fd=parent)
            with os.fdopen(fd, "wb") as stream:
                if os.name == "nt":
                    from cyberthunder.security.file_trust import check_open_file
                    check_open_file(stream.fileno(), output, private=True)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        receipt = inspect_archive(output, digest, limits=limits)
        if _snapshot(root, backend, limits).fingerprint != snap.fingerprint:
            _fail("source changed during archival; output is unaccepted")
        # Recheck private custody and bytes after the source check as well.
        inspect_archive(output, digest, limits=limits)
        receipt.pop("manifest")
        receipt.update(source_fingerprint=snap.fingerprint, deletion_enabled=False)
        return receipt
