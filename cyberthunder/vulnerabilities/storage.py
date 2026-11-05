"""Bounded file validation and a fixed, versioned offline interchange format.

Hashes establish integrity only. Import never promotes a manifest's publisher
claim to trusted provenance. Inspection checks file headers and the Java table
schema; vulnerability matching remains the scanner's job.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import sqlite3
import struct
import time
import zipfile
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from .errors import VulnerabilityConflict, VulnerabilityError

MAIN = {"db/metadata.json", "db/trivy.db"}
JAVA = {"java-db/metadata.json", "java-db/trivy-java.db"}
MEMBERS = MAIN | JAVA
MANIFEST = "manifest.json"
FORMAT = "cyberthunder-vulnerability-bundle"
JSON_LIMIT = 64 * 1024
CHUNK = 1024 * 1024
GENERATION_RE = re.compile(r"[0-9a-f]{32}\Z")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def timestamp(value: object) -> datetime:
    if (not isinstance(value, str) or len(value) > 64
            or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                                r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})", value)):
        raise VulnerabilityError("Invalid database timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None or result.year < 2000:
            raise ValueError
        return result.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise VulnerabilityError("Invalid database timestamp") from None


def _pairs(pairs: list) -> dict:
    result = {}
    seen = set()
    for key, value in pairs:
        # The scanner's JSON decoder accepts case-insensitive struct field names.
        # Reject aliases that could override a validated Version/UpdatedAt later.
        if key.casefold() in seen:
            raise VulnerabilityError("Duplicate JSON field")
        seen.add(key.casefold())
        result[key] = value
    return result


def read_object(raw: bytes) -> dict:
    if len(raw) > JSON_LIMIT:
        raise VulnerabilityError("Database metadata exceeds size limit")
    try:
        result = json.loads(raw, object_pairs_hook=_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise VulnerabilityError("Invalid database metadata JSON") from None
    if not isinstance(result, dict):
        raise VulnerabilityError("Database metadata must be an object")
    return result


def encoded(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def regular(path: Path) -> os.stat_result:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or is_link(path):
        raise VulnerabilityError("Database files must be regular files without links")
    return info


def is_link(path: Path) -> bool:
    return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())


def tree_size(root: Path, limit: int, max_entries: int = 64, *, transient: bool = False) -> int:
    """Inspect without following symlinks, junctions, or unbounded directory trees."""
    total = count = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        if is_link(directory):
            raise VulnerabilityError("Links are not permitted in database storage")
        try:
            entries = os.scandir(directory)
        except FileNotFoundError:
            if transient and directory != root:
                continue
            raise
        with entries:
            for entry in entries:
                count += 1
                if count > max_entries or is_link(Path(entry.path)):
                    raise VulnerabilityError("Unexpected database storage layout")
                try:
                    mode = entry.stat(follow_symlinks=False).st_mode
                    if stat.S_ISDIR(mode):
                        pending.append(Path(entry.path))
                    elif stat.S_ISREG(mode):
                        info = regular(Path(entry.path))
                        total += info.st_size
                        if total > limit:
                            raise VulnerabilityError("Database size limit exceeded")
                    else:
                        raise VulnerabilityError("Database files must be regular files")
                except FileNotFoundError:
                    if not transient:
                        raise
    return total


def remove_tree(path: Path, parent: Path) -> None:
    """Only remove a direct child of a known service-owned directory."""
    if path.parent.resolve() != parent.resolve() or path.resolve() == parent.resolve() or is_link(path):
        raise VulnerabilityError("Unsafe database storage path")
    if path.exists():
        # Refuse nested junctions as well; shutil's platform behavior differs.
        for directory, dirs, files in os.walk(path, followlinks=False):
            for name in dirs + files:
                child = Path(directory) / name
                if is_link(child):
                    child.unlink() if child.is_symlink() else child.rmdir()
        shutil.rmtree(path)


def require_space(directory: Path, required: int) -> None:
    if shutil.disk_usage(directory).free < required + JSON_LIMIT * 4:
        raise VulnerabilityError("Insufficient free disk space for database operation")


class Lease:
    """Nonblocking OS lock: survives threads, releases automatically on process exit."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.file = open(path, "a+b")
        try:
            self.file.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            raise VulnerabilityConflict("A database operation is already active") from None

    def close(self) -> None:
        if self.file.closed:
            return
        try:
            self.file.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_UN)
        finally:
            self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def digest(path: Path, limit: int, guard: Callable[[], None]) -> dict:
    before = regular(path)
    if not 0 < before.st_size <= limit:
        raise VulnerabilityError("Database file size is invalid")
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while block := stream.read(CHUNK):
            guard()
            size += len(block)
            if size > limit:
                raise VulnerabilityError("Database size limit exceeded")
            hasher.update(block)
    after = regular(path)
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns) or size != before.st_size:
        raise VulnerabilityError("Database changed during validation")
    return {"sha256": hasher.hexdigest(), "bytes": size}


def _header(path: Path, kind: str) -> None:
    with path.open("rb") as stream:
        head = stream.read(100)
    size = path.stat().st_size
    if kind == "java":
        page_size = struct.unpack_from(">H", head, 16)[0] if len(head) >= 100 else 0
        page_size = 65536 if page_size == 1 else page_size
        valid = (head.startswith(b"SQLite format 3\x00") and 512 <= page_size <= 65536
                 and page_size & (page_size - 1) == 0 and size >= page_size
                 and size % page_size == 0)
    else:
        valid = _bolt_header(path, size)
    if not valid:
        raise VulnerabilityError("Invalid database file header")


def _bolt_header(path: Path, size: int) -> bool:
    # bbolt has two checksummed metadata pages. One may be invalid after a
    # torn write; use the other, as bbolt does. Never traverse untrusted trees.
    with path.open("rb") as stream:
        for page_size in (1024, 2048, 4096, 8192, 16384, 32768, 65536):
            if size < page_size * 4 or size % page_size:
                continue
            candidates = []
            for page in (0, 1):
                stream.seek(page * page_size)
                raw = stream.read(80)
                if len(raw) != 80:
                    return False
                page_id, flags, count, overflow = struct.unpack_from("<QHHI", raw)
                magic, version, stored_size, _, root, _, freelist, pages, txid, checksum = (
                    struct.unpack_from("<4I6Q", raw, 16))
                if magic != 0xED0CDAED or version != 2 or stored_size != page_size:
                    continue
                computed = 0xcbf29ce484222325
                for byte in raw[16:72]:
                    computed = ((computed ^ byte) * 0x100000001b3) & 0xffffffffffffffff
                if checksum == computed:
                    valid = (page_id == page and flags == 4 and not count and not overflow
                             and txid % 2 == page and 2 <= root < pages <= size // page_size
                             and (freelist == 0xffffffffffffffff or 2 <= freelist < pages))
                    candidates.append((txid, valid))
            if candidates:
                # A newer checksummed meta wins; invalid bounds on it must not
                # be hidden by an older valid transaction.
                return max(candidates, key=lambda item: item[0])[1]
    return False


def _java_schema(path: Path, guard: Callable[[], None]) -> None:
    # Schema inspection only: read-only/immutable avoids journals or changes to
    # a published generation. Bound SQLite parsing and preserve control errors.
    conn = sqlite3.connect(path.absolute().as_uri() + "?mode=ro&immutable=1", uri=True)
    interrupted = []
    deadline = time.monotonic() + 5

    def progress():
        try:
            guard()
            if time.monotonic() >= deadline:
                raise VulnerabilityError("Java database schema validation timed out")
        except Exception as exc:
            interrupted.append(exc)
            return 1
        return 0

    try:
        conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, JSON_LIMIT)
        conn.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, JSON_LIMIT)
        conn.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 64)
        conn.set_progress_handler(progress, 1000)
        conn.execute("PRAGMA trusted_schema=OFF")
        for table, columns in (("artifacts", {"id", "group_id", "artifact_id"}),
                               ("indices", {"artifact_id", "version", "sha1", "archive_type"})):
            guard()
            row = conn.execute("SELECT type FROM sqlite_schema WHERE name=?", (table,)).fetchone()
            if row != ("table",):
                raise VulnerabilityError("Invalid Java database schema")
            actual = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
            if not columns <= actual:
                raise VulnerabilityError("Invalid Java database schema")
    except sqlite3.Error:
        if interrupted:
            raise interrupted[0]
        raise VulnerabilityError("Invalid Java database schema") from None
    finally:
        conn.close()


def inspect(cache: Path, limit: int, guard: Callable[[], None] = lambda: None,
            *, expected: dict | None = None) -> tuple[dict, list[dict]]:
    tree_size(cache, limit + JSON_LIMIT)
    names = {p.relative_to(cache).as_posix() for p in cache.rglob("*") if p.is_file()}
    names.discard(MANIFEST)
    if not MAIN <= names or names - MEMBERS or (names & JAVA and not JAVA <= names):
        raise VulnerabilityError("Database generation has missing or unexpected files")
    for directory in cache.rglob("*"):
        if directory.is_dir() and directory.relative_to(cache).as_posix() not in {"db", "java-db"}:
            raise VulnerabilityError("Unexpected database directory")
    if expected is not None and names != set(expected):
        raise VulnerabilityError("Database manifest does not match payload files")
    files = {}
    databases = []
    current = datetime.now(timezone.utc)
    total = 0
    for kind, folder, filename, schema in (("main", "db", "trivy.db", 2),
                                           ("java", "java-db", "trivy-java.db", 1)):
        if f"{folder}/{filename}" not in names:
            databases.append(missing_database(kind))
            continue
        meta_path = cache / folder / "metadata.json"
        if regular(meta_path).st_size > JSON_LIMIT:
            raise VulnerabilityError("Database metadata exceeds size limit")
        meta = read_object(meta_path.read_bytes())
        if type(meta.get("Version")) is not int or meta["Version"] != schema:
            raise VulnerabilityError("Unsupported database schema")
        updated = timestamp(meta.get("UpdatedAt"))
        next_update = timestamp(meta.get("NextUpdate"))
        # Upstream OCI artifacts have Go's zero time until a CLI download finishes.
        # Preserve that absence on offline import; never invent a download date.
        raw_downloaded = meta.get("DownloadedAt")
        downloaded = (None if raw_downloaded in (None, "0001-01-01T00:00:00Z")
                      else timestamp(raw_downloaded))
        if (updated > current + timedelta(minutes=5)
                or (downloaded is not None and downloaded > current + timedelta(minutes=5))):
            raise VulnerabilityError("Database timestamp is in the future")
        if next_update <= updated or next_update - updated > timedelta(days=31):
            raise VulnerabilityError("Invalid database freshness interval")
        _header(cache / folder / filename, kind)
        if kind == "java":
            _java_schema(cache / folder / filename, guard)
        for name in (f"{folder}/metadata.json", f"{folder}/{filename}"):
            files[name] = digest(cache / name, limit, guard)
            total += files[name]["bytes"]
            if total > limit:
                raise VulnerabilityError("Database size limit exceeded")
            if expected is not None and files[name] != expected[name]:
                raise VulnerabilityError("Database integrity verification failed")
        dbfile = files[f"{folder}/{filename}"]
        databases.append({"kind": kind, "present": True, "schema": schema,
                          "updated_at": updated.isoformat(), "next_update": next_update.isoformat(),
                          "downloaded_at": downloaded.isoformat() if downloaded else None,
                          "stale": current >= next_update,
                          **dbfile})
    return files, databases


def missing_database(kind: str) -> dict:
    return {"kind": kind, "present": False, "schema": None, "updated_at": None,
            "next_update": None, "downloaded_at": None, "stale": False, "sha256": None, "bytes": None}


def validate_manifest(doc: dict) -> dict:
    if set(doc) != {"format", "version", "created_at", "provenance", "source", "files"}:
        raise VulnerabilityError("Unsupported bundle manifest fields")
    if doc["format"] != FORMAT or type(doc["version"]) is not int or doc["version"] != 1:
        raise VulnerabilityError("Unsupported bundle manifest version")
    timestamp(doc["created_at"])
    if doc["provenance"] not in ("official_download", "offline_import", "unknown"):
        raise VulnerabilityError("Invalid bundle provenance")
    if doc["source"] not in (None, "official_trivy", "offline_bundle"):
        raise VulnerabilityError("Unsupported bundle source")
    files = doc["files"]
    if not isinstance(files, dict) or set(files) not in (MAIN, MAIN | JAVA):
        raise VulnerabilityError("Invalid bundle member list")
    for entry in files.values():
        if not isinstance(entry, dict) or set(entry) != {"sha256", "bytes"}:
            raise VulnerabilityError("Invalid bundle file metadata")
        if (type(entry["bytes"]) is not int or entry["bytes"] <= 0
                or not isinstance(entry["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])):
            raise VulnerabilityError("Invalid bundle size or digest")
    return doc


def _check_zip_directory(path: Path):
    # ZipFile allocates the entire central directory before callers can examine
    # infolist(). Bound its size/count first to reject entry-count memory bombs.
    with path.open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        length = stream.tell()
        # Include the preceding ZIP64 locator even with a maximum-length comment.
        stream.seek(max(0, length - 65577))
        tail = stream.read(65577)
    offset = tail.rfind(b"PK\x05\x06")
    if offset < 0 or len(tail) - offset < 22:
        raise VulnerabilityError("Invalid ZIP directory")
    _, disk, central_disk, disk_entries, entries, size, location, comment = struct.unpack_from("<4s4H2IH", tail, offset)
    if ((offset >= 20 and tail[offset - 20:offset - 16] == b"PK\x06\x07")
            or disk or central_disk or disk_entries != entries or entries not in (3, 5)
            or size > JSON_LIMIT or size < entries * 46
            or location + size != length - len(tail) + offset
            or offset + 22 + comment != len(tail)):
        raise VulnerabilityError("Unsupported or oversized ZIP directory")


def import_zip(path: Path, cache: Path, limit: int, guard: Callable[[], None]) -> dict:
    """No extractall: every member must match a literal name before opening it."""
    try:
        if regular(path).st_size > limit + JSON_LIMIT * 2:
            raise VulnerabilityError("Bundle size limit exceeded")
        guard()
        _check_zip_directory(path)
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            names = [i.filename for i in members]
            if (len(members) not in (3, 5) or len(set(names)) != len(names)
                    or set(names) not in (MAIN | {MANIFEST}, MEMBERS | {MANIFEST})):
                raise VulnerabilityError("Bundle contains missing, duplicate, or unexpected members")
            total = 0
            for info in members:
                mode = info.external_attr >> 16
                if (info.orig_filename != info.filename or info.flag_bits & 1
                        or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        or (stat.S_IFMT(mode) not in (0, stat.S_IFREG))
                        or info.external_attr & 0x10 or info.is_dir()):
                    raise VulnerabilityError("Bundle members must be unencrypted regular files")
                cap = JSON_LIMIT if info.filename.endswith(".json") else limit
                if not 0 < info.file_size <= cap:
                    raise VulnerabilityError("Bundle member exceeds size limit")
                total += info.file_size
            if total > limit + JSON_LIMIT:
                raise VulnerabilityError("Bundle expanded size limit exceeded")
            manifest = validate_manifest(read_object(archive.read(MANIFEST)))
            if set(manifest["files"]) != set(names) - {MANIFEST}:
                raise VulnerabilityError("Bundle manifest does not match archive")
            require_space(cache, sum(info.file_size for info in members if info.filename != MANIFEST))
            expanded = 0
            for name, expected in manifest["files"].items():
                info = archive.getinfo(name)
                if expected["bytes"] != info.file_size:
                    raise VulnerabilityError("Bundle size does not match manifest")
                dest = cache / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                hasher = hashlib.sha256()
                count = 0
                with archive.open(info) as src, dest.open("xb") as out:
                    while block := src.read(CHUNK):
                        guard()
                        expanded += len(block)
                        count += len(block)
                        if expanded > limit or count > expected["bytes"]:
                            raise VulnerabilityError("Bundle expanded size limit exceeded")
                        hasher.update(block)
                        out.write(block)
                    out.flush()
                    os.fsync(out.fileno())
                if count != expected["bytes"] or hasher.hexdigest() != expected["sha256"]:
                    raise VulnerabilityError("Bundle integrity verification failed")
            inspect(cache, limit, guard, expected=manifest["files"])
            return manifest
    except (OSError, zipfile.BadZipFile, NotImplementedError, EOFError, UnicodeError, zlib.error):
        raise VulnerabilityError("Unreadable or corrupt database bundle") from None
