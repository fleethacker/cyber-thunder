"""Bounded, passive local content imports; integrity is not signature verification.

Call import_content with a ContentService, never a path supplied by a remote client.
The caller must also bound HTTP reads before allocating the bytes passed here.
ContentService._accept owns indexing/deltas and must support raw SCAP XML and SRGs.
Upload provenance lives in ingest.upload so existing ContentStore backends retain it.
"""
from __future__ import annotations

import errno
import hashlib
import re
import stat
import tempfile
import time
import unicodedata
import zipfile
import zlib
from pathlib import Path
from typing import TYPE_CHECKING
from xml.etree import ElementTree as ET

from cyberthunder.audit.chain import file_lock
from cyberthunder.control.identity import require_human
from cyberthunder.findings.schema import utcnow
from cyberthunder.ingest.content import fetch as fx
from cyberthunder.ingest.content import index as ix
from cyberthunder.ingest.delta import safe_name

if TYPE_CHECKING:
    from cyberthunder.ingest.content.service import ContentService

MAX_UPLOAD_BYTES = 32 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_MEMBERS = 2048
MAX_ELEMENTS = 250000
MAX_DEPTH = 64
_XCCDF = {"", "http://checklists.nist.gov/xccdf/1.1", "http://checklists.nist.gov/xccdf/1.2"}
_SCAP = {"", "http://scap.nist.gov/schema/scap/source/1.2", "http://scap.nist.gov/schema/scap/source/1.3"}
_AUTOMATED_CHECK_SYSTEMS = {"http://oval.mitre.org/XMLSchema/oval-definitions-5",
                            "http://open-scap.org/page/SCE"}
_DEVICES = {"con", "prn", "aux", "nul", "conin$", "conout$",
            *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


class ContentUploadError(ValueError):
    """A local upload is unsupported, malformed, or exceeds a resource bound."""


def _name(filename: str) -> str:
    if not isinstance(filename, str) or not filename.strip() or len(filename) > 4096:
        raise ContentUploadError("an XML or ZIP filename is required")
    # NFKC also catches Windows' superscript COM/LPT device aliases.
    base = unicodedata.normalize("NFKC", filename).replace("\\", "/").rsplit("/", 1)[-1].rstrip(" .")
    suffix = Path(base).suffix.lower()
    if suffix not in (".xml", ".zip"):
        raise ContentUploadError("only XML and ZIP content uploads are supported")
    stem = fx.disk_name(base[:-len(suffix)])[:100]
    return stem + suffix


class _BoundedTree(ET.TreeBuilder):
    def __init__(self):
        super().__init__()
        self.depth = self.elements = 0

    def doctype(self, name, pubid, system):
        # Expat calls this before expanding entities, including UTF-16 documents.
        raise ContentUploadError("DTD and entity declarations are not permitted")

    def start(self, tag, attrs):
        self.depth += 1
        self.elements += 1
        if self.depth > MAX_DEPTH or self.elements > MAX_ELEMENTS:
            raise ContentUploadError("XML structure exceeds the depth or element limit")
        return super().start(tag, attrs)

    def end(self, tag):
        self.depth -= 1
        return super().end(tag)


def _xml(data: bytes) -> ET.Element:
    try:
        return ET.fromstring(data, parser=ET.XMLParser(target=_BoundedTree()))
    except ContentUploadError:
        raise
    except (ET.ParseError, LookupError, ValueError, RecursionError):
        raise ContentUploadError("content XML does not parse") from None


def _local(el: ET.Element) -> str:
    return el.tag.rsplit("}", 1)[-1]


def _ns(el: ET.Element) -> str:
    return el.tag[1:].split("}", 1)[0] if el.tag.startswith("{") else ""


def _text(el: ET.Element) -> str:
    return " ".join("".join(el.itertext()).split())


def _benchmark(el: ET.Element) -> dict:
    bid = el.get("id", "").strip()
    # The existing manual catalog uses safe_name(id) as a filesystem basename.
    # Refuse lossy/Windows-device IDs before that writer can alias another benchmark.
    if bid and (safe_name(bid) != bid or fx.disk_name(bid) != bid or len(bid) > 180):
        raise ContentUploadError("benchmark id cannot be stored safely")
    rules = [r for r in el.iter() if _local(r) == "Rule"]
    ids = [r.get("id", "").strip() for r in rules]
    if _ns(el) not in _XCCDF or not bid or not ids or not all(ids) or len(set(ids)) != len(ids):
        raise ContentUploadError("XCCDF requires a benchmark id and unique, named rules")
    fields = {name: [_text(c) for c in el if _local(c) == name] for name in ("title", "version")}
    releases = [_text(c) for c in el if _local(c) == "plain-text" and c.get("id") == "release-info"]
    version = fields["version"][0] if len(fields["version"]) == 1 else None
    release = releases[0] if len(releases) == 1 else None
    pair = None
    if version and re.fullmatch(r"[0-9]{1,6}", version) and release:
        match = re.search(r"\bRelease:\s*([0-9]{1,6})\b", release, re.I)
        if match:
            pair = (int(version), int(match[1]))
    elif version and (match := re.fullmatch(r"V([0-9]{1,6})R([0-9]{1,6})", version, re.I)):
        pair = (int(match[1]), int(match[2]))
    elif version and (match := re.fullmatch(r"([0-9]{1,6})\.([0-9]{1,6})", version)):
        # DISA SCAP releases use padded major.release values such as 002.010.
        pair = (int(match[1]), int(match[2]))
    return {"benchmark_id": bid, "title": fields["title"][0] if fields["title"] else None,
            "version": version, "release_info": release, "catalog_version": list(pair) if pair else None,
            "status": [{"value": _text(c), "date": c.get("date")} for c in el if _local(c) == "status"],
            "version_time": next((c.get("time") for c in el if _local(c) == "version"), None),
            "references": [{"href": c.get("href"), "text": _text(c)} for c in el if _local(c) == "reference"],
            "rules": len(ids)}


def _describe(root: ET.Element) -> dict | None:
    name = _local(root)
    if name not in ("Benchmark", "data-stream-collection"):
        return None
    if name == "data-stream-collection" and _ns(root) not in _SCAP:
        raise ContentUploadError("unsupported SCAP namespace")
    benchmarks = [_benchmark(el) for el in root.iter() if _local(el) == "Benchmark"]
    if not benchmarks:
        raise ContentUploadError("SCAP content contains no XCCDF benchmark")
    # Manual DISA checks also have check-content-ref (system="C-..._chk").
    # Only recognized automated check systems make a bare Benchmark SCAP content.
    automatic = name == "data-stream-collection" or any(
        _local(el) == "check" and el.get("system") in _AUTOMATED_CHECK_SYSTEMS and
        any(_local(child) in ("check-content-ref", "check-content") for child in el) for el in root.iter())
    srg = all(re.search(r"(?:^|_)SRG$", b["benchmark_id"], re.I) or
              (b["title"] or "").lower().endswith("security requirements guide") for b in benchmarks)
    return {"kind": "scap_benchmark" if automatic else "srg" if srg else "manual_stig",
            "benchmarks": benchmarks}


def _member_name(info: zipfile.ZipInfo) -> str:
    name = unicodedata.normalize("NFKC", info.orig_filename).replace("\\", "/")
    parts = name.rstrip("/").split("/")
    if (name.startswith("/") or any(p in ("", ".", "..") or ":" in p or p != p.rstrip(" .") or
            any(ord(c) < 32 or c in '<>"|?*' for c in p) or
            p.split(".", 1)[0].casefold() in _DEVICES for p in parts)):
        raise ContentUploadError("ZIP member has an unsafe path")
    mode = stat.S_IFMT(info.external_attr >> 16)
    if mode not in (0, stat.S_IFREG, stat.S_IFDIR) or info.flag_bits & 1:
        raise ContentUploadError("ZIP links, special files and encrypted members are not supported")
    if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise ContentUploadError("unsupported ZIP compression method")
    return name.casefold()


def _validate(path: Path, filename: str) -> dict:
    if filename.endswith(".xml"):
        description = _describe(_xml(path.read_bytes()))
        if description is None:
            raise ContentUploadError("XML is not an XCCDF benchmark or SCAP datastream")
        return dict(description, member=None, integrity_checks=["xml"])
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_MEMBERS:
                raise ContentUploadError("ZIP exceeds the member count limit")
            names = [_member_name(info) for info in infos]
            if len(names) != len(set(names)):
                raise ContentUploadError("ZIP has duplicate member paths")
            if any(info.file_size > MAX_UPLOAD_BYTES for info in infos):
                raise ContentUploadError("ZIP member exceeds the decompression limit")
            if sum(info.file_size for info in infos) > MAX_EXPANDED_BYTES:
                raise ContentUploadError("ZIP exceeds the total decompression limit")
            descriptions = {}
            expanded = 0
            for info in infos:
                if info.is_dir():
                    if info.file_size:
                        raise ContentUploadError("ZIP directory contains file data")
                    continue
                xml = info.filename.lower().endswith((".xml", ".xsl", ".xslt"))
                chunks = []
                size = 0
                with archive.open(info) as source:
                    while chunk := source.read(fx.CHUNK):
                        size += len(chunk)
                        expanded += len(chunk)
                        if size > MAX_UPLOAD_BYTES or expanded > MAX_EXPANDED_BYTES:
                            raise ContentUploadError("ZIP exceeds the decompression limit")
                        if xml:
                            chunks.append(chunk)
                if xml:
                    description = _describe(_xml(b"".join(chunks)))
                    if description is not None:
                        descriptions[info.filename] = description
            if not descriptions:
                raise ContentUploadError("ZIP contains no XCCDF benchmark or SCAP datastream")
            kinds = {d["kind"] for d in descriptions.values()}
            # Match the existing acceptance readers exactly; never validate one member and ingest another.
            member = fx.find_datastream(archive) if "scap_benchmark" in kinds else fx._pick_member(archive)
            description = descriptions.get(member.filename)
            if description is None or ("scap_benchmark" in kinds and description["kind"] != "scap_benchmark"):
                raise ContentUploadError("ZIP benchmark selection is ambiguous")
            if len(descriptions) != 1:
                raise ContentUploadError("upload one benchmark package at a time")
            return dict(description, member=member.filename, integrity_checks=["zip_crc", "xml"])
    except ContentUploadError:
        raise
    except OSError as exc:
        if exc.errno != errno.EINVAL:
            raise
        raise ContentUploadError("ZIP has invalid member offsets") from None
    except (ValueError, zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, zlib.error):
        raise ContentUploadError("ZIP is corrupt or has no supported benchmark member") from None


def _identity(value: str) -> str:
    value = re.sub(r"^xccdf_[^ ]*?_benchmark_", "", value, flags=re.I)
    value = re.sub(r"_(STIG|SRG)$", "", value, flags=re.I).casefold()
    value = value.replace("microsoft", "ms").replace("red_hat_enterprise_linux", "rhel")
    return re.sub(r"[^a-z0-9]", "", value)


def _entry(svc: ContentService, name: str, digest: str, description: dict) -> ix.Entry:
    benchmarks = description["benchmarks"]
    product = version = None
    if len(benchmarks) == 1:
        benchmark = benchmarks[0]
        entries, _ = svc.catalog_entries()  # local cache/snapshot only; never check the live index
        matches = {e.product_key for e in entries if e.product_key and
                   _identity(e.product_key) == _identity(benchmark["benchmark_id"])}
        if len(matches) == 1:
            product = matches.pop()
        version = tuple(benchmark["catalog_version"]) if benchmark["catalog_version"] else None
    # An exact official filename alone marks content current in existing selection code.
    # A digest-qualified local name also keeps failed/new releases away from previous good bytes.
    filename = f"upload-{digest}-{name}"
    return ix.Entry(filename=filename, url="", host="", title=benchmarks[0]["title"] or name,
                    kind=description["kind"], product_key=product, version=version,
                    version_label=f"V{version[0]}R{version[1]}" if version else None)


def import_content(svc: ContentService, data: bytes, filename: str, actor: str) -> dict:
    """Return {record: HeldRecord, delta: PullDelta | None}; never scan or run uploaded content.

    Duplicate held bytes return the existing record and delta=None without changing provenance.
    Unknown identities/versions remain unknown; filenames supply neither identity nor release.
    ContentUploadError means validation failed, PermissionError means actor validation failed,
    and the existing KillSwitchEngaged exception means the import was stopped.
    """
    try:
        actor = require_human(actor)
        if actor.casefold() == "operator":
            raise PermissionError("content upload requires a named human actor")
    except PermissionError:
        svc.audit.append("content.import", "?", {"reason": "named human actor required"}, outcome="blocked")
        raise
    svc.ctx.killswitch.guard("content.import", actor)
    started = time.monotonic()
    details = {"source": "uploaded", "bytes": len(data) if isinstance(data, bytes) else 0}
    try:
        name = _name(filename)
        if not isinstance(data, bytes) or not data:
            raise ContentUploadError("upload must contain nonempty bytes")
        if len(data) > MAX_UPLOAD_BYTES:
            raise ContentUploadError("upload exceeds the 32 MiB size limit")
        digest = hashlib.sha256(data).hexdigest()
        details["sha256"] = digest
        staging = svc.store.root / "incoming"
        staging.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="upload-", dir=staging) as temporary:
            work = Path(temporary) / name
            work.write_bytes(data)
            try:
                description = _validate(work, name)
            except ContentUploadError as exc:
                fx.quarantine(work, svc.store.quarantine_dir, str(exc), filename=name)
                svc.audit.append("content.quarantine", actor, dict(details, reason=str(exc)),
                                 outcome="failed", subject=name)
                raise
            with svc._job_lock, file_lock(svc.store.root / "upload.lock"):
                svc.ctx.killswitch.guard("content.import", actor)
                if svc._running:
                    raise ContentUploadError("a content pull is running; retry the upload after it finishes")
                for held in svc.store.records():
                    if held.get("sha256") == digest:
                        dest = svc.store.files_dir / fx.disk_name(held.get("disk_name") or held["filename"])
                        if dest.is_file() and dest.stat().st_size == len(data) and fx.sha256_file(dest) == digest:
                            svc.audit.append("content.import", actor, dict(details, identical=True), subject=name)
                            return {"record": held, "delta": None}
                entry = _entry(svc, name, digest, description)
                svc.ctx.killswitch.guard("content.import", actor)
                record = svc._accept(work, entry, source="uploaded", actor=actor,
                                     sha256=digest, etag=None, size=len(data))
                # _accept timestamps its fetch. Local receipt is separate from publisher release or live sync.
                benchmark = description["benchmarks"][0] if len(description["benchmarks"]) == 1 else {}
                release = benchmark.get("release_info") or benchmark.get("version")
                record.update(fetched_at=None, fetched_by=None, benchmark_id=benchmark.get("benchmark_id"),
                              benchmark_release=release)
                record["ingest"]["upload"] = dict(description, filename=name, imported_at=utcnow(),
                                                  imported_by=actor, authenticity_verified=False)
                record = svc.store.put(record)
                details["seconds"] = round(time.monotonic() - started, 3)
                svc.audit.append("content.import", actor, details, subject=entry.filename)
                return {"record": record, "delta": record["ingest"].get("delta")}
    except (ContentUploadError, OSError, ValueError, RuntimeError) as exc:
        details.update(seconds=round(time.monotonic() - started, 3), error=type(exc).__name__)
        svc.audit.append("content.import_failed", actor, details, outcome="failed")
        raise


__all__ = ["import_content", "MAX_UPLOAD_BYTES", "ContentUploadError"]
