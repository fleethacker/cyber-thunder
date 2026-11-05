"""Bounded, passive Nessus/ACAS imports into the normal scan and findings store."""
from __future__ import annotations

import hashlib
import json
import re
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path

from cyberthunder.audit.chain import file_lock
from cyberthunder.control.identity import require_human
from cyberthunder.findings.schema import Finding, RE_CVE, summarize
from cyberthunder.parsers.nessus import parse_nessus
from cyberthunder.scan import ScanRun, TargetScanResult
from cyberthunder.store import is_partial_run

MAX_XML_BYTES = 16 * 1024 * 1024
MAX_MAPPING_BYTES = 256 * 1024
MAX_UPLOAD_BYTES = MAX_XML_BYTES + MAX_MAPPING_BYTES + 64 * 1024
MAX_HOSTS = 4096
MAX_ITEMS = 50000
MAX_ELEMENTS = 250000
MAX_DEPTH = 32
MAX_FIELD = 65536


class ScannerImportError(ValueError):
    """A safe, fixed diagnostic; never include source text or source paths."""


def import_actor(actor: str) -> str:
    try:
        actor = require_human(actor)
        if actor.casefold() == "operator":
            raise PermissionError
    except PermissionError:
        raise PermissionError("scanner import requires a named human actor") from None
    return actor


def read_local_file(path: str | Path, limit: int) -> bytes:
    """CLI-only path reader. HTTP accepts bytes, never server paths."""
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(limit + 1)
    except OSError:
        raise ScannerImportError("cannot read scanner import input") from None
    if len(data) > limit:
        raise ScannerImportError("scanner import input exceeds the size limit")
    return data


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ScannerImportError("host mapping contains duplicate keys")
        result[key] = value
    return result


def parse_mapping(data: bytes) -> dict[str, str]:
    if len(data) > MAX_MAPPING_BYTES:
        raise ScannerImportError("host mapping exceeds the size limit")
    try:
        mapping = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise ScannerImportError("host mapping must be a valid JSON object with unique keys") from None
    return validate_mapping(mapping)


def validate_mapping(mapping) -> dict[str, str]:
    if not isinstance(mapping, dict) or not mapping or len(mapping) > MAX_HOSTS:
        raise ScannerImportError("a non-empty host mapping is required within the host limit")
    for key, value in mapping.items():
        if any(not isinstance(s, str) or not s.strip() or len(s) > 1024
               or any(ord(c) < 32 or ord(c) == 127 for c in s) for s in (key, value)):
            raise ScannerImportError("host mapping entries must be non-empty bounded strings without controls")
    if len(set(mapping.values())) != len(mapping):
        raise ScannerImportError("each source host must map to a distinct inventory target")
    if len(json.dumps(mapping).encode("utf-8")) > MAX_MAPPING_BYTES:
        raise ScannerImportError("host mapping exceeds the size limit")
    return dict(mapping)


def parse_upload(body: bytes, content_type: str) -> tuple[bytes, dict, bool]:
    """Strict stdlib multipart reader; filenames and other MIME metadata are discarded."""
    if len(body) > MAX_UPLOAD_BYTES:
        raise ScannerImportError("scanner upload exceeds the size limit")
    if len(content_type) > 256 or "\r" in content_type or "\n" in content_type:
        raise ScannerImportError("invalid scanner upload content type")
    try:
        message = BytesParser(policy=policy.default).parsebytes(
            b"Content-Type: " + content_type.encode("ascii") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body)
        boundary = message.get_boundary()
        if (message.get_content_type() != "multipart/form-data" or not message.is_multipart()
                or not boundary or len(boundary) > 70 or message.defects):
            raise ValueError
        fields = {}
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if (part.is_multipart() or part.defects or name not in {"file", "host_map", "include_info"}
                    or name in fields or part.get_content_disposition() != "form-data"
                    or part.get("Content-Transfer-Encoding", "binary").lower() not in {"binary", "7bit", "8bit"}):
                raise ValueError
            fields[name] = part.get_payload(decode=True)
        if set(fields) not in ({"file", "host_map"}, {"file", "host_map", "include_info"}):
            raise ValueError
        include = fields.get("include_info", b"false")
        if include not in (b"true", b"false"):
            raise ValueError
    except (ValueError, UnicodeError, TypeError):
        raise ScannerImportError("send multipart file, host_map JSON, and optional include_info=true or false") from None
    return fields["file"], parse_mapping(fields["host_map"]), include == b"true"


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


class _BoundedTree(ET.TreeBuilder):
    def __init__(self):
        super().__init__()
        self.sizes = []
        self.elements = 0

    def doctype(self, name, pubid, system):
        raise ScannerImportError("DTD and entity declarations are not allowed")

    def start(self, tag, attrs):
        self.elements += 1
        self.sizes.append(0)
        if (len(self.sizes) > MAX_DEPTH or self.elements > MAX_ELEMENTS or len(attrs) > 64
                or len(tag) > 1024 or any(len(k) > 1024 or len(v) > MAX_FIELD for k, v in attrs.items())):
            raise ScannerImportError("scanner XML exceeds structural limits")
        return super().start(tag, attrs)

    def data(self, data):
        if self.sizes:
            self.sizes[-1] += len(data)
            if self.sizes[-1] > MAX_FIELD:
                raise ScannerImportError("scanner XML field exceeds the size limit")
        return super().data(data)

    def end(self, tag):
        self.sizes.pop()
        return super().end(tag)


def _validate_xml(data: bytes) -> set[str]:
    if not isinstance(data, bytes) or not data or len(data) > MAX_XML_BYTES:
        raise ScannerImportError("scanner XML must be non-empty and within the size limit")
    try:
        root = ET.fromstring(data, parser=ET.XMLParser(target=_BoundedTree()))
    except (ET.ParseError, LookupError, ValueError):
        raise ScannerImportError("invalid or unsafe Nessus XML") from None
    if _local(root.tag) != "NessusClientData_v2":
        raise ScannerImportError("expected a NessusClientData_v2 export")
    parents = {child: parent for parent in root.iter() for child in parent}
    reports, hosts, items = [], set(), 0
    for node in root.iter():
        tag = _local(node.tag)
        parent = parents.get(node)
        parent_tag = _local(parent.tag) if parent is not None else ""
        if tag == "Report":
            if parent is not root:
                raise ScannerImportError("invalid scanner report structure")
            reports.append(node)
        elif tag == "ReportHost":
            host = node.get("name", "")
            if (parent_tag != "Report" or not host.strip() or len(host) > 1024 or host in hosts
                    or any(ord(c) < 32 or ord(c) == 127 for c in host)):
                raise ScannerImportError("source host names must be non-empty, unique and valid")
            hosts.add(host)
        elif tag == "HostProperties" and parent_tag != "ReportHost":
            raise ScannerImportError("invalid scanner host properties structure")
        elif tag == "ReportItem":
            items += 1
            plugin, port = node.get("pluginID", ""), node.get("port", "")
            if (parent_tag != "ReportHost" or not re.fullmatch(r"[0-9]{1,10}", plugin)
                    or not re.fullmatch(r"[0-9]{1,5}", port) or int(port) > 65535
                    or node.get("severity") not in {"0", "1", "2", "3", "4"}
                    or node.get("protocol") not in {"tcp", "udp", "icmp"}):
                raise ScannerImportError("invalid scanner plugin, port, protocol or severity")
            for child in node:
                if _local(child.tag) == "cve" and not RE_CVE.fullmatch((child.text or "").strip().upper()):
                    raise ScannerImportError("invalid scanner CVE identifier")
            fields = {_local(c.tag): c.text or "" for c in node}
            if any(k.startswith("compliance-") for k in fields) and not any(
                    fields.get(k, "").strip() for k in ("compliance-check-id", "compliance-check-name")):
                raise ScannerImportError("compliance results require a stable check identifier or name")
    if len(reports) != 1 or not hosts or not items or len(hosts) > MAX_HOSTS or items > MAX_ITEMS:
        raise ScannerImportError("export must contain one report with hosts and results within the import limits")
    return hosts


def import_results(ctx, data: bytes, host_map: dict[str, str], *, actor: str, include_info: bool = False) -> dict:
    """Validate everything before writes; only public store methods publish the import."""
    actor = import_actor(actor)
    try:
        return _import_results(ctx, data, host_map, actor=actor, include_info=include_info)
    except OSError:
        raise OSError("scanner import storage is unavailable") from None


def _import_results(ctx, data: bytes, host_map: dict[str, str], *, actor: str, include_info: bool) -> dict:
    ctx.killswitch.guard("ingest.scanner", actor)
    if not isinstance(include_info, bool):
        raise ScannerImportError("include_info must be a boolean")
    mapping = validate_mapping(host_map)
    hosts = _validate_xml(data)
    if set(mapping) != hosts:
        raise ScannerImportError("host mapping must match every ReportHost name exactly, with no extra entries")
    targets = {target.id: target for target in ctx.inventory.all()}
    if any(tid not in targets for tid in mapping.values()):
        raise ScannerImportError("host mapping references an unknown inventory target")
    source_hash = hashlib.sha256(data).hexdigest()
    identity = {"version": 1, "source": "acas", "sha256": source_hash, "host_map": mapping,
                "include_info": include_info}
    import_id = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    scan_id = "scan-import-" + import_id
    # The existing parser takes a path. Keep its input outside persistent state, and always remove it.
    with tempfile.TemporaryDirectory(prefix="ct-scanner-") as temporary:
        path = Path(temporary) / "input.nessus"
        path.write_bytes(data)
        try:
            findings = parse_nessus(path, include_info=include_info)
        except (ET.ParseError, ValueError, LookupError):
            raise ScannerImportError("cannot normalize scanner results") from None
    if not findings:
        raise ScannerImportError("export contains no importable findings; current results were preserved")
    for finding in findings:
        original_host = finding.host
        finding.host = mapping[original_host]
        finding.id = Finding.make_id(finding.host, finding.source, finding.rule_id)
        finding.asset_type = targets[finding.host].asset_type
        finding.scan_id = scan_id
        finding.raw_ref = "sha256:" + source_hash
        finding.tags.extend(["import:nessus", "source-host:" + original_host])
    result = {"scan_id": scan_id, "source": "acas", "source_sha256": source_hash,
              "import_id": import_id, "imported_count": len(findings), "targets": sorted(mapping.values())}
    store = ctx.store
    ctx.killswitch.guard("ingest.scanner", actor)
    with file_lock(store.ingest_dir / "scanner-import.lock"):
        ctx.killswitch.guard("ingest.scanner", actor)
        existing = store.load_scan_run(scan_id)
        if existing is not None:
            ctx.audit.append("ingest.scanner.repeat", actor, result, subject=scan_id)
            return dict(result, repeated=True, carried_forward_count=existing["findings_count"] - len(findings))
        # With no full baseline, StateStore starts at the newest partial run. Carry prior observations
        # forward explicitly so imports on a fresh node also preserve unrelated hosts and findings.
        runs = store.list_scan_runs()
        merged = {}
        if not any(not is_partial_run(run) for run in runs):
            for run in reversed(runs):
                merged.update((f.id, f) for f in store.load_findings(run["id"]))
        merged.update((f.id, f) for f in findings)
        saved = list(merged.values())
        carried = len(saved) - len(findings)
        now = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        host_counts = Counter(f.host for f in saved)
        open_counts = Counter(f.host for f in saved if f.is_open)
        run_hosts = sorted(host_counts)
        run = ScanRun(id=scan_id, targets=run_hosts, modules=["scanner_import"],
                      rule_filter=sorted({f.rule_id for f in saved}), trigger="scanner_import",
                      requested_by=actor, status="done", started_at=now, finished_at=now,
                      findings_count=len(saved), summary=summarize(saved), results={
                          tid: TargetScanResult(target_id=tid, status="done", started_at=now, finished_at=now,
                                                findings=host_counts[tid], open=open_counts[tid])
                          for tid in run_hosts})
        # Findings first, run last: readers cannot discover an empty run if saving findings fails.
        ctx.killswitch.guard("ingest.scanner", actor)
        store.save_findings(scan_id, saved, meta=dict(identity, import_id=import_id, trigger="scanner_import",
                                                    imported_count=len(findings), carried_forward_count=carried))
        ctx.killswitch.guard("ingest.scanner", actor)
        ctx.audit.append("ingest.scanner.publish", actor, dict(result, carried_forward_count=carried),
                         subject=scan_id)
        ctx.killswitch.guard("ingest.scanner", actor)
        store.save_scan_run(run.to_dict())
        ctx.audit.append("ingest.scanner", actor, dict(result, carried_forward_count=carried), subject=scan_id)
    return dict(result, repeated=False, carried_forward_count=carried)
