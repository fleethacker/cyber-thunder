"""Passive, bounded container OS XCCDF observations; no platform or host inference."""
from __future__ import annotations

import base64
import binascii
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import re
import xml.etree.ElementTree as ET

from cyberthunder.audit.chain import file_lock
from cyberthunder.control.principal import authorize
from cyberthunder.findings.schema import Finding, Status, summarize
from cyberthunder.ingest.scanner_results import import_actor, read_local_file
from cyberthunder.inventory.host import persisted_target
from cyberthunder.scan import ScanRun, TargetScanResult
from cyberthunder.security.resources import capture, check_record

MAX_XML_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_UPLOAD_BYTES = ((MAX_XML_BYTES + 2) // 3) * 4 + MAX_MANIFEST_BYTES + 1024
MAX_ELEMENTS = 250000
MAX_DEPTH = 32
MAX_FIELD = 65536
MAX_RESULTS = 50000
NAMESPACES = {"http://checklists.nist.gov/xccdf/1.1", "http://checklists.nist.gov/xccdf/1.2"}
RESULTS = {"pass", "fail", "error", "notapplicable", "notchecked", "unknown",
           "notselected", "informational", "fixed"}
SOURCE = "openscap-container"


class ScapImportError(ValueError):
    """Fixed diagnostics that do not echo untrusted content or local paths."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value, maximum=1024):
    if (not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum
            or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value)):
        raise ScapImportError("expected nonempty bounded text without controls or surrounding whitespace")
    return value


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ScapImportError("duplicate JSON keys are not allowed")
        result[key] = value
    return result


def _json(data, limit):
    if not isinstance(data, bytes) or not data or len(data) > limit:
        raise ScapImportError("JSON input exceeds the size limit or is empty")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise ScapImportError("expected valid UTF-8 JSON with unique keys") from None


def validate_manifest(value):
    fields = {"source_id", "test_result_id", "target_id", "benchmark_id", "profile_id",
              "expected_rule_ids", "provenance"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ScapImportError("manifest requires exact source, TestResult, target, benchmark, profile, rules and provenance")
    for key in fields - {"expected_rule_ids", "provenance"}:
        _text(value[key])
    rules = value["expected_rule_ids"]
    if not isinstance(rules, list) or not rules or len(rules) > MAX_RESULTS:
        raise ScapImportError("expected_rule_ids must be a nonempty bounded list")
    for rule in rules:
        _text(rule)
    if len(set(rules)) != len(rules):
        raise ScapImportError("expected_rule_ids contains duplicates")
    p = value["provenance"]
    required = {"engine", "engine_version", "mode", "image_ref", "subject_ref", "platform", "exit_code"}
    if not isinstance(p, dict) or set(p) not in (required, required | {"image_digest"}):
        raise ScapImportError("explicit engine, image, subject, platform and exit-code provenance is required")
    for key in set(p) - {"exit_code"}:
        _text(p[key])
    if p["engine"] != "openscap" or p["mode"] not in {"rootfs", "podman-image", "podman-container"}:
        raise ScapImportError("unsupported engine or container evaluation mode")
    if type(p["exit_code"]) is not int or not 0 <= p["exit_code"] <= 255:
        raise ScapImportError("exit_code must be an integer between 0 and 255")
    if "image_digest" in p and not re.fullmatch(r"sha256:[a-f0-9]{64}", p["image_digest"]):
        raise ScapImportError("image_digest must be a SHA-256 digest")
    if len(_canonical(value)) > MAX_MANIFEST_BYTES:
        raise ScapImportError("manifest exceeds the size limit")
    return {**value, "expected_rule_ids": sorted(rules), "provenance": dict(p)}


def parse_manifest(data):
    return validate_manifest(_json(data, MAX_MANIFEST_BYTES))


def parse_upload(data):
    envelope = _json(data, MAX_UPLOAD_BYTES)
    if not isinstance(envelope, dict) or set(envelope) != {"xml_base64", "manifest"}:
        raise ScapImportError("send only xml_base64 and manifest; server paths are not accepted")
    encoded = envelope["xml_base64"]
    if not isinstance(encoded, str) or len(encoded) > ((MAX_XML_BYTES + 2) // 3) * 4:
        raise ScapImportError("encoded XML exceeds the size limit")
    try:
        xml = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise ScapImportError("xml_base64 must be strict base64") from None
    return xml, validate_manifest(envelope["manifest"])


class _BoundedTree(ET.TreeBuilder):
    def __init__(self):
        super().__init__()
        self.sizes = []
        self.elements = 0

    def doctype(self, name, pubid, system):
        # Parser callback also catches UTF-16 declarations; byte-string searches do not.
        raise ScapImportError("DTD and entity declarations are not allowed")

    def start(self, tag, attrs):
        self.elements += 1
        self.sizes.append(0)
        if (len(self.sizes) > MAX_DEPTH or self.elements > MAX_ELEMENTS or len(attrs) > 64
                or len(tag) > 1024 or any(len(k) > 1024 or len(v) > MAX_FIELD for k, v in attrs.items())):
            raise ScapImportError("XCCDF exceeds structural limits")
        return super().start(tag, attrs)

    def data(self, data):
        if self.sizes:
            self.sizes[-1] += len(data)
            if self.sizes[-1] > MAX_FIELD:
                raise ScapImportError("XCCDF field exceeds the size limit")
        return super().data(data)

    def end(self, tag):
        self.sizes.pop()
        return super().end(tag)


def parse_results(data, manifest):
    """One namespace-qualified Benchmark/TestResult. Never resolve external references."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_XML_BYTES:
        raise ScapImportError("XCCDF must be nonempty bytes within the size limit")
    try:
        root = ET.fromstring(data, parser=ET.XMLParser(target=_BoundedTree()))
    except (ET.ParseError, LookupError, ValueError):
        raise ScapImportError("invalid or unsafe XCCDF XML") from None
    namespace, sep, local = root.tag[1:].partition("}") if root.tag.startswith("{") else ("", "", "")
    if not sep or namespace not in NAMESPACES or local not in {"Benchmark", "TestResult"}:
        raise ScapImportError("expected a namespace-qualified XCCDF Benchmark or TestResult")
    q = lambda name: "{" + namespace + "}" + name
    parents = {child: parent for parent in root.iter() for child in parent}
    critical = {"Benchmark", "TestResult", "Rule", "rule-result", "result", "profile", "benchmark"}
    for node in root.iter():
        name = node.tag.rsplit("}", 1)[-1]
        if name in critical and node.tag != q(name):
            raise ScapImportError("mixed or ambiguous XCCDF namespaces")
        parent = parents.get(node)
        if name == "Benchmark" and node is not root:
            raise ScapImportError("nested benchmarks are not supported")
        if name == "TestResult" and node is not root and parent is not root:
            raise ScapImportError("nested TestResult is not supported")
        if name == "rule-result" and (parent is None or parent.tag != q("TestResult")):
            raise ScapImportError("invalid rule-result placement")
        if name == "result" and (parent is None or parent.tag != q("rule-result")):
            raise ScapImportError("invalid result placement")
        if name in {"benchmark", "profile"} and (parent is None or parent.tag != q("TestResult")):
            raise ScapImportError("invalid result identity placement")
        if name in {"Rule", "Group"} and (parent is None or parent.tag not in {q("Benchmark"), q("Group")}):
            raise ScapImportError("invalid benchmark rule placement")
    tests = list(root.iter(q("TestResult")))
    if len(tests) != 1 or tests[0].get("id") != manifest["test_result_id"]:
        raise ScapImportError("exactly one explicitly matching TestResult is required")
    test = tests[0]
    profiles = test.findall(q("profile"))
    benchmarks = test.findall(q("benchmark"))
    if len(profiles) != 1 or profiles[0].get("idref") != manifest["profile_id"]:
        raise ScapImportError("profile identity does not match the explicit manifest")
    if (len(benchmarks) > 1 or local == "TestResult" and len(benchmarks) != 1
            or local == "Benchmark" and root.get("id") != manifest["benchmark_id"]
            or benchmarks and benchmarks[0].get("id") != manifest["benchmark_id"]):
        raise ScapImportError("benchmark identity is missing, ambiguous or inconsistent")
    metadata = {}
    for rule in root.iter(q("Rule")):
        rid = _text(rule.get("id"))
        if rid in metadata or len(metadata) >= MAX_RESULTS:
            raise ScapImportError("duplicate rules or too many rules")
        titles = rule.findall(q("title"))
        if len(titles) > 1:
            raise ScapImportError("ambiguous rule title")
        title = " ".join("".join(titles[0].itertext()).split()) if titles else rid
        if len(title) > MAX_FIELD:
            raise ScapImportError("rule title exceeds the size limit")
        metadata[rid] = (title or rid, rule.get("severity", "unknown"))
    rows = {}
    for rr in test.findall(q("rule-result")):
        rid = _text(rr.get("idref"))
        results = rr.findall(q("result"))
        if rid in rows or len(rows) >= MAX_RESULTS:
            raise ScapImportError("duplicate or conflicting rule results, or too many results")
        if len(results) != 1 or len(results[0]) or (results[0].text or "").strip() not in RESULTS:
            raise ScapImportError("each rule-result requires exactly one recognized result")
        raw = results[0].text.strip()
        title, severity = metadata.get(rid, (rid, "unknown"))
        rows[rid] = {"result": raw, "title": title, "severity": rr.get("severity", severity)}
    if not rows:
        raise ScapImportError("TestResult contains no rule results")
    missing = sorted(set(manifest["expected_rule_ids"]) - set(rows))
    for rid in missing:
        title, severity = metadata.get(rid, (rid, "unknown"))
        rows[rid] = {"result": "missing", "title": title, "severity": severity}
    if len(rows) > MAX_RESULTS:
        raise ScapImportError("results including missing rules exceed the result limit")
    for name in ("start-time", "end-time"):
        if test.get(name):
            try:
                if "T" not in test.get(name):
                    raise ValueError
                datetime.fromisoformat(test.get(name))
            except ValueError:
                raise ScapImportError("invalid evaluation timestamp") from None
    # An absent completion timestamp or engine error cannot establish complete evaluation.
    finished = bool(test.get("end-time")) and manifest["provenance"]["exit_code"] in {0, 2}
    complete = finished
    complete = complete and not any(r["result"] in {"missing", "error", "notchecked", "unknown", "informational"}
                                    or r["result"] == "notselected" and rid in manifest["expected_rule_ids"]
                                    for rid, r in rows.items())
    counts = dict(sorted(Counter(r["result"] for r in rows.values()).items()))
    return rows, {"result_counts": counts, "missing_rule_ids": missing,
                  "notselected_rule_ids": sorted(rid for rid, r in rows.items() if r["result"] == "notselected"),
                  "evaluation_finished": finished, "evaluated_at": test.get("end-time") or test.get("start-time"),
                  "result_scope_complete": bool(complete), "platform_applicability": "unverified",
                  "compliance_claim": False}


def import_results(ctx, data, manifest, *, actor):
    """Publish observations last; exact repeats retain their original time and ownership."""
    actor = import_actor(actor)
    try:
        return _import_results(ctx, data, manifest, actor=actor)
    except PermissionError:
        raise
    except OSError:
        raise OSError("SCAP import storage is unavailable") from None


def _import_results(ctx, data, manifest, *, actor):
    authorize(ctx, "import", actor=actor)
    ctx.killswitch.guard("ingest.scap", actor)
    manifest = validate_manifest(manifest)
    tid = manifest["target_id"]
    try:
        scopes = capture(ctx, [tid])
        target = persisted_target(ctx.inventory, tid)
    except (KeyError, ValueError):
        raise ScapImportError("manifest references an unavailable inventory target") from None

    def guard():
        authorize(ctx, "import", actor=actor)
        authorize(ctx, "import", actor=actor, target=target)
        authorize(ctx, "read", actor=actor, target=target)
        try:
            unchanged = capture(ctx, [tid]) == scopes
        except (KeyError, ValueError):
            unchanged = False
        if not unchanged:
            raise PermissionError("SCAP import target ownership changed")
        ctx.killswitch.guard("ingest.scap", actor)

    guard()
    rows, coverage = parse_results(data, manifest)
    source_hash = hashlib.sha256(data).hexdigest()
    identity = {"version": 1, "source": SOURCE, "source_sha256": source_hash, "manifest": manifest}
    import_id = _digest(identity)
    scan_id = "scan-scap-" + import_id
    # Observation identity isolates target generations and explicitly declared container evidence.
    observation = {"source_id": manifest["source_id"], "test_result_id": manifest["test_result_id"],
                   "benchmark_id": manifest["benchmark_id"], "profile_id": manifest["profile_id"],
                   "subject": {key: value for key, value in manifest["provenance"].items()
                               if key not in {"engine", "engine_version", "exit_code"}},
                   "authorization_scopes": scopes}
    now = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    findings = []
    for rid, row in sorted(rows.items()):
        raw = row["result"]
        status = Status.from_xccdf(raw) or Status.NOT_REVIEWED
        findings.append(Finding(host=tid, source=SOURCE, rule_id=rid, title=row["title"],
            severity=row["severity"], status=status, id=_digest([observation, rid])[:32],
            benchmark=manifest["benchmark_id"], asset_type="containers", scan_id=scan_id,
            raw_ref="sha256:" + source_hash, collected_at=coverage["evaluated_at"] or "", authorization_scope=scopes[0],
            evidence="Imported container OS observation; XCCDF result: " + raw +
                     ". Platform applicability is unverified; no compliance certification.",
            tags=["import:container-scap", "xccdf-result:" + raw],
            collection_provenance={"producer": "container_scap_import", "source_sha256": source_hash,
                **observation, "provenance": manifest["provenance"], "raw_result": raw,
                "platform_applicability": "unverified",
                "compliance_claim": False}))
    # Existing reports count scanner errors/unreviewed observations, not arbitrary run summary
    # fields. A separate coverage observation makes incomplete evaluation and unverified platform
    # applicability visible even when every supplied rule says pass or notapplicable.
    findings.append(Finding(host=tid, source=SOURCE, rule_id="container-scap:coverage",
        id=_digest([observation, {"kind": "coverage"}])[:32], title="Container OS evaluation coverage",
        severity="info", status=Status.NOT_REVIEWED if coverage["evaluation_finished"] else Status.ERROR,
        asset_type="containers", scan_id=scan_id, authorization_scope=scopes[0], collected_at=now,
        raw_ref="sha256:" + source_hash,
        evidence="Container platform applicability is unverified; no compliance certification. " +
                 ("Expected result scope is complete." if coverage["result_scope_complete"] else
                  "Evaluation is incomplete: engine failure, missing completion or unresolved rule results."),
        tags=["import:container-scap", "coverage:unverified"],
        collection_provenance={"producer": "container_scap_import", "observation_kind": "coverage",
            "source_sha256": source_hash, **observation, "provenance": manifest["provenance"], **coverage}))
    receipt = {"scan_id": scan_id, "import_id": import_id, "source": SOURCE, "source_sha256": source_hash,
               "source_id": manifest["source_id"], "test_result_id": manifest["test_result_id"],
               "targets": [tid], "imported_count": len(rows), "coverage_finding_count": 1,
               "findings_count": len(findings), **coverage}
    meta = {**identity, "import_id": import_id, "requested_by": actor, "authorization_scopes": scopes,
            "receipt": receipt}
    store = ctx.store
    guard()
    # Share the passive scanner import lock with Nessus. Public store publication also acquires
    # observation/review lifecycle locks, for both JSON and SQLite.
    with file_lock(store.ingest_dir / "scanner-import.lock"):
        guard()
        staged = store.read_json(store.scans_dir / scan_id / "findings.json")
        existing = store.load_scan_run(scan_id)
        if staged is not None:
            old = staged.get("meta", {})
            if (old.get("requested_by") != actor or old.get("authorization_scopes") != scopes
                    or old.get("import_id") != import_id):
                raise PermissionError("SCAP import belongs to a different account or target generation")
        if existing is not None:
            if staged is None or existing.get("requested_by") != actor:
                raise PermissionError("SCAP import ownership is unavailable")
            check_record(ctx, existing, "import")
            guard()
            ctx.audit.append("ingest.scap.repeat", actor, receipt, subject=scan_id)
            return {**staged["meta"]["receipt"], "repeated": True}
        now = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        findings[-1].collected_at = now
        run = ScanRun(id=scan_id, targets=[tid], modules=["container_scap_import"],
            rule_filter=sorted(rows), trigger="scanner_import", requested_by=actor,
            status="done" if coverage["result_scope_complete"] else "error", started_at=now, finished_at=now,
            findings_count=len(findings), summary={**summarize(findings), "container_scap": coverage},
            coverage_incomplete=True, authorization_scopes=scopes,
            results={tid: TargetScanResult(target_id=tid,
                status="done" if coverage["result_scope_complete"] else "error", started_at=now, finished_at=now,
                findings=len(findings), open=sum(f.is_open for f in findings), coverage=coverage,
                errors=[] if coverage["result_scope_complete"] else ["Container evaluation is incomplete"])})
        guard()
        store.save_findings(scan_id, findings, meta=meta)
        guard()
        ctx.audit.append("ingest.scap.publish", actor, receipt, subject=scan_id)
        guard()
        store.save_scan_run(run.to_dict())
        ctx.audit.append("ingest.scap", actor, receipt, subject=scan_id)
    return {**receipt, "repeated": False}
