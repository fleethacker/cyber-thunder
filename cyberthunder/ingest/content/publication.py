"""Immutable content generations. The index replacement is the only activation point.

Local process-crash recovery, not protection against whole-state restore or power loss.
All mutations run under ContentService's cross-process publication lock.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import re
from pathlib import Path

from cyberthunder.findings.schema import utcnow
from cyberthunder.ingest.content import signatures as sig

_reading = ContextVar("content_generation_read", default=None)


@contextmanager
def read_scope(store):
    doc = index(store)
    token = _reading.set((store, doc))
    try:
        yield doc
    finally:
        _reading.reset(token)


FORMAT = 2
HEX = re.compile(r"[a-f0-9]{64}")


class PublicationError(ValueError):
    pass


class PublicationReviewRequired(PublicationError):
    def __init__(self, review):
        super().__init__("Review this content publication in Import/transfer before submitting again")
        self.review = review


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def checkpoint(phase):
    """Fault-injection seam; no runtime configuration or external callback."""


def validate_intent(value):
    if value is None:
        return None
    fields = {"mode", "expected_generation", "review_sha256", "candidate_sha256", "request_id", "reason"}
    if not isinstance(value, dict) or set(value) != fields:
        raise PublicationError("Invalid publication intent fields")
    if value["mode"] not in {"legacy_baseline", "downgrade"}:
        raise PublicationError("Invalid publication intent mode")
    if any(not isinstance(value[k], str) or not HEX.fullmatch(value[k])
           for k in ("expected_generation", "review_sha256", "candidate_sha256")):
        raise PublicationError("Invalid publication intent binding")
    if not isinstance(value["request_id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,80}", value["request_id"]):
        raise PublicationError("Invalid publication request identifier")
    reason = value["reason"]
    if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 512 or any(ord(c) < 32 for c in reason):
        raise PublicationError("A separate publication reason is required")
    return dict(value, reason=reason.strip())


def index(store):
    pinned = _reading.get()
    if pinned is not None and pinned[0] is store:
        return pinned[1]
    path = store.root / "content/index.json"
    guard = store.files.get("content/publication.guard.json")
    doc = store.read_json(path)
    if guard and (guard.get("backend") != store.backend_name or not doc or doc.get("publication_format") != FORMAT):
        raise PublicationError("Content ledger missing or backend changed; controlled recovery is required")
    if doc is None:
        return {}
    if not isinstance(doc, dict):
        raise PublicationError("Invalid content ledger")
    if "publication_format" in doc:
        if (doc["publication_format"] != FORMAT or not isinstance(doc.get("generation"), str)
                or not HEX.fullmatch(doc["generation"]) or any(not isinstance(doc.get(k), dict)
                for k in ("publications", "active", "floors", "requests", "files"))):
            raise PublicationError("Invalid content generation; no legacy fallback is allowed")
        if doc["publications"] and doc["generation"] not in doc["publications"]:
            raise PublicationError("Missing current publication")
        expected_floors = {}
        for gid, publication in doc["publications"].items():
            if not isinstance(publication, dict) or publication.get("record", {}).get("generation") != gid:
                raise PublicationError("Invalid publication history")
            if doc["files"].get(gid) != publication["record"]:
                raise PublicationError("Publication record differs from committed history")
            if publication.get("trusted") and publication.get("activated"):
                for item in publication["lineages"]:
                    if item["release"]:
                        previous = expected_floors.get(item["key"])
                        if not previous or item["release"] > previous["release"]:
                            expected_floors[item["key"]] = {**item, "sha256": publication["record"]["sha256"]}
        if expected_floors != doc["floors"]:
            raise PublicationError("Content release floor is inconsistent; recovery is required")
        # Validate the active generation's references, never substitute older bytes.
        for key, generation in doc["active"].items():
            publication = doc["publications"].get(generation)
            if not isinstance(publication, dict):
                raise PublicationError("Missing active publication")
            if not publication.get("activated") or key not in {item["key"] for item in publication["lineages"]}:
                raise PublicationError("Invalid active lineage reference")
            verify_artifacts(store, publication)
    return doc


def verify_artifacts(store, publication):
    if not isinstance(publication.get("artifacts"), list) or not publication["artifacts"]:
        raise PublicationError("Missing publication artifacts")
    for item in publication["artifacts"]:
        relative = item.get("path", "")
        if not isinstance(relative, str) or not relative.startswith("content/") or any(
                part in {"", ".", ".."} for part in relative.split("/")) or "\\" in relative or ":" in relative:
            raise PublicationError("Invalid publication artifact path")
        try:
            data, size = sig.copy_checked(store.root / relative, maximum=sig.MAX_FILE_BYTES)
        except (OSError, ValueError):
            raise PublicationError("Committed content is unavailable; recovery is required") from None
        if size != item["bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise PublicationError("Committed content changed; recovery is required")


def records(store, doc=None):
    doc = index(store) if doc is None else doc
    out = []
    active = set(doc.get("active", {}).values())
    for rec in (doc.get("files") or {}).values():
        row = copy.deepcopy(rec)
        generation = row.get("generation")
        row["active"] = bool(generation and generation in active)
        if not generation or generation not in doc.get("publications", {}):
            row["authenticity"] = {"status": "legacy_unverified", "operator_attested": False, "disa_signature": False}
            row["commit_status"] = "legacy_history"
        out.append(row)
    return out


def legacy_state(store, doc):
    # Bind legacy bytes as well as metadata; filenames and saved trust labels do not grant authority.
    paths = list((store.ingest_dir / "catalog").glob("*.xml"))
    for rec in (doc.get("files") or {}).values():
        if rec.get("generation") not in doc.get("publications", {}):
            name = rec.get("disk_name") or rec.get("filename")
            if not isinstance(name, str) or Path(name).name != name or "\\" in name:
                raise PublicationError("Unsafe legacy content reference")
            paths.append(store.root / "content/files" / name)
    if not doc.get("publication_format"):
        files = store.root / "content/files"
        if files.exists() and any(path not in paths for path in files.iterdir()):
            raise PublicationError("Unindexed legacy content requires controlled recovery; it is not an empty node")
    held = []
    for path in sorted(set(paths)):
        try:
            raw, size = sig.copy_checked(path, maximum=sig.MAX_FILE_BYTES)
        except (OSError, ValueError):
            raise PublicationError("Legacy content is unreadable; baseline intent cannot repair corruption") from None
        sha = hashlib.sha256(raw).hexdigest()
        for rec in (doc.get("files") or {}).values():
            if rec.get("generation") not in doc.get("publications", {}) and path.name == (rec.get("disk_name") or rec.get("filename")):
                if rec.get("sha256") and rec["sha256"] != sha:
                    raise PublicationError("Legacy content hash mismatch; baseline intent cannot repair corruption")
        item = {"path": path.relative_to(store.root).as_posix(), "sha256": sha, "bytes": size}
        if path.parent == store.ingest_dir / "catalog":
            from .uploads import _xml, _benchmark
            try:
                metadata = _benchmark(_xml(raw))
            except ValueError:
                raise PublicationError("Legacy catalog is invalid; baseline intent cannot repair corruption") from None
            item.update(id=metadata["benchmark_id"], release=metadata["catalog_version"])
        held.append(item)
    return held


def generation(store, doc=None):
    doc = index(store) if doc is None else doc
    return doc.get("generation") or digest({"legacy": doc, "artifacts": legacy_state(store, doc)})


def inspect(path, entry, *, development=False, catalog_import=False):
    from . import uploads, fetch
    if entry.kind not in {"manual_stig", "srg", "scap_benchmark"}:
        return {"kind": entry.kind, "benchmarks": [], "member": None}, []
    try:
        description = uploads._validate(path, entry.filename.lower())
    except uploads.ContentUploadError:
        # Development SCAP documents may contain only structural metadata.
        # They remain untrusted reference bytes, never a verified active release.
        if not development or entry.kind != "scap_benchmark":
            raise
        fetch.check_file(path, entry.kind, filename=entry.filename)
        return {"kind": entry.kind, "benchmarks": [], "member": None}, []
    if catalog_import and description["kind"] == "scap_benchmark" and entry.kind == "manual_stig":
        # The direct catalog-diff entrypoint accepts a validated single XCCDF Benchmark,
        # including automated checks. A datastream collection is not a catalog.
        from cyberthunder.ingest.delta import read_benchmark_xml
        root = uploads._xml(read_benchmark_xml(path))
        if uploads._local(root) == "Benchmark" and len(description["benchmarks"]) == 1:
            description = dict(description, kind="manual_stig")
    if description["kind"] != entry.kind:
        raise PublicationError("Declared content kind does not match its validated contents")
    if len(description["benchmarks"]) > 16:
        raise PublicationError("Too many benchmark lineages in one publication")
    lineages = []
    seen = set()
    for benchmark in description["benchmarks"]:
        bid = benchmark["benchmark_id"]
        if bid in seen:
            raise PublicationError("Duplicate benchmark identity")
        seen.add(bid)
        version = benchmark["catalog_version"]
        scheme = "disa"
        if version is None and re.fullmatch(r"[0-9]{1,6}(?:\.[0-9]{1,6}){2}", benchmark.get("version") or ""):
            version = [int(v) for v in benchmark["version"].split(".")]
            scheme = "numeric-triple"
        for name in (entry.filename, description.get("member") or ""):
            match = re.search(r"(?:^|[_-])V([0-9]+)R([0-9]+)(?=[_.-]|$)", name, re.I)
            if match and (scheme != "disa" or version != [int(match[1]), int(match[2])]):
                raise PublicationError("Filename release does not match validated content")
        if entry.version is not None and list(entry.version) != version:
            raise PublicationError("Declared release does not match validated content")
        lineages.append({"id": bid, "kind": entry.kind, "scheme": scheme, "release": version,
                         "key": digest(["catalog" if entry.kind in {"manual_stig", "srg"} else entry.kind, bid])})
    return description, lineages


def human(ctx, actor):
    from cyberthunder.control.principal import require_current
    principal = require_current("import", actor)
    if not principal.verified or principal.kind != "human":
        raise PermissionError("Publication intent requires a verified human")
    ctx.authorize("import", actor=actor)
    ctx.authorize("admin", actor=actor)
    return dict(principal.evidence(), policy_sha256=ctx.access._load()[1])


def write_artifact(store, path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        old, _ = sig.copy_checked(path, maximum=sig.MAX_FILE_BYTES)
        if old != data:
            raise PublicationError("Immutable content path already holds different bytes")
    else:
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            import os
            os.fsync(stream.fileno())
    return {"path": path.relative_to(store.root).as_posix(), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def result(doc, publication, *, status=None):
    rec = copy.deepcopy(publication["record"])
    rec["active"] = rec["generation"] in set(doc["active"].values())
    rec["commit_status"] = status or publication.get("commit_status", "committed_with_bookkeeping_pending")
    return rec


def publish(service, path, entry, *, source, actor, sha256, etag, size, authenticity,
            intent=None, upload=None, old=None, method=None, job_id=None, catalog_import=False):
    """Called with stable authorized bytes under the common publication lock."""
    from . import fetch
    from cyberthunder.control.principal import current_principal
    if _reading.get() is not None:
        raise PublicationError("Publication cannot write from a pinned reader")
    intent = validate_intent(intent)
    if intent and source == "pulled":
        raise PublicationError("Exceptional activation requires Import/transfer; pulls cannot consent")
    state = service.store.state
    doc = index(state)
    legacy = legacy_state(state, doc)
    parent = generation(state, doc)
    principal = current_principal()
    identity = principal.evidence() if principal else None
    owner = [identity.get("iss"), identity.get("sub")] if identity else None
    if intent:
        identity = human(service.ctx, actor)
        owner = [identity["iss"], identity["sub"]]
        previous = doc.get("requests", {}).get(intent["request_id"])
        if previous:
            if previous["intent"] != digest(intent) or previous["owner"] != owner or previous["candidate"] != sha256:
                raise PublicationError("Publication request identifier was already consumed")
            publication = doc["publications"][previous["generation"]]
            verify_artifacts(state, publication)
            return result(doc, publication)
    development = authenticity["status"] == "unsigned_dev"
    description, lineages = inspect(path, entry, development=development, catalog_import=catalog_import)
    trusted = not development
    known = all(item["release"] is not None for item in lineages) and bool(lineages)
    floors = doc.get("floors", {})
    current = [doc.get("publications", {}).get(doc.get("active", {}).get(item["key"]), {}) for item in lineages]
    # Exact active bytes are a no-op only within the same assurance class.
    if current and all(p.get("record", {}).get("sha256") == sha256 and
            p.get("trusted") == trusted for p in current):
        if intent:
            raise PublicationError("This content is already active; no exceptional intent is applicable")
        existing = dict(result(doc, current[0]), already_held=True)
        try:
            service.audit.append("content.import", actor, {"sha256": sha256, "identical": True}, subject=entry.filename)
        except Exception:
            existing["commit_status"] = "committed_with_bookkeeping_pending"
        return existing
    for previous in doc.get("publications", {}).values():
        if not previous.get("trusted") or not previous.get("activated"):
            continue
        for prior in previous["lineages"]:
            for item in lineages:
                if (prior["key"] == item["key"] and prior["release"] == item["release"]
                        and previous["record"]["sha256"] != sha256):
                    raise PublicationError("Different bytes claim a previously accepted release")
    keys = {item["key"] for item in lineages}
    if any(any(item["key"] not in keys for item in publication.get("lineages", [])) for publication in current):
        raise PublicationError("A multi-benchmark publication must be replaced as a complete set")
    mode = None
    for item, active in zip(lineages, current):
        floor = floors.get(item["key"])
        if floor:
            if not trusted:
                raise PublicationError("Development content cannot replace an authorized release")
            if not item["release"] or item["scheme"] != floor["scheme"]:
                raise PublicationError("Content release cannot be compared to the accepted floor")
            if item["release"] == floor["release"] and sha256 != floor["sha256"]:
                raise PublicationError("Different bytes claim the same accepted release")
            if item["release"] < floor["release"]:
                mode = "downgrade"
        if trusted and active and not active.get("trusted"):
            mode = mode or "legacy_baseline"
    # Existing ambiguous legacy state cannot be silently certified by the new format.
    if trusted and legacy and any(doc.get("legacy_baselines", {}).get(item["key"]) != digest(legacy) for item in lineages):
        mode = mode or "legacy_baseline"
    if mode or intent:
        identity = human(service.ctx, actor)
        if not known:
            raise PublicationError("A baseline or downgrade requires unambiguous validated releases")
        review = {"code": "content_publication_review", "mode": mode or intent["mode"],
                  "expected_generation": parent, "candidate_sha256": sha256, "candidate_bytes": size,
                  "candidate": [{k: v for k, v in item.items() if k != "key"} for item in lineages],
                  "current": [{"id": item["id"], "release": next((row["release"] for row in active.get("lineages", []) if row["key"] == item["key"]), None),
                               "sha256": active.get("record", {}).get("sha256"),
                               "floor": floors.get(item["key"], {}).get("release")}
                              for item, active in zip(lineages, current)],
                  "legacy_sha256": digest(legacy), "session_sha256": digest(identity)}
        for row in review["current"]:
            if row["sha256"] is None:
                previous = next((item for item in legacy if item.get("id") == row["id"]), None)
                if previous:
                    row.update(release=previous["release"], sha256=previous["sha256"])
        review["review_sha256"] = digest(review)
        if source == "pulled":
            raise PublicationError("Exceptional activation requires explicit Import/transfer review; pulls cannot consent")
        if not intent or any(intent[k] != review[k] for k in
                ("mode", "expected_generation", "candidate_sha256", "review_sha256")) or not mode:
            raise PublicationReviewRequired(review)
        human(service.ctx, actor)
    # Never let unknown source metadata select a verified active release.
    active_candidate = known
    if not doc.get("publication_format"):
        doc = {"publication_format": FORMAT, "generation": parent, "files": doc.get("files", {}),
               "publications": {}, "active": {}, "floors": {}, "requests": {}, "legacy_baselines": {}}
        # Establish a recoverable empty managed ledger before staging any artifacts.
        state.write_json(service.store.index_path, doc)
    state.files.put("content/publication.guard.json", {"backend": state.backend_name, "format": FORMAT})
    generation_id = digest([parent, sha256, state.new_id("publication-")])
    directory = service.store.root / "generations" / generation_id
    directory.mkdir(parents=True)
    artifacts = []
    source_dest = service.store.files_dir / (sha256 + Path(entry.filename).suffix.lower())
    artifacts.append(write_artifact(state, source_dest, path.read_bytes()))
    ingest = {}
    delta = None
    if entry.kind in {"manual_stig", "srg"}:
        prior = next((p.get("delta", {}).get("catalog_path") for p in current if p.get("delta")), None)
        # Legacy bytes can be compared, but never used as a release floor.
        if prior is None:
            from cyberthunder.ingest.delta import safe_name
            candidate = state.ingest_dir / "catalog" / (safe_name(lineages[0]["id"]) + ".xml")
            prior = str(candidate) if candidate.exists() else old
        delta, xml = service.ingest._prepare_stig(path, entry.filename, previous=prior, actor=actor,
                                                 method=method, receipt_source=source)
        catalog = directory / "catalog.xml"
        artifacts.append(write_artifact(state, catalog, xml))
        delta["catalog_path"] = str(catalog)
        ingest = {"delta_id": delta["id"], "catalog_path": str(catalog), "report": delta,
                  "delta": {k: delta.get(k) for k in ("id", "benchmark_id", "old_release", "new_release", "counts", "full_import")}}
        ingest["delta"].update(filename=entry.filename, rescan_rules=len(delta["rescan_rule_ids"]))
    elif entry.kind == "scap_benchmark":
        extracted = service._extract_datastream(path, entry)
        dest = directory / "datastream.xml"
        artifacts.append(write_artifact(state, dest, extracted.read_bytes()))
        ingest["datastream_path"] = str(dest)
    now = utcnow()
    rec = {"filename": entry.filename, "disk_name": source_dest.name, "product_key": entry.product_key,
           "kind": entry.kind, "version": list(entry.version) if entry.version else None,
           "version_label": entry.version_label, "upload_date": entry.upload_date, "sha256": sha256,
           "etag": etag, "bytes": size, "url": entry.url, "fetched_at": now, "fetched_by": actor,
           "source": source, "ingest": ingest, "authenticity": authenticity, "title": entry.title,
           "benchmark_id": None, "benchmark_release": None,
           "generation": generation_id, "active": active_candidate, "job_id": job_id,
           "commit_status": "committed_with_bookkeeping_pending"}
    if upload:
        benchmark = description["benchmarks"][0] if len(description["benchmarks"]) == 1 else {}
        rec.update(fetched_at=None, fetched_by=None, benchmark_id=benchmark.get("benchmark_id"),
                   benchmark_release=benchmark.get("release_info") or benchmark.get("version"))
        ingest["upload"] = dict(description, filename=upload, imported_at=now, imported_by=actor,
                                authenticity_verified=False)
    checkpoint("prepared")
    snapshot, snapshot_size = sig.copy_checked(path, maximum=sig.MAX_FILE_BYTES)
    if (hashlib.sha256(snapshot).hexdigest(), snapshot_size) != (sha256, size) or (
            artifacts[0]["sha256"], artifacts[0]["bytes"]) != (sha256, size):
        raise sig.AuthenticityError("Prepared source differs from authorized content")
    sig.acceptance(service.ctx, actor, sha256, size)
    service.ctx.killswitch.guard("content.import", actor)
    if intent:
        if human(service.ctx, actor) != identity:
            raise PermissionError("Publication identity changed")
    event = service.audit.append("content.publication_intent", actor,
        {"generation": generation_id, "parent": parent, "sha256": sha256,
         "lineages": lineages, "intent": intent, "active": active_candidate})
    checkpoint("audited")
    sig.acceptance(service.ctx, actor, sha256, size)
    service.ctx.killswitch.guard("content.import", actor)
    if intent and human(service.ctx, actor) != identity:
        raise PermissionError("Publication identity changed")
    publication = {"record": rec, "lineages": lineages, "artifacts": artifacts, "delta": delta,
                   "trusted": trusted, "activated": active_candidate, "audit_intent": {"seq": event["seq"], "hash": event["hash"]},
                   "commit_status": "committed_with_bookkeeping_pending"}
    verify_artifacts(state, publication)
    new = copy.deepcopy(doc)
    new["generation"] = generation_id
    new["publications"][generation_id] = publication
    new["files"][generation_id] = rec
    if active_candidate:
        for item in lineages:
            new["active"][item["key"]] = generation_id
            floor = floors.get(item["key"])
            if trusted and item["release"] and (not floor or item["release"] > floor["release"]):
                new["floors"][item["key"]] = {**item, "sha256": sha256}
    if intent:
        new["requests"][intent["request_id"]] = {"owner": owner, "intent": digest(intent),
                                              "candidate": sha256, "generation": generation_id}
        if intent["mode"] == "legacy_baseline":
            for item in lineages:
                new["legacy_baselines"][item["key"]] = digest(legacy)
    checkpoint("before_commit")
    try:
        state.write_json(service.store.index_path, new)
    except Exception:
        # A backend may have committed before a late error; resolve, never retry activation.
        try:
            actual = index(state)
        except Exception:
            raise PublicationError("Publication outcome is unknown; reconcile the ledger before retrying") from None
        if generation_id not in actual.get("publications", {}):
            raise
        return result(actual, actual["publications"][generation_id])
    try:
        checkpoint("committed")
        service.audit.append("content.publication_committed", actor, {"generation": generation_id, "sha256": sha256})
        if delta:
            service.audit.append("ingest.stig", actor, {"delta_id": delta["id"], "benchmark_id": delta["benchmark_id"],
                "old_release": delta["old_release"], "new_release": delta["new_release"], "counts": delta["counts"],
                "filename": entry.filename, "full_bytes": delta["sizes"]["full_bytes"],
                "compressed_bytes": delta["sizes"]["compressed_bytes"], "method": delta["sizes"]["method"],
                "authenticity": delta["authenticity"], "generation": generation_id}, subject=delta["id"])
        if source in {"imported", "uploaded"}:
            service.audit.append("content.import", actor, {"sha256": sha256, "bytes": size,
                "generation": generation_id, "identical": False}, subject=entry.filename)
        from .library import ContentLibrary
        ContentLibrary(service).record_transfer(source, now)
        publication["commit_status"] = "committed"
        rec["commit_status"] = "committed"
        new["publications"][generation_id] = publication
        new["files"][generation_id] = rec
        state.write_json(service.store.index_path, new)
    except Exception:
        return result(new, publication, status="committed_with_bookkeeping_pending")
    return result(new, publication)
