"""Read-only catalog annotations for existing native checks; never executable coverage."""
from __future__ import annotations

import copy
import hashlib
import json
import re
import unicodedata
from pathlib import Path

from cyberthunder.control.principal import authorize
from cyberthunder.findings.schema import RE_CCI, Severity
from cyberthunder.ingest.content import publication as pub, signatures, uploads

# Explicit product declarations only. These are the bundled check families, not aliases
# for related operating systems, scanner benchmarks, or similarly titled publications.
FAMILIES = {
    "linux_rhel9": ("linux", "native", "RHEL-09-", "RHEL_9", "linux/stig_rules.json"),
    "windows11": ("windows", "windows-stig", "WN11-", "MS_Windows_11", "windows/w11_catalog.json"),
    "cisco_ndm": ("cisco_ios", "cisco_ios", "CISC-ND-", "Cisco_IOS-XE_Switch", "cisco/stig_rules.json"),
    "cisco_l2s": ("cisco_ios", "cisco_ios", "CISC-L2-", "Cisco_IOS-XE_Switch", "cisco/stig_rules.json"),
    "cisco_rtr": ("cisco_ios", "cisco_ios", "CISC-RT-", "Cisco_IOS-XE_Router", "cisco/stig_rules.json"),
    "kubernetes": ("kubernetes", "kubernetes", "CNTR-K8-", "Kubernetes", "kubernetes/stig_rules.json"),
}
KEY = "catalog_rule_metadata"
MAX_BUNDLE_BYTES = 2 * 1024 * 1024
MAX_XML_BYTES = 32 * 1024 * 1024
MAX_RULES = 10000
MAX_TEXT = 4096
MAX_RECORD_BYTES = 16 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,255}")
_TRUSTED = {"operator_attested", "human_override", "trusted_https_source"}
_STATUSES = _TRUSTED | {"unsigned", "unsigned_dev", "unknown_signer", "legacy_unverified"}
_XHTML = "http://www.w3.org/1999/xhtml"
_INLINE = {"p", "span", "b", "i", "em", "strong", "br", "code", "pre", "ul", "ol", "li", "a", "sub", "sup"}


def _label(value):
    if value is None:
        return None
    if (not isinstance(value, str) or len(value) > MAX_TEXT
            or any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in value)):
        raise pub.PublicationError("Native catalog metadata text exceeds the safe limit")
    return value


def _identifier(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise pub.PublicationError("Native catalog metadata has an unsafe identifier")
    return _label(value)


def _record_size(value):
    size = len(json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii"))
    if size > MAX_RECORD_BYTES:
        raise pub.PublicationError("Native catalog metadata record exceeds the size limit")
    return size


def _authenticity(value):
    # Receipts may contain private override reasons, actors, URLs and local paths.
    # Export only assurance facts and digests; the authoritative receipt stays local.
    status = value.get("status")
    result = {"status": status if status in _STATUSES else "unknown",
              "operator_attested": value.get("operator_attested") is True,
              "disa_signature": value.get("disa_signature") is True}
    for key in ("document_sha256", "key_sha256"):
        if isinstance(value.get(key), str) and pub.HEX.fullmatch(value[key]):
            result[key] = value[key]
    if value.get("unverified_status") in {"unsigned", "unknown_signer"}:
        result["unverified_status"] = value["unverified_status"]
    return result


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise pub.PublicationError("Duplicate bundled metadata key")
        result[key] = value
    return result


def _bundle(path):
    try:
        data, _ = signatures.copy_checked(path, maximum=MAX_BUNDLE_BYTES)
        bundled = json.loads(data, object_pairs_hook=_object)
        def bound(value, depth=0):
            if depth > 32:
                raise pub.PublicationError("Bundled metadata exceeds the depth limit")
            if isinstance(value, (dict, list)):
                if len(value) > MAX_RULES:
                    raise pub.PublicationError("Bundled metadata exceeds the record limit")
                for child in value.values() if isinstance(value, dict) else value:
                    bound(child, depth + 1)
        bound(bundled)
        if isinstance(bundled, dict):
            entries = bundled["rules"]
            if not isinstance(entries, dict):
                raise ValueError
        else:
            entries = {}
            for row in bundled:
                sid = row["stig_id"]
                if sid in entries:
                    raise pub.PublicationError("Duplicate bundled STIG identifier")
                entries[sid] = row
        for sid, row in entries.items():
            _identifier(sid)
            if not isinstance(row, dict):
                raise ValueError
            _record_size(row)
        return hashlib.sha256(data).hexdigest(), entries
    except pub.PublicationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise pub.PublicationError("Bundled native metadata is unavailable or invalid") from None


def _bindings(target):
    value = (target.options or {}).get("native_catalog_bindings", {})
    if not isinstance(value, dict) or len(value) > len(FAMILIES):
        raise ValueError("native_catalog_bindings must be a bounded family mapping")
    for family, binding in value.items():
        if family not in FAMILIES or FAMILIES[family][0] != target.asset_type:
            raise ValueError("native catalog family does not match this adapter")
        if (not isinstance(binding, dict) or set(binding) != {"product_key", "benchmark_id"}
                or binding["product_key"] != FAMILIES[family][3]
                or not isinstance(binding["benchmark_id"], str)
                or not 1 <= len(binding["benchmark_id"]) <= 180
                or not _ID.fullmatch(binding["benchmark_id"])):
            raise ValueError("native catalog binding requires an exact product and benchmark id; pins are unsupported")
    return copy.deepcopy(value)


def _text(element):
    parts = []
    size = 0
    for part in element.itertext():
        size += len(part)
        if size > MAX_TEXT:
            raise pub.PublicationError("Native catalog metadata text exceeds the safe limit")
        parts.append(part)
    return _label(" ".join("".join(parts).split()))


def _children(element, name):
    return [child for child in element if uploads._local(child) == name and uploads._ns(child) == uploads._ns(element)]


def _title(element):
    titles = _children(element, "title")
    if (len(titles) != 1 or len([child for child in element if uploads._local(child) == "title"]) != 1
            or any(uploads._ns(child) != _XHTML or uploads._local(child) not in _INLINE
                   for child in titles[0].iter() if child is not titles[0])):
        return None
    return _text(titles[0]) or None


def _catalog(store, doc, binding):
    """Use only the active manual-catalog lineage in the pinned authoritative ledger."""
    key = pub.digest(["catalog", binding["benchmark_id"]])
    gid = doc.get("active", {}).get(key)
    if gid is None:
        return {"status": "no_active_catalog", "binding": binding}, {}
    publication = doc["publications"][gid]
    record = publication["record"]
    lineages = [item for item in publication["lineages"] if item["key"] == key]
    if len(lineages) != 1 or lineages[0]["id"] != binding["benchmark_id"]:
        raise pub.PublicationError("Active native catalog lineage identity differs")
    lineage = lineages[0]
    if lineage["scheme"] not in {"disa", "numeric-triple"}:
        raise pub.PublicationError("Active native catalog has an unknown release scheme")
    origin = {"binding": binding, "publication_generation": gid,
              "source_sha256": record["sha256"], "source_bytes": record["bytes"],
              "source": record.get("source") if record.get("source") in {"imported", "pulled", "uploaded"} else "unknown",
              "filename": uploads._name(record["filename"]),
              "authenticity": _authenticity(record["authenticity"]),
              "commit_status": (publication["commit_status"] if publication["commit_status"] in
                                {"committed", "committed_with_bookkeeping_pending"} else "unknown"),
              "benchmark_id": lineage["id"], "release_scheme": lineage["scheme"],
              "release": list(lineage["release"]) if lineage["release"] is not None else None}
    if record["product_key"] != binding["product_key"]:
        raise pub.PublicationError("Active native catalog product differs from the explicit binding")
    if publication["trusted"] is not True or origin["authenticity"]["status"] not in _TRUSTED:
        return dict(origin, status="untrusted_active_catalog"), {}
    report = publication.get("delta") or {}
    if lineage["kind"] not in {"manual_stig", "srg"} or report.get("benchmark_id") != binding["benchmark_id"]:
        raise pub.PublicationError("Active native catalog lineage has no matching catalog")
    # Locate the committed artifact, then hash the very bytes parsed. A pinned ledger
    # alone must not mask corruption after its initial artifact verification.
    artifacts = [item for item in publication["artifacts"]
                 if store.root / item["path"] == Path(report["catalog_path"])]
    if len(artifacts) != 1:
        raise pub.PublicationError("Active native catalog has no unique committed artifact")
    artifact = artifacts[0]
    try:
        data, size = signatures.copy_checked(store.root / artifact["path"], maximum=MAX_XML_BYTES)
    except (OSError, ValueError):
        raise pub.PublicationError("Active native catalog is unavailable or exceeds the size limit") from None
    sha = hashlib.sha256(data).hexdigest()
    if size != artifact["bytes"] or sha != artifact["sha256"]:
        raise pub.PublicationError("Active native catalog changed during metadata read")
    root = uploads._xml(data)
    if uploads._local(root) != "Benchmark" or root.get("id") != binding["benchmark_id"]:
        raise pub.PublicationError("Active native catalog benchmark identity differs")
    benchmark = uploads._benchmark(root)
    release = benchmark["catalog_version"]
    if lineage["scheme"] == "numeric-triple" and re.fullmatch(r"[0-9]{1,6}(?:\.[0-9]{1,6}){2}", benchmark["version"] or ""):
        release = [int(part) for part in benchmark["version"].split(".")]
    if lineage["scheme"] not in {"disa", "numeric-triple"} or release != lineage["release"] or release is None:
        raise pub.PublicationError("Active native catalog release differs from the committed lineage")
    if benchmark["rules"] > MAX_RULES:
        raise pub.PublicationError("Native catalog exceeds the rule limit")
    benchmark_title = _title(root)
    origin.update(catalog_sha256=sha, catalog_bytes=size, benchmark_title=benchmark_title,
                  benchmark_version=_label(benchmark["version"]), benchmark_release=_label(benchmark["release_info"]),
                  catalog_rule_count=benchmark["rules"])
    _record_size(origin)
    rules = {}
    parents = {child: parent for parent in root.iter() for child in parent}
    statuses = [_text(element).lower() for element in _children(root, "status")]
    for rule in (element for element in root.iter() if uploads._local(element) == "Rule"):
        if uploads._ns(rule) != uploads._ns(root):
            raise pub.PublicationError("Native catalog rule namespace differs from benchmark")
        # Match the explicit Rule/version only. References and title similarity are
        # not an alias registry; multiple versions or duplicate STIG IDs are ambiguous.
        versions = [_text(element) for element in _children(rule, "version") if not len(element)]
        group = parents.get(rule)
        while group is not None and uploads._local(group) != "Group":
            group = parents.get(group)
        rule_statuses = statuses + [_text(element).lower() for element in _children(rule, "status")]
        title = _title(rule)
        item = {"rule_id": _identifier(rule.get("id")), "stig_id": versions[0] if len(versions) == 1 else None,
                "group_id": _identifier(group.get("id")) if group is not None else None,
                "title": title,
                "severity": Severity.parse(rule.get("severity")).value,
                "cci": sorted({cci for element in _children(rule, "ident") + _children(rule, "reference")
                               for cci in RE_CCI.findall(_text(element))}),
                "withdrawn": any(status in {"deprecated", "withdrawn", "obsolete"} for status in rule_statuses),
                "ambiguous": len(versions) != 1 or len([c for c in rule if uploads._local(c) == "version"]) != 1
                             or not title or not benchmark_title}
        _record_size(item)
        for version in set(versions):
            _identifier(version)
            rules.setdefault(version, []).append(item)
    return dict(origin, status="active_catalog"), rules


def annotate_native_findings(ctx, target, collected, findings, *, actor):
    """Annotate fresh scan output without changing finding, approval or evidence identity.

    All statuses here describe metadata mapping. Even a match is not an assessment
    of the imported release: the native implementation still owns its original result.
    """
    if "check" not in collected.modules or target.asset_type not in {v[0] for v in FAMILIES.values()}:
        return
    bindings = _bindings(target)
    catalogs = {}
    generation = None
    if bindings:
        authorize(ctx, "read", actor=actor)
        with pub.read_scope(ctx.store) as doc:
            # An outer scope pins ledger identity, not continued artifact integrity.
            # Recheck every active source and derived artifact, including development
            # publications, without switching to a newer generation.
            for gid in set(doc.get("active", {}).values()):
                pub.verify_artifacts(ctx.store, doc["publications"][gid])
            # This validates legacy holdings too; absent activation is not a license
            # to hide corrupt or unindexed legacy artifacts behind a bundled label.
            generation = pub.generation(ctx.store, doc)
            for family, binding in bindings.items():
                catalogs[family] = _catalog(ctx.store, doc, binding)
        authorize(ctx, "read", actor=actor)
    bundles = {}
    counts = {}
    pending = []
    total = 0
    for finding in findings:
        family = next((name for name, (asset, source, prefix, _, _) in FAMILIES.items()
                       if target.asset_type == asset and finding.source == source
                       and (finding.rule_version or "").startswith(prefix)), None)
        if family is None:
            continue
        if finding.catalog_rule_metadata is not None:
            raise ValueError("Native catalog metadata is already attached; historical findings are immutable")
        path = Path(__file__).parent / "adapters" / FAMILIES[family][4]
        if path not in bundles:
            bundles[path] = _bundle(path)
        sha, entries = bundles[path]
        if finding.rule_version not in entries:
            continue
        origin, rules = catalogs.get(family, ({"status": "not_configured"}, {}))
        metadata = {"version": 1, "family": family, "assessment": "not_assessed",
                    "snapshot_generation": generation, "catalog": copy.deepcopy(origin),
                    "native": {"finding_id": finding.id, "source": finding.source, "rule_id": finding.rule_id,
                               "stig_id": finding.rule_version, "benchmark": finding.benchmark,
                               "benchmark_release": finding.benchmark_release, "status": finding.status.value},
                    "bundled": {"source": "bundled_extract", "sha256": sha,
                                "path": path.relative_to(Path(__file__).parent).as_posix()},
                    "metadata_source": "bundled_extract", "mapping_status": origin["status"]}
        if origin["status"] == "active_catalog":
            matches = rules.get(finding.rule_version, [])
            if not matches:
                metadata["mapping_status"] = "missing"
            elif len(matches) != 1 or matches[0]["ambiguous"]:
                metadata["mapping_status"] = "ambiguous"
            else:
                match = matches[0]
                metadata["rule"] = {key: value for key, value in match.items() if key not in {"withdrawn", "ambiguous"}}
                metadata["mapping_status"] = "withdrawn" if match["withdrawn"] else "matched"
                metadata["metadata_source"] = "active_catalog"
        status = metadata["mapping_status"]
        total += _record_size(metadata)
        if total > MAX_TOTAL_BYTES or len(pending) >= MAX_RULES:
            raise pub.PublicationError("Native catalog annotations exceed the total limit")
        counts[status] = counts.get(status, 0) + 1
        pending.append((finding, metadata))
    summary = {"version": 1, "snapshot_generation": generation, "counts": counts,
               "assessment": "not_assessed", "coverage_added": 0,
               "catalogs": {family: origin for family, (origin, _) in catalogs.items()}}
    if total + _record_size(summary) > MAX_TOTAL_BYTES:
        raise pub.PublicationError("Native catalog annotations exceed the total limit")
    if bindings:
        authorize(ctx, "read", actor=actor)
    for finding, metadata in pending:
        finding.catalog_rule_metadata = metadata
    collected.raw[KEY] = summary
