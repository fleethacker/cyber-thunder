"""Read-only catalog annotations for existing native checks; never executable coverage."""
from __future__ import annotations

import copy
import hashlib
import json
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
                or not 1 <= len(binding["benchmark_id"]) <= 180):
            raise ValueError("native catalog binding requires an exact product and benchmark id; pins are unsupported")
    return copy.deepcopy(value)


def _text(element):
    return " ".join("".join(element.itertext()).split())


def _children(element, name):
    return [child for child in element if uploads._local(child) == name]


def _catalog(store, doc, binding):
    """Use only the active manual-catalog lineage in the pinned authoritative ledger."""
    key = pub.digest(["catalog", binding["benchmark_id"]])
    gid = doc.get("active", {}).get(key)
    if gid is None:
        return {"status": "no_active_catalog", "binding": binding}, {}
    publication = doc["publications"][gid]
    record = publication["record"]
    lineage = next(item for item in publication["lineages"] if item["key"] == key)
    origin = {"binding": binding, "publication_generation": gid,
              "source_sha256": record["sha256"], "source_bytes": record["bytes"],
              "source": record.get("source"), "filename": record["filename"],
              "authenticity": copy.deepcopy(record["authenticity"]),
              "commit_status": publication["commit_status"],
              "benchmark_id": lineage["id"], "release_scheme": lineage["scheme"],
              "release": list(lineage["release"])}
    if record["product_key"] != binding["product_key"]:
        raise pub.PublicationError("Active native catalog product differs from the explicit binding")
    if not publication["trusted"]:
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
    data, size = signatures.copy_checked(store.root / artifact["path"], maximum=uploads.MAX_EXPANDED_BYTES)
    sha = hashlib.sha256(data).hexdigest()
    if size != artifact["bytes"] or sha != artifact["sha256"]:
        raise pub.PublicationError("Active native catalog changed during metadata read")
    root = uploads._xml(data)
    if uploads._local(root) != "Benchmark" or root.get("id") != binding["benchmark_id"]:
        raise pub.PublicationError("Active native catalog benchmark identity differs")
    benchmark = uploads._benchmark(root)
    origin.update(catalog_sha256=sha, catalog_bytes=size, benchmark_title=benchmark["title"],
                  benchmark_version=benchmark["version"], benchmark_release=benchmark["release_info"],
                  catalog_rule_count=benchmark["rules"])
    rules = {}
    parents = {child: parent for parent in root.iter() for child in parent}
    for rule in (element for element in root.iter() if uploads._local(element) == "Rule"):
        # Match the explicit Rule/version only. References and title similarity are
        # not an alias registry; multiple versions or duplicate STIG IDs are ambiguous.
        versions = [_text(element) for element in _children(rule, "version")]
        group = parents.get(rule)
        while group is not None and uploads._local(group) != "Group":
            group = parents.get(group)
        statuses = [_text(element).lower() for element in _children(root, "status") + _children(rule, "status")]
        titles = _children(rule, "title")
        item = {"rule_id": rule.get("id"), "stig_id": versions[0] if len(versions) == 1 else None,
                "group_id": group.get("id") if group is not None else None,
                "title": _text(titles[0]) if len(titles) == 1 else None,
                "severity": Severity.parse(rule.get("severity")).value,
                "cci": sorted({cci for element in _children(rule, "ident") + _children(rule, "reference")
                               for cci in RE_CCI.findall(_text(element))}),
                "withdrawn": any(status in {"deprecated", "withdrawn", "obsolete"} for status in statuses),
                "ambiguous": len(versions) != 1 or len(titles) != 1}
        for version in set(versions):
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
            # This validates legacy holdings too; absent activation is not a license
            # to hide corrupt or unindexed legacy artifacts behind a bundled label.
            generation = pub.generation(ctx.store, doc)
            for family, binding in bindings.items():
                catalogs[family] = _catalog(ctx.store, doc, binding)
        authorize(ctx, "read", actor=actor)
    bundles = {}
    counts = {}
    pending = []
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
            data = path.read_bytes()
            bundled = json.loads(data)
            entries = bundled["rules"] if isinstance(bundled, dict) else {row["stig_id"]: row for row in bundled}
            bundles[path] = (hashlib.sha256(data).hexdigest(), entries)
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
        counts[status] = counts.get(status, 0) + 1
        pending.append((finding, metadata))
    if bindings:
        authorize(ctx, "read", actor=actor)
    for finding, metadata in pending:
        finding.catalog_rule_metadata = metadata
    collected.raw[KEY] = {"version": 1, "snapshot_generation": generation, "counts": counts,
                          "assessment": "not_assessed", "coverage_added": 0,
                          "catalogs": {family: origin for family, (origin, _) in catalogs.items()}}
