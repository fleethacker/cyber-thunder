"""Offline inventory of check and fix capabilities, never a compliance score.

Native catalogs are subsets. Only a supplied XCCDF document provides a denominator.
Rule identifiers are matched, not CCI citations: one CCI can describe many rules.
SCAP counts are preflight capabilities, not evidence that a host was evaluated.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
from types import CodeType
import xml.etree.ElementTree as ET

from cyberthunder.findings.schema import utcnow
from cyberthunder.remediation.library import FixEntry
from cyberthunder.report.render import ReportError, render
from cyberthunder.scap.datastream import Benchmark, Datastream, Rule, OVAL_SYSTEM, load

EXECUTABLE_KINDS = {
    "linux": {"script"}, "windows": {"powershell"}, "cisco_ios": {"config_snippet"},
    "kubernetes": {"manifest"}, "containers": {"script"},
}
LIMITATIONS = (
    "Capability inventory, not a compliance score or a record of checks run on a host. "
    "Finding every seeded item does not mean a whole benchmark is covered.",
    "Native and fix mappings use rule identifiers. Matching an identifier across releases does not "
    "prove the check or fix implements changed rule text. Review benchmark drift before use.",
    "SCAP eligible means the supplied content passes structural preflight. Windows uses the current "
    "OVAL probe support list; Linux requires external OpenSCAP. Platform applicability, profile "
    "selection, privileges and collection errors still determine what runs on a real target.",
    "Executable fixes are library entries with payloads and rollback declarations, not fixes proven "
    "safe on every host. Host-specific prerequisites and approval still apply. Generated scan-time "
    "fixes are excluded; hunt and patch entries appear only in the separate library inventory.",
)


@dataclass
class NativeCatalog:
    asset_type: str
    benchmark: str
    release: str
    catalog_entries: int
    rules: dict[str, set[str]]


def _keys(*values) -> set[str]:
    return {str(v) for v in values if v}


def _constants(value) -> set[str]:
    """Identifiers in active check functions, excluding comments and unused catalog rows."""
    if isinstance(value, str):
        return {value}
    if isinstance(value, CodeType):
        value = value.co_consts
    if isinstance(value, (tuple, list)):
        return set().union(*(_constants(v) for v in value)) if value else set()
    return set()


def native_catalogs(asset_types: set[str] | None = None) -> list[NativeCatalog]:
    selected = set(EXECUTABLE_KINDS) if asset_types is None else asset_types
    result = []
    if "linux" in selected:
        from cyberthunder.adapters.linux import checks as linux, rules as lr
        native = [r for r in linux.NATIVE if r.family in linux.FAMILY]
        for stig, title, release, size in (
            (True, lr.BENCHMARK, lr.RELEASE, len(lr.stig_rules())),
            (False, "Cyber Thunder Linux checks", "bundled", sum(not r.stig_id for r in native)),
        ):
            rows = {r.rule_id: _keys(r.rule_id, r.stig_id, r.ssg,
                                   lr.SSG_PREFIX + r.ssg if r.ssg else None)
                    for r in native if bool(r.stig_id) == stig}
            result.append(NativeCatalog("linux", title, release, size, rows))
    if "windows" in selected:
        from cyberthunder.adapters.windows import checks as win
        cat = win.catalog()
        for stig, title, release, size in (
            (True, cat["benchmark"], cat["release"], len(cat["rules"])),
            (False, "Cyber Thunder Windows checks", "bundled", sum(not c.stig_id for c in win.CHECKS)),
        ):
            rows = {c.stig_id or c.rule_id: _keys(c.stig_id, c.rule_id, c.fix_ref)
                    for c in win.CHECKS if bool(c.stig_id) == stig}
            result.append(NativeCatalog("windows", title, release, size, rows))
    if "cisco_ios" in selected:
        from cyberthunder.adapters.cisco import rules as cisco
        for family, (title, release) in cisco.FAMILY_BENCHMARK.items():
            rules = [r for r in cisco.load_rules() if r.family == family]
            result.append(NativeCatalog("cisco_ios", title, release, len(rules),
                                        {r.stig_id: _keys(r.stig_id, r.rule_id) for r in rules}))
    if "kubernetes" in selected:
        from cyberthunder.adapters.kubernetes import checks as kube
        referenced = set(kube.APISERVER_RULES)
        for fn in kube.ALL_CHECKS:
            referenced.update(_constants(fn.__code__))
        result.append(NativeCatalog("kubernetes", "Kubernetes STIG", "V2R4 (includes legacy checks)",
                                    len(kube.stig_rules()),
                                    {sid: {sid} for sid in kube.stig_rules() if sid in referenced}))
        for title, release, rules in (
            ("CIS Kubernetes Benchmark", "v1.8", kube.CIS_RULES.values()),
            ("Cyber Thunder Kubernetes checks", "bundled", kube.LOCAL_RULES.values()),
        ):
            rows = {r.base: {r.base} for r in rules}
            result.append(NativeCatalog("kubernetes", title, release, len(rows), rows))
    if "containers" in selected:
        from cyberthunder.adapters.containers import checks as containers
        for title in sorted({r.benchmark for r in containers.RULES.values()}):
            rows = {r.base: {r.base} for r in containers.RULES.values() if r.benchmark == title}
            result.append(NativeCatalog("containers", title, "bundled", len(rows), rows))
    return result


def executable(entry: FixEntry) -> bool:
    return (entry.kind in EXECUTABLE_KINDS.get(entry.asset_type, set())
            and bool(entry.payload.strip()) and entry.reversible and entry.rollback_kind != "manual")


def fix_counts(rules: dict[str, set[str]], entries: list[FixEntry]) -> dict:
    executed, runbooks = set(), set()
    for rid, keys in rules.items():
        matching = [e for e in entries if keys.intersection(e.applies_to)]
        if any(executable(e) for e in matching):
            executed.add(rid)
        elif any(e.kind == "runbook" for e in matching):
            runbooks.add(rid)
    return {"executable_fixes": len(executed), "runbook_only": len(runbooks),
            "executable_rule_ids": sorted(executed), "runbook_only_rule_ids": sorted(runbooks)}


def _family(benchmark: Benchmark) -> tuple[str, str | None, str | None]:
    bid = benchmark.id.removeprefix("xccdf_mil.disa.stig_benchmark_")
    version = benchmark.version or ""
    parts = re.fullmatch(r"0*(\d+)\.0*(\d+)", version)
    if parts:
        return bid, str(int(parts[1])), str(int(parts[2]))
    release = re.search(r"Release\s*:?\s*(\d+)", benchmark.release or "", re.I)
    return bid, version.lstrip("0") or None, str(int(release[1])) if release else None


def _asset(benchmark: Benchmark) -> str | None:
    ids = [r.version or "" for r in benchmark.rules.values()]
    for prefix, asset in (("RHEL-", "linux"), ("UBTU-", "linux"), ("WN", "windows"),
                          ("W2K", "windows"), ("CISC-", "cisco_ios"), ("CNTR-K8-", "kubernetes")):
        if any(r.startswith(prefix) for r in ids):
            return asset
    return None


def rule_keys(rule: Rule) -> set[str]:
    # Group ids and CCI references are deliberately excluded: neither is a unique cross-benchmark key.
    return _keys(rule.id, rule.short_id, rule.version)


def _scap_eligible(ds: Datastream, rule: Rule, asset: str | None) -> bool:
    if asset == "windows":
        from cyberthunder.scap.oval.windows_probes import SUPPORTED
        return ds.support(rule, SUPPORTED).supported
    if asset == "linux":
        check = rule.oval_check
        doc = ds.oval_for(check)
        return bool(check and doc and check.name in doc.definitions and not doc.missing([check.name]))
    return False


def benchmark_rows(documents: list[tuple[Datastream, str]], catalogs: list[NativeCatalog],
                   entries: list[FixEntry], sources: dict | None = None) -> list[dict]:
    rows = []
    for ds, digest in documents:
        for benchmark in ds.benchmarks:
            asset = _asset(benchmark)
            native = set().union(*(keys for c in catalogs if c.asset_type == asset for keys in c.rules.values()))
            rules = {r.id: rule_keys(r) for r in benchmark.rules.values()}
            family = _family(benchmark)
            # Never attach a different release's SCAP counts to a manual benchmark.
            peers = [(other, b) for other, _ in documents for b in other.benchmarks
                     if (other is ds and b is benchmark)
                     or (_family(b) == family and family[1] and family[2])]
            eligible = set().union(*(rule_keys(r) for other, b in peers for r in b.rules.values()
                                     if _scap_eligible(other, r, asset)))
            native_ids = {rid for rid, keys in rules.items() if keys & native}
            scap_ids = {rid for rid, keys in rules.items() if keys & eligible}
            missing = sorted(set(rules) - native_ids - scap_ids)
            rows.append({
                "asset_type": asset or "unmapped", "benchmark": benchmark.title,
                "benchmark_id": benchmark.id, "release": benchmark.release or benchmark.version or "unknown",
                "source": Path(ds.path).name, "sha256": digest, "kind": ds.kind,
                **(sources or {}).get(str(ds.path), {}),
                "published_rules": len(rules), "native_checks": len(native_ids), "scap_eligible": len(scap_ids),
                "not_covered": len(missing), "not_covered_rule_ids": missing,
                "native_rule_ids": sorted(native_ids), "scap_rule_ids": sorted(scap_ids),
                "scap_engine": "external OpenSCAP" if asset == "linux" else
                               "Windows OVAL preflight" if asset == "windows" else "none",
                **fix_counts(rules, [e for e in entries if e.asset_type == asset]),
            })
    return rows


def _paths(ctx, benchmark_dir: str | None) -> list[Path]:
    if benchmark_dir is not None:
        root = Path(benchmark_dir)
        if not root.is_dir():
            raise ReportError("coverage: benchmark directory does not exist")
        roots = [root]
    else:
        roots = [Path(__file__).resolve().parents[2] / "STIG",
                 ctx.store.root / "ingest" / "catalog", ctx.store.root / "content" / "scap"]
    return sorted({p.resolve() for root in roots if root.is_dir() for p in root.rglob("*.xml")})


def _load_content(path: Path) -> tuple[Datastream, str, dict] | None:
    """Fingerprint a document and its local OVAL companions, then parse a fresh snapshot."""
    versions = {}

    def read(p: Path) -> bytes:
        stat = p.stat()
        if stat.st_size > 256 * 1024 * 1024:
            raise ValueError("benchmark exceeds the 256 MiB content limit")
        versions[p] = (stat.st_mtime_ns, stat.st_size)
        return p.read_bytes()

    data = read(path)
    digest = sha256(data).hexdigest()
    root = ET.fromstring(data)
    local = lambda tag: tag.rsplit("}", 1)[-1]
    if local(root.tag) == "oval_definitions":
        return None  # Companions are evaluated with their XCCDF, not as separate benchmarks.
    dependencies = {}
    if local(root.tag) == "Benchmark":
        refs = set()
        for el in root.iter():
            if el.get("system", "").rstrip("/") != OVAL_SYSTEM:
                continue
            if local(el.tag) == "check":
                refs.update(ref.get("href") for ref in el if local(ref.tag) == "check-content-ref")
            elif local(el.tag) == "check-fact-ref":
                refs.add(el.get("href"))
        for href in sorted(ref for ref in refs if ref):
            companion = path.parent / Path(href).name
            if companion.exists():
                dependencies[companion.name] = sha256(read(companion)).hexdigest()
            else:
                versions[companion] = None
                dependencies[companion.name] = None
    # The shared scan cache is keyed by the XCCDF file alone. Reports must also
    # notice an OVAL file being added, removed or changed between renders.
    ds = load(path)
    for source, before in versions.items():
        after = source.stat() if source.exists() else None
        signature = (after.st_mtime_ns, after.st_size) if after else None
        if before != signature:
            raise ValueError("benchmark changed while reading; regenerate the report")
    if not ds.benchmarks:
        raise ValueError("no XCCDF benchmark")
    content_digest = sha256(json.dumps([digest, dependencies], sort_keys=True).encode()).hexdigest()
    return ds, digest, {"content_sha256": content_digest, "oval_dependencies": dependencies}


def build_coverage(ctx, benchmark_dir: str | None = None) -> dict:
    """Read installed checks, library entries and local content. No transports or scanners are called."""
    catalogs, entries, inventories, errors = [], [], [], []
    adapters = list(ctx.adapters.all())
    loaded = {a.asset_type for a in adapters}
    for asset in sorted(loaded):
        try:
            catalogs.extend(native_catalogs({asset}))
        except Exception as exc:
            errors.append(f"{asset}: native catalog unavailable ({type(exc).__name__})")
    for adapter in adapters:
        try:
            fixes = {e.fix_ref: e for e in adapter.fixes()}
        except Exception as exc:
            errors.append(f"{adapter.asset_type}: fix library unavailable ({type(exc).__name__})")
            continue
        entries.extend(fixes.values())
        inventories.append({"asset_type": adapter.asset_type, "entries": len(fixes),
                            "by_kind": dict(sorted(Counter(e.kind for e in fixes.values()).items())),
                            "by_source": dict(sorted(Counter(e.source for e in fixes.values()).items())),
                            "fix_refs": sorted(fixes)})
    for asset in sorted(set(EXECUTABLE_KINDS) - loaded):
        errors.append(f"{asset}: adapter not loaded; its checks and fixes are unavailable")
    native = []
    for c in catalogs:
        if c.asset_type not in loaded:
            continue
        native.append({"asset_type": c.asset_type, "benchmark": c.benchmark, "release": c.release,
                       "catalog_entries": c.catalog_entries, "native_checks": len(c.rules),
                       "published_rules": None, "scap_eligible": None, "not_covered": None,
                       "native_rule_ids": sorted(c.rules),
                       **fix_counts(c.rules, [e for e in entries if e.asset_type == c.asset_type])})
    documents, seen, sources = [], set(), {}
    for path in _paths(ctx, benchmark_dir):
        try:
            content = _load_content(path)
            if content is None:
                continue
            ds, digest, metadata = content
            if metadata["content_sha256"] in seen:
                continue
            documents.append((ds, digest))
            sources[str(ds.path)] = metadata
            seen.add(metadata["content_sha256"])
        except (OSError, ValueError, ET.ParseError) as exc:
            errors.append(f"{path.name}: benchmark unavailable ({type(exc).__name__})")
    return {"schema_version": 1, "generated_at": utcnow(), "limitations": list(LIMITATIONS),
            "native_catalogs": native,
            "benchmarks": benchmark_rows(documents, catalogs, entries, sources),
            "fix_library": inventories, "library_entries": sum(i["entries"] for i in inventories),
            "errors": errors}
