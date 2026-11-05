"""STIG release deltas.

A new STIG release arrives over the constrained link. We compare it against the release already in the
local catalog and report what was added, removed and changed, so only the affected rules are rescanned
and only the changed rule text has to cross the link next time.

Rules are keyed by STIG ID (rule_version, e.g. RHEL-09-255045) when the benchmark carries one, because
DISA bumps the SV-...r<rev>_rule id on every revision while the STIG ID stays put. Rules without a STIG ID
fall back to their XCCDF rule id.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import tempfile
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from cyberthunder.findings.schema import utcnow
from cyberthunder.parsers.xccdf import RuleMeta, parse_xccdf

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.store import StateStore

MAX_MEMBER_BYTES = 256 * 1024 * 1024   # refuse absurd zip members (zip bombs) outright


class BenchmarkError(ValueError):
    pass


@dataclass
class RuleRef:
    rule_id: str
    stig_id: str | None
    title: str
    severity: str
    change: str | None = None              # first of title|severity|check|fix that differs (changed rules only)
    changes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DeltaReport:
    id: str
    benchmark_id: str
    old_release: str | None
    new_release: str | None
    rules_added: list[RuleRef] = field(default_factory=list)
    rules_removed: list[RuleRef] = field(default_factory=list)
    rules_changed: list[RuleRef] = field(default_factory=list)
    counts: dict = field(default_factory=dict)
    rescan_rule_ids: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "DeltaReport":
        d = dict(d)
        for k in ("rules_added", "rules_removed", "rules_changed"):
            d[k] = [RuleRef(**r) for r in d.get(k, [])]
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in d.items() if k in known})


# -- loading --------------------------------------------------------------------------------------

def _pick_member(zf: zipfile.ZipFile) -> zipfile.ZipInfo:
    members = [m for m in zf.infolist() if not m.is_dir()]
    xccdf = [m for m in members if m.filename.lower().endswith("-xccdf.xml")]
    if not xccdf:
        xccdf = [m for m in members if m.filename.lower().endswith("xccdf.xml")]
    if not xccdf:
        raise BenchmarkError("zip has no *-xccdf.xml member")
    xccdf.sort(key=lambda m: m.filename)
    m = xccdf[0]
    if m.file_size > MAX_MEMBER_BYTES:
        raise BenchmarkError(f"{m.filename} is {m.file_size} bytes uncompressed; refusing")
    return m


def read_benchmark_xml(path: str | Path) -> bytes:
    """The XCCDF document itself, from an .xml file or a DISA .zip."""
    p = Path(path)
    if zipfile.is_zipfile(p):
        with zipfile.ZipFile(p) as zf:
            return zf.read(_pick_member(zf))
    return p.read_bytes()


def rule_key(meta: RuleMeta) -> str:
    return meta.rule_version or meta.rule_id


def load_benchmark(path: str | Path) -> tuple[str, str | None, dict[str, RuleMeta]]:
    """(benchmark_id, release, rules keyed by STIG ID or rule id). Accepts .xml or a DISA .zip."""
    p = Path(path)
    if zipfile.is_zipfile(p):
        tmp = Path(tempfile.mkdtemp(prefix="ct-stig-"))
        try:
            with zipfile.ZipFile(p) as zf:
                m = _pick_member(zf)
                dest = tmp / Path(m.filename).name     # basename only: no path traversal from the archive
                dest.write_bytes(zf.read(m))
            return _load_xml(dest)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return _load_xml(p)


def _load_xml(path: Path) -> tuple[str, str | None, dict[str, RuleMeta]]:
    parsed = parse_xccdf(path)
    if not parsed.benchmark_id:
        raise BenchmarkError(f"{path.name} is not an XCCDF benchmark")
    rules: dict[str, RuleMeta] = {}
    for meta in parsed.rules.values():
        rules[rule_key(meta)] = meta
    return parsed.benchmark_id, parsed.benchmark_release, rules


# -- diff -----------------------------------------------------------------------------------------

def _digest(text: str | None) -> str:
    norm = " ".join((text or "").split())
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


def rule_changes(old: RuleMeta, new: RuleMeta) -> list[str]:
    """Which of title|severity|check|fix differ, in that order. Whitespace-only edits are not changes."""
    out = []
    if " ".join(old.title.split()) != " ".join(new.title.split()):
        out.append("title")
    if old.severity != new.severity:
        out.append("severity")
    if _digest(old.check_text) != _digest(new.check_text):
        out.append("check")
    if _digest(old.fix_text) != _digest(new.fix_text):
        out.append("fix")
    return out


def _ref(meta: RuleMeta, changes: list[str] | None = None) -> RuleRef:
    return RuleRef(rule_id=meta.rule_id, stig_id=meta.rule_version, title=meta.title,
                   severity=getattr(meta.severity, "value", str(meta.severity)),
                   change=changes[0] if changes else None, changes=list(changes or []))


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("._") or "benchmark"


def new_delta_id(benchmark_id: str, release: str | None) -> str:
    from cyberthunder.store import StateStore
    slug = safe_name(f"{benchmark_id.rsplit('_', 1)[-1]}-{release or 'unreleased'}")[:60]
    return StateStore.new_id(f"delta-{slug}-")


def diff(old: tuple | None, new: tuple, *, delta_id: str | None = None) -> DeltaReport:
    """Compare two load_benchmark() results. old=None means a full import: every rule is 'added'."""
    bid, new_rel, new_rules = new
    old_rel, old_rules = (old[1], old[2]) if old else (None, {})
    added = [_ref(new_rules[k]) for k in sorted(set(new_rules) - set(old_rules))]
    removed = [_ref(old_rules[k]) for k in sorted(set(old_rules) - set(new_rules))]
    changed = []
    common = sorted(set(new_rules) & set(old_rules))
    for k in common:
        ch = rule_changes(old_rules[k], new_rules[k])
        if ch:
            changed.append(_ref(new_rules[k], ch))
    rescan: list[str] = []
    for r in added + changed:
        for v in (r.stig_id, r.rule_id):
            if v and v not in rescan:
                rescan.append(v)
    counts = {"added": len(added), "removed": len(removed), "changed": len(changed),
              "unchanged": len(common) - len(changed), "total": len(new_rules)}
    return DeltaReport(id=delta_id or new_delta_id(bid, new_rel), benchmark_id=bid, old_release=old_rel,
                       new_release=new_rel, rules_added=added, rules_removed=removed, rules_changed=changed,
                       counts=counts, rescan_rule_ids=rescan)


# -- catalog --------------------------------------------------------------------------------------

def catalog_dir(store: "StateStore") -> Path:
    return store.ingest_dir / "catalog"


def deltas_dir(store: "StateStore") -> Path:
    return store.ingest_dir / "deltas"


def catalog_path(store: "StateStore", benchmark_id: str) -> Path:
    return catalog_dir(store) / f"{safe_name(benchmark_id)}.xml"


def apply(delta: DeltaReport, new_path: str | Path, store: "StateStore") -> Path:
    """Make the new release the catalog copy and keep the delta report. Returns the catalog path."""
    dest = catalog_path(store, delta.benchmark_id)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".xml.tmp")
    tmp.write_bytes(read_benchmark_xml(new_path))
    tmp.replace(dest)
    store.write_json(deltas_dir(store) / f"{delta.id}.json", delta.to_dict())
    return dest


def load_delta(store: "StateStore", delta_id: str) -> DeltaReport:
    d = store.read_json(deltas_dir(store) / f"{safe_name(delta_id)}.json")
    if d is None:
        raise KeyError(f"no delta {delta_id!r}")
    return DeltaReport.from_dict(d)


def list_deltas(store: "StateStore") -> list[dict]:
    out = [store.read_json(p) for p in store.list_json(deltas_dir(store))]
    return sorted((d for d in out if d), key=lambda d: d.get("created_at", ""), reverse=True)
