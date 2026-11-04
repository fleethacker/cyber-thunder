"""SCAP 1.2 / 1.3 source datastreams and bare XCCDF + OVAL pairs.

A DISA SCAP benchmark is one XML file: a <data-stream-collection> holding <component> elements (the XCCDF
Benchmark, the OVAL definitions, a CPE dictionary and its OVAL) and a <data-stream> whose <component-ref>
elements carry XML catalogs. An XCCDF rule says

    <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
      <check-content-ref href="U_..._Benchmark-oval.xml" name="oval:mil.disa.stig.windows11:def:253462"/>

and the href resolves through the catalog of the checklist's component-ref (uri name -> '#<component-ref id>')
and that component-ref's xlink:href ('#<component id>') to the OVAL component. A bare XCCDF file resolves the
href as a file next to it instead.

load() returns a Datastream with every benchmark (rules, profiles, platforms) and every OVAL component, and
answers per rule whether its definition can be evaluated with the probes this package implements.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from cyberthunder.findings.schema import Reference, Severity
from cyberthunder.parsers.xccdf import _parse_rule

from .oval.model import OvalDocument
from .oval.parser import parse_oval_element

OVAL_SYSTEM = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
XLINK_HREF = "{http://www.w3.org/1999/xlink}href"
RULE_PREFIXES = ("xccdf_mil.disa.stig_rule_", "xccdf_org.ssgproject.content_rule_")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _children(el: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in el if _local(c.tag) == name]


def _child(el: ET.Element, name: str) -> ET.Element | None:
    return next((c for c in el if _local(c.tag) == name), None)


def _text(el: ET.Element | None) -> str:
    return " ".join("".join(el.itertext()).split()) if el is not None else ""


def short_rule_id(rule_id: str) -> str:
    """'xccdf_mil.disa.stig_rule_SV-253462r1016421_rule' -> 'SV-253462r1016421_rule'."""
    for p in RULE_PREFIXES:
        if rule_id.startswith(p):
            return rule_id[len(p):]
    return rule_id


@dataclass
class CheckRef:
    system: str
    href: str
    name: str | None            # OVAL definition id; None means "every definition in the file" (not used by DISA)
    component: str | None = None  # key into Datastream.oval once resolved

    @property
    def is_oval(self) -> bool:
        return self.system.rstrip("/") == OVAL_SYSTEM


@dataclass
class Rule:
    id: str
    version: str | None          # STIG id, e.g. WN11-SO-000205
    title: str
    severity: Severity
    group_id: str | None = None
    description: str = ""
    check_text: str | None = None
    fix_text: str | None = None
    references: list[Reference] = field(default_factory=list)
    checks: list[CheckRef] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)   # platform idrefs ('#xccdf_..._platform_X' or a CPE)
    selected: bool = True                                 # default selection, before any profile
    groups: list[str] = field(default_factory=list)       # enclosing Group ids, outermost first

    @property
    def short_id(self) -> str:
        return short_rule_id(self.id)

    @property
    def oval_check(self) -> CheckRef | None:
        return next((c for c in self.checks if c.is_oval and c.name), None)

    @property
    def ccis(self) -> list[str]:
        return [r.id for r in self.references if r.system == "cci"]


@dataclass
class Profile:
    id: str
    title: str
    description: str = ""
    selects: list[tuple[str, bool]] = field(default_factory=list)   # (rule or group id, selected) in order


@dataclass
class Platform:
    """A CPE applicability platform: a logical test over OVAL definitions (check-fact-ref)."""
    id: str
    title: str
    operator: str = "AND"
    negate: bool = False
    facts: list[CheckRef] = field(default_factory=list)


@dataclass
class Benchmark:
    id: str
    title: str
    version: str | None = None
    release: str | None = None
    rules: dict[str, Rule] = field(default_factory=dict)
    profiles: dict[str, Profile] = field(default_factory=dict)
    platforms: dict[str, Platform] = field(default_factory=dict)
    component: str | None = None

    def selected_rules(self, profile_id: str | None = None) -> list[Rule]:
        """Rules a profile selects, in document order. No profile: the rules selected by default."""
        sel = {rid: r.selected for rid, r in self.rules.items()}
        if profile_id:
            prof = self.profiles.get(profile_id)
            if prof is None:
                raise KeyError(f"profile {profile_id!r} is not in benchmark {self.id}; "
                               f"profiles: {', '.join(self.profiles) or 'none'}")
            for idref, on in prof.selects:
                if idref in sel:
                    sel[idref] = on
                else:
                    for rid, r in self.rules.items():
                        if idref in r.groups:
                            sel[rid] = on
        return [r for rid, r in self.rules.items() if sel.get(rid)]

    def rule(self, key: str) -> Rule | None:
        """By full id, short id (SV-...), STIG id (WN11-...) or group id (V-...)."""
        for r in self.rules.values():
            if key in (r.id, r.short_id, r.version, r.group_id):
                return r
        return None


@dataclass
class RuleSupport:
    rule: Rule
    supported: bool
    probes: set[str] = field(default_factory=set)
    unsupported: set[str] = field(default_factory=set)
    missing: list[str] = field(default_factory=list)
    reason: str = ""


@dataclass
class Datastream:
    path: str
    kind: str                                          # datastream | xccdf
    benchmarks: list[Benchmark] = field(default_factory=list)
    oval: dict[str, OvalDocument] = field(default_factory=dict)
    ids: dict[str, str] = field(default_factory=dict)   # datastream id, collection id

    @property
    def benchmark(self) -> Benchmark:
        if not self.benchmarks:
            raise ValueError(f"{self.path} contains no XCCDF benchmark")
        return self.benchmarks[0]

    def oval_for(self, check: CheckRef | None) -> OvalDocument | None:
        if check is None or check.component is None:
            return None
        return self.oval.get(check.component)

    def support(self, rule: Rule, supported_probes) -> RuleSupport:
        chk = rule.oval_check
        if chk is None:
            systems = ", ".join(sorted({c.system for c in rule.checks})) or "none"
            return RuleSupport(rule, False, reason=f"no OVAL check (check systems: {systems})")
        doc = self.oval_for(chk)
        if doc is None:
            return RuleSupport(rule, False, reason=f"OVAL content {chk.href!r} is not in the datastream")
        if chk.name not in doc.definitions:
            return RuleSupport(rule, False, reason=f"definition {chk.name} is not in {chk.href}")
        probes = doc.probes([chk.name])
        missing = doc.missing([chk.name])
        unsupported = {p for p in probes if p not in supported_probes}
        ok = not unsupported and not missing
        reason = ""
        if unsupported:
            reason = "unsupported OVAL test types: " + ", ".join(sorted(p + "_test" for p in unsupported))
        elif missing:
            reason = "unresolved references: " + ", ".join(missing[:5])
        return RuleSupport(rule, ok, probes, unsupported, missing, reason)

    def counts(self) -> dict:
        b = self.benchmarks[0] if self.benchmarks else None
        out = {"benchmarks": len(self.benchmarks), "rules": len(b.rules) if b else 0,
               "profiles": len(b.profiles) if b else 0}
        for doc in self.oval.values():
            for k, v in doc.counts().items():
                out[k] = out.get(k, 0) + v
        return out


# -- loading ----------------------------------------------------------------------------------------------------
def _release(bench: ET.Element) -> tuple[str | None, str | None]:
    version = _text(_child(bench, "version")) or None
    info = next((_text(p) for p in _children(bench, "plain-text") if p.get("id") == "release-info"), "")
    m = re.match(r"^0*(\d+)\.0*(\d+)$", version or "")
    rel = f"Version {m.group(1)} Release {m.group(2)}" if m else (f"Version {version}" if version else "")
    if info:
        rel = f"{rel} ({info})" if rel else info
    return version, rel or None


def _parse_benchmark(bench: ET.Element) -> Benchmark:
    parents = {c: p for p in bench.iter() for c in p}
    version, release = _release(bench)
    b = Benchmark(id=bench.get("id", ""), title=_text(_child(bench, "title")), version=version, release=release)
    for el in bench.iter():
        n = _local(el.tag)
        if n == "Profile":
            p = Profile(id=el.get("id", ""), title=_text(_child(el, "title")),
                        description=_text(_child(el, "description")))
            for s in _children(el, "select"):
                p.selects.append((s.get("idref", ""), (s.get("selected") or "true").lower() in ("true", "1")))
            b.profiles[p.id] = p
        elif n == "platform" and el.get("id") and _local(parents.get(el, el).tag) == "platform-specification":
            lt = _child(el, "logical-test")
            plat = Platform(id=el.get("id"), title=_text(_child(el, "title")))
            if lt is not None:
                plat.operator = (lt.get("operator") or "AND").upper()
                plat.negate = (lt.get("negate") or "false").lower() in ("true", "1")
                for f in lt.iter():
                    if _local(f.tag) == "check-fact-ref":
                        plat.facts.append(CheckRef(f.get("system", ""), f.get("href", ""), f.get("id-ref")))
            b.platforms[plat.id] = plat
        elif n == "Rule":
            meta = _parse_rule(el, parents)
            groups, selected = [], (el.get("selected") or "true").lower() in ("true", "1")
            p = parents.get(el)
            while p is not None and p is not bench:
                if _local(p.tag) == "Group":
                    groups.insert(0, p.get("id", ""))
                    if (p.get("selected") or "true").lower() in ("false", "0"):
                        selected = False
                p = parents.get(p)
            checks = []
            for chk in _children(el, "check"):
                for ref in _children(chk, "check-content-ref"):
                    checks.append(CheckRef(chk.get("system", ""), ref.get("href", ""), ref.get("name")))
            content = next((_text(_child(c, "check-content")) for c in _children(el, "check")
                            if _child(c, "check-content") is not None), None)
            b.rules[meta.rule_id] = Rule(
                id=meta.rule_id, version=meta.rule_version, title=meta.title, severity=meta.severity,
                group_id=meta.group_id, description=meta.description, check_text=content or None,
                fix_text=meta.fix_text, references=list(meta.references), checks=checks,
                platforms=[pl.get("idref", "") for pl in _children(el, "platform")], selected=selected,
                groups=groups)
    return b


def _resolve_catalog(cref: ET.Element) -> dict[str, str]:
    """uri name -> target ('#id') from a component-ref's XML catalog."""
    out = {}
    for el in cref.iter():
        if _local(el.tag) == "uri" and el.get("name"):
            out[el.get("name")] = el.get("uri", "")
    return out


def load(path: str | Path, oval_path: str | Path | None = None) -> Datastream:
    """Load a source datastream, or a bare XCCDF benchmark (with its OVAL file next to it or given)."""
    p = Path(path)
    root = ET.parse(str(p)).getroot()
    name = _local(root.tag)
    if name == "data-stream-collection":
        return _load_datastream(p, root)
    if name == "Benchmark":
        return _load_pair(p, root, Path(oval_path) if oval_path else None)
    raise ValueError(f"{p.name}: root element <{name}> is neither a SCAP datastream nor an XCCDF Benchmark")


def _load_datastream(p: Path, root: ET.Element) -> Datastream:
    ds = Datastream(path=str(p), kind="datastream", ids={"collection": root.get("id", "")})
    components = {c.get("id", ""): c for c in root if _local(c.tag) == "component"}
    crefs: dict[str, ET.Element] = {}
    stream = next((c for c in root if _local(c.tag) == "data-stream"), None)
    if stream is not None:
        ds.ids["datastream"] = stream.get("id", "")
        for el in stream.iter():
            if _local(el.tag) == "component-ref":
                crefs[el.get("id", "")] = el

    def comp_of_cref(cref_id: str) -> str | None:
        cref = crefs.get(cref_id)
        if cref is None:
            return None
        return (cref.get(XLINK_HREF) or "").lstrip("#") or None

    oval_ids = set()
    for cid, comp in components.items():
        for ch in comp:
            if _local(ch.tag) == "oval_definitions":
                ds.oval[cid] = parse_oval_element(ch)
                oval_ids.add(cid)
    for cref_id, cref in crefs.items():
        comp_id = comp_of_cref(cref_id)
        comp = components.get(comp_id or "")
        if comp is None:
            continue
        bench_el = next((c for c in comp if _local(c.tag) == "Benchmark"), None)
        if bench_el is None:
            continue
        b = _parse_benchmark(bench_el)
        b.component = comp_id
        catalog = _resolve_catalog(cref)

        def resolve(href: str) -> str | None:
            target = catalog.get(href, href if href.startswith("#") else "")
            target_cref = target.lstrip("#")
            comp_id2 = comp_of_cref(target_cref) if target_cref in crefs else target_cref
            return comp_id2 if comp_id2 in oval_ids else None

        for r in b.rules.values():
            for c in r.checks:
                c.component = resolve(c.href)
        for pl in b.platforms.values():
            for f in pl.facts:
                f.component = resolve(f.href)
        ds.benchmarks.append(b)
    return ds


def _load_pair(p: Path, root: ET.Element, oval_path: Path | None) -> Datastream:
    ds = Datastream(path=str(p), kind="xccdf")
    b = _parse_benchmark(root)
    ds.benchmarks.append(b)
    refs = [c for r in b.rules.values() for c in r.checks] + [f for pl in b.platforms.values() for f in pl.facts]
    for c in refs:
        if not c.is_oval:
            continue
        cand = oval_path if oval_path else (p.parent / Path(c.href).name if c.href else None)
        if cand is None:
            continue
        key = str(cand)
        if key not in ds.oval and cand.exists():
            ds.oval[key] = parse_oval_element(ET.parse(str(cand)).getroot())
        if key in ds.oval:
            c.component = key
    return ds


_CACHE: dict[tuple, Datastream] = {}


def load_cached(path: str | Path) -> Datastream:
    """load() once per file version; scans and verify re-use the parsed benchmark."""
    p = Path(path).resolve()
    st = p.stat()
    key = (str(p), st.st_mtime_ns, st.st_size)
    if key not in _CACHE:
        if len(_CACHE) > 8:
            _CACHE.clear()
        _CACHE[key] = load(p)
    return _CACHE[key]


def rules_for(ds: Datastream, profile: str | None = None, rule_filter: list[str] | None = None) -> list[Rule]:
    """Rules a profile selects, narrowed to a rule filter (full ids, SV ids, STIG ids or V ids)."""
    rules = ds.benchmark.selected_rules(profile)
    if rule_filter:
        want = {x for x in rule_filter if x}
        rules = [r for r in rules if {r.id, r.short_id, r.version, r.group_id} & want]
    return rules
