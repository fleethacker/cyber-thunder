"""Trim a SCAP datastream to a set of rules, keeping it a valid datastream.

Kept: the rules asked for (with their Groups), profile selects that name them, the CPE platforms they use, and
exactly the OVAL definitions, tests, objects, states and variables those rules and platforms reference. The
other components (CPE dictionary and its OVAL) are copied unchanged. Used to build small test fixtures and to
send only the rules an enclave needs over a constrained link.
"""
from __future__ import annotations

import io
import xml.etree.ElementTree as ET
from pathlib import Path

from .datastream import load

PREFERRED_PREFIXES = {
    "http://scap.nist.gov/schema/scap/source/1.2": "ds",
    "http://checklists.nist.gov/xccdf/1.2": "xccdf",
    "http://oval.mitre.org/XMLSchema/oval-definitions-5": "oval-def",
    "http://oval.mitre.org/XMLSchema/oval-definitions-5#windows": "win-def",
    "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent": "ind-def",
    "http://oval.mitre.org/XMLSchema/oval-common-5": "oval",
    "urn:oasis:names:tc:entity:xmlns:xml:catalog": "cat",
    "http://www.w3.org/1999/xlink": "xlink",
    "http://www.w3.org/2001/XMLSchema-instance": "xsi",
    "http://purl.org/dc/elements/1.1/": "dc",
    "http://cpe.mitre.org/language/2.0": "cpe-lang",
    "http://cpe.mitre.org/dictionary/2.0": "cpe-dict",
}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _register_namespaces(path: Path) -> None:
    seen: dict[str, str] = {}
    for _, (prefix, uri) in ET.iterparse(str(path), events=("start-ns",)):
        if prefix and uri not in seen:
            seen[uri] = prefix
    for uri, prefix in {**seen, **PREFERRED_PREFIXES}.items():
        try:
            ET.register_namespace(prefix, uri)
        except ValueError:
            pass


def subset(src: str | Path, rule_keys: list[str], dest: str | Path) -> dict:
    """Write a datastream holding only the given rules (full ids, SV ids, STIG ids or V ids). Returns counts."""
    src, dest = Path(src), Path(dest)
    ds = load(src)
    b = ds.benchmark
    keep_rules = {}
    for k in rule_keys:
        r = b.rule(k)
        if r is None:
            raise KeyError(f"rule {k!r} is not in {src.name}")
        keep_rules[r.id] = r
    keep_platforms = {p.lstrip("#") for r in keep_rules.values() for p in r.platforms if p.startswith("#")}
    defs_by_comp: dict[str, set[str]] = {}
    for r in keep_rules.values():
        c = r.oval_check
        if c and c.component:
            defs_by_comp.setdefault(c.component, set()).add(c.name)
    for pid in keep_platforms:
        for f in b.platforms[pid].facts:
            if f.component and f.name:
                defs_by_comp.setdefault(f.component, set()).add(f.name)
    keep_oval = {comp: ds.oval[comp].closure(ids) for comp, ids in defs_by_comp.items()}

    _register_namespaces(src)
    tree = ET.parse(str(src))
    root = tree.getroot()
    for comp in (c for c in root if _local(c.tag) == "component"):
        cid = comp.get("id", "")
        bench = next((c for c in comp if _local(c.tag) == "Benchmark"), None)
        if bench is not None and cid == b.component:
            _trim_benchmark(bench, keep_rules, keep_platforms)
        oval = next((c for c in comp if _local(c.tag) == "oval_definitions"), None)
        if oval is not None and cid in keep_oval:
            _trim_oval(oval, keep_oval[cid])
    for el in list(root):
        if _local(el.tag) == "Signature":
            root.remove(el)
    buf = io.BytesIO()
    tree.write(buf, encoding="UTF-8", xml_declaration=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(buf.getvalue().replace(b"\r\n", b"\n"))
    out = load(dest)
    return out.counts()


def _trim_benchmark(bench: ET.Element, keep_rules: dict, keep_platforms: set[str]) -> None:
    keep_groups = {g for r in keep_rules.values() for g in r.groups}
    keep_ids = set(keep_rules) | keep_groups

    def prune(parent: ET.Element) -> None:
        for el in list(parent):
            n = _local(el.tag)
            if n == "Group":
                if el.get("id") not in keep_groups:
                    parent.remove(el)
                else:
                    prune(el)
            elif n == "Rule" and el.get("id") not in keep_rules:
                parent.remove(el)

    prune(bench)
    for el in bench:
        n = _local(el.tag)
        if n == "Profile":
            for s in list(el):
                if _local(s.tag) == "select" and s.get("idref") not in keep_ids:
                    el.remove(s)
        elif n == "platform-specification":
            for p in list(el):
                if _local(p.tag) == "platform" and p.get("id") not in keep_platforms:
                    el.remove(p)


def _trim_oval(oval: ET.Element, keep: dict[str, set[str]]) -> None:
    for sec in list(oval):
        name = _local(sec.tag)
        if name not in keep:
            continue
        for el in list(sec):
            if el.get("id") and el.get("id") not in keep[name]:
                sec.remove(el)
        if len(sec) == 0:
            oval.remove(sec)
