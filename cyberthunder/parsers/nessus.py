"""ACAS / Nessus export parser (NessusClientData_v2 XML, the ``.nessus`` file).

ACAS is the Navy's fielded vulnerability scanner, so its export is the most likely input on a real
enclave. We only read the export; nothing here talks to a scanner or a host.

Namespace-agnostic (matches local tag names) and streaming (``iterparse``), so a multi-hundred-MB
export does not have to fit in memory: each ReportItem is turned into a Finding and released.

Mapping (one Finding per host + plugin):
  rule_id   nessus:<pluginID>
  severity  stig_severity (I/II/III) when ACAS supplies it, else Nessus severity 4/3 high, 2 medium, 1 low
  status    OPEN for severity > 0; informational plugins are skipped unless include_info=True
  fix_ref   patch:<pluginID>   (a hint for the fix library; nothing is resolved or run here)
A plugin that fires on several ports of one host is merged into one Finding (all ports listed in tags and
evidence), because Finding ids are host + source + rule and must stay unique.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

from cyberthunder.adapters.base import make_finding
from cyberthunder.findings.schema import RE_IAVM, Finding, Reference

MAX_DESCRIPTION = 1500
MAX_EVIDENCE = 1000

_STIG_SEV = {"I": "high", "II": "medium", "III": "low"}
_NESSUS_SEV = {4: "high", 3: "high", 2: "medium", 1: "low", 0: "info"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _clean(text: str | None) -> str:
    return " ".join((text or "").split())


def _trim(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def _int(value: str | None, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _asset_type(os_name: str) -> str | None:
    low = os_name.lower()
    if "windows" in low:
        return "windows"
    if "linux" in low or "red hat" in low or "ubuntu" in low:
        return "linux"
    return None


def _item_fields(item: ET.Element) -> dict:
    """Child text by tag name; cve and xref repeat, so they are lists."""
    d: dict = {"cve": [], "xref": []}
    for c in item:
        name = _local(c.tag)
        v = _clean(c.text)
        if name in ("cve", "xref"):
            if v:
                d[name].append(v)
        else:
            d[name] = v      # plugin output is flattened to one line: evidence is shown inline
    return d


def _references(fields: dict) -> list[str]:
    refs: list[str] = []

    def add(r: str) -> None:
        if r and r not in refs:
            refs.append(r)

    for cve in fields["cve"]:
        add(cve.upper())
    for x in fields["xref"]:
        kind, _, val = x.partition(":")
        kind, val = kind.strip().upper(), val.strip()
        if kind in ("IAVA", "IAVB", "IAVT"):
            m = RE_IAVM.search(val)
            add(m.group(0) if m else val)
        elif kind == "CWE" and val:
            add(f"CWE-{val}")
        elif kind == "CVE" and val:
            add(val.upper())
        elif kind == "MSFT" and val:
            add(val)           # MS17-010 style bulletin ids are self-describing
        elif kind and val:
            add(f"{kind}:{val}")   # CERT, EDB-ID, MSKB, ...: keep the kind so a bare number is never cited alone
    return refs


def _severity(fields: dict, nessus_sev: int) -> str:
    stig = _STIG_SEV.get(fields.get("stig_severity", "").strip().upper())
    return stig or _NESSUS_SEV.get(nessus_sev, "info")


def _build(host: str, hostprops: dict, attrs: dict, fields: dict, scan_name: str, source: str,
           path: str) -> Finding:
    nsev = _int(attrs.get("severity"))
    plugin = attrs.get("pluginID", "")
    port_s = f"{attrs.get('port', '0')}/{attrs.get('protocol', 'tcp')}"
    description = _trim(" ".join(p for p in (fields.get("synopsis", ""), fields.get("description", "")) if p),
                        MAX_DESCRIPTION)
    evidence = " ".join(p for p in (_trim(fields.get("plugin_output", ""), MAX_EVIDENCE), f"[{port_s}]") if p)
    tags = [f"family:{attrs.get('pluginFamily', '')}", f"port:{port_s}"]
    if fields.get("cvss3_base_score"):
        tags.append(f"cvss3:{fields['cvss3_base_score']}")
    if fields.get("exploit_available", "").lower() == "true":
        tags.append("exploit_available")
    refs = _references(fields)
    # make_finding only needs an id and an asset type, so a plain namespace stands in for an inventory Target:
    # the host in a scan export is not necessarily in the inventory yet.
    target = SimpleNamespace(id=host, asset_type=_asset_type(hostprops.get("operating-system", "")))
    f = make_finding(
        target=target, source=source, rule_id=f"nessus:{plugin}",
        title=attrs.get("pluginName") or f"Nessus plugin {plugin}", severity=_severity(fields, nsev),
        status="open" if nsev > 0 else "not_reviewed",
        description=description, evidence=evidence, references=refs,
        fix_ref=f"patch:{plugin}", fix_text=fields.get("solution") or None,
        benchmark=f"ACAS (Nessus) {scan_name}".strip(), tags=tags, raw_ref=path)
    if not refs:
        # No CVE or advisory: still cite the plugin so the finding traces back to the scanner.
        f.references.append(Reference("nessus", f"nessus:{plugin}"))
    return f


def parse_nessus(path: str | Path, *, host: str | None = None, source: str = "acas",
                 include_info: bool = False) -> list[Finding]:
    """Parse a NessusClientData_v2 export into Findings. ``host`` overrides the ReportHost name."""
    path = str(path)
    findings: dict[tuple[str, str], Finding] = {}
    scan_name = ""
    cur_host = ""
    props: dict = {}
    in_props = False
    with open(path, "rb") as fh:
        for event, el in ET.iterparse(fh, events=("start", "end")):
            name = _local(el.tag)
            if event == "start":
                if name == "Report":
                    scan_name = el.get("name", "")
                elif name == "ReportHost":
                    cur_host = el.get("name", "")
                    props = {}
                elif name == "HostProperties":
                    in_props = True
                continue
            if name == "tag" and in_props:
                props[el.get("name", "")] = _clean(el.text)
            elif name == "HostProperties":
                in_props = False
            elif name == "ReportItem":
                attrs = dict(el.attrib)
                fields = _item_fields(el)
                el.clear()
                if _int(attrs.get("severity")) == 0 and not include_info:
                    continue
                shown = host or cur_host
                f = _build(shown, props, attrs, fields, scan_name, source, path)
                prev = findings.get((shown, f.rule_id))
                if prev is None:
                    findings[(shown, f.rule_id)] = f
                else:
                    _merge(prev, f)
            elif name == "ReportHost":
                el.clear()
    return list(findings.values())


def _merge(into: Finding, extra: Finding) -> None:
    """Same plugin on another port of the same host: keep one finding and record every port."""
    for t in extra.tags:
        if t.startswith("port:") and t not in into.tags:
            into.tags.append(t)
    if extra.evidence:
        into.evidence = _trim(" ".join(p for p in (into.evidence, extra.evidence) if p), MAX_EVIDENCE * 2)
    for r in extra.references:
        if all(x.id != r.id for x in into.references):
            into.references.append(r)


def parse_nessus_hosts(path: str | Path) -> list[dict]:
    """List the hosts in an export ({name, ip, os, fqdn}) for inventory import."""
    hosts: list[dict] = []
    cur: dict | None = None
    with open(str(path), "rb") as fh:
        for event, el in ET.iterparse(fh, events=("start", "end")):
            name = _local(el.tag)
            if event == "start":
                if name == "ReportHost":
                    cur = {"name": el.get("name", ""), "ip": None, "os": None, "fqdn": None}
                continue
            if name == "tag" and cur is not None:
                key = {"host-ip": "ip", "operating-system": "os", "host-fqdn": "fqdn"}.get(el.get("name", ""))
                if key:
                    cur[key] = _clean(el.text) or None
            elif name == "ReportItem":
                el.clear()
            elif name == "ReportHost" and cur is not None:
                hosts.append(cur)
                cur = None
                el.clear()
    return hosts
