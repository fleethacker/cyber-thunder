"""Which DISA files this node wants, from what it knows about its own assets.

Inputs are the inventory (asset type, tags, options), the platform facts the last scan recorded for each
target (collected.json "facts"), and the content already held. A target whose facts are missing can name
its products with options["stig_products"] (a list of product keys such as "RHEL_9").

For each product key wanted: the newest non-sunset manual STIG (or SRG where DISA publishes only an SRG),
and the newest SCAP benchmark when a scanner here can execute it (Windows and Linux). Automation content
and the quarterly compilation are pulled only on request.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping

from cyberthunder.ingest.content.index import ALLOWED_HOSTS, Entry

SCAP_TYPES = {"windows", "linux"}       # asset types whose scanner here executes a SCAP datastream
GUIDE_KINDS = ("manual_stig", "srg")

_WIN_SERVER = re.compile(r"server\s*(20\d\d)", re.I)
_DC_TAGS = {"dc", "domain_controller", "domain-controller", "ad", "active_directory"}


@dataclass
class ProductWant:
    product_key: str
    targets: list[str]
    reasons: list[str]
    scap: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Selection:
    products: dict[str, ProductWant] = field(default_factory=dict)
    wanted: list[dict] = field(default_factory=list)     # entries the node should hold, newest per product/kind
    updates: list[dict] = field(default_factory=list)    # wanted and not held (or held at an older version)
    current: list[dict] = field(default_factory=list)    # wanted and held at this version or newer
    skipped: list[dict] = field(default_factory=list)    # {target_id|filename|product_key, reason}

    def to_dict(self) -> dict:
        return {"products": {k: v.to_dict() for k, v in sorted(self.products.items())}, "wanted": self.wanted,
                "updates": self.updates, "current": self.current, "skipped": self.skipped}


# -- facts to product keys ------------------------------------------------------------------------

def _facts_of(target, collected: Mapping[str, Any] | None) -> dict:
    facts: dict[str, Any] = {}
    opt = getattr(target, "options", None) or {}
    if isinstance(opt.get("facts"), dict):
        facts.update(opt["facts"])
    c = (collected or {}).get("facts") if isinstance(collected, Mapping) else None
    if isinstance(c, dict):
        for k, v in c.items():
            if k == "extra" and isinstance(v, dict):
                for kk, vv in v.items():
                    facts.setdefault(kk, vv)
            elif v not in (None, "", []):
                facts[k] = v
    return facts


def _windows(target, facts: dict) -> tuple[list[str], list[str], str | None]:
    name = str(facts.get("os_name") or "")
    keys, why = [], []
    m = _WIN_SERVER.search(name)
    if m:
        if m.group(1) in ("2016", "2019", "2022", "2025"):
            keys.append(f"MS_Windows_Server_{m.group(1)}")
            why.append(f"os_name {name!r}")
    elif re.search(r"windows\s*11", name, re.I):
        keys.append("MS_Windows_11")
        why.append(f"os_name {name!r}")
    elif re.search(r"windows\s*10", name, re.I):
        keys.append("MS_Windows_10")
        why.append(f"os_name {name!r}")
    tags = {str(t).lower() for t in (getattr(target, "tags", None) or [])}
    role = str((getattr(target, "options", None) or {}).get("role") or "").lower()
    domain_role = facts.get("domain_role")
    is_dc = bool(tags & _DC_TAGS) or role in _DC_TAGS or str(domain_role) in ("4", "5") or \
        str(domain_role).lower() in ("backupdomaincontroller", "primarydomaincontroller")
    joined = facts.get("part_of_domain") in (True, "true", "True", 1)
    if is_dc or joined:
        keys += ["Active_Directory_Domain", "Active_Directory_Forest"]
        why.append("domain controller" if is_dc else "domain-joined (facts part_of_domain)")
    if not keys:
        return [], [], (f"Windows edition not recognised from os_name {name!r}" if name
                        else "no Windows facts yet; scan the host or set options.stig_products")
    return keys, why, None


def _major(v: Any) -> str | None:
    m = re.match(r"\s*(\d+)", str(v or ""))
    return m.group(1) if m else None


def _linux(target, facts: dict) -> tuple[list[str], list[str], str | None]:
    name = str(facts.get("os_name") or "")
    ident = str(facts.get("model") or facts.get("id") or "").lower()
    ver = str(facts.get("os_version") or "")
    low = f"{name} {ident}".lower()
    major = _major(ver)
    why = [f"os_name {name!r} {ver}".strip()]
    if not name and not ident:
        return [], [], "no Linux facts yet; scan the host or set options.stig_products"
    if any(k in low for k in ("red hat", "rhel", "rocky", "alma", "centos stream")):
        if major in ("8", "9", "10"):
            return [f"RHEL_{major}"], why, None
        return [], [], f"RHEL-family release {ver!r} has no supported STIG here"
    if "oracle" in low or ident == "ol":
        if major in ("8", "9"):
            return [f"Oracle_Linux_{major}"], why, None
        return [], [], f"Oracle Linux {ver!r} has no supported STIG here"
    if "ubuntu" in low:
        m = re.match(r"\s*(\d{2})\.(\d{2})", ver)
        if m and f"{m.group(1)}.{m.group(2)}" in ("20.04", "22.04", "24.04"):
            return [f"CAN_Ubuntu_{m.group(1)}-{m.group(2)}"], why, None
        return [], [], f"Ubuntu {ver!r} is not an LTS release with a STIG"
    if "suse" in low or "sles" in low:
        if major == "15":
            return ["SLES_15"], why, None
        return [], [], f"SLES {ver!r} has no supported STIG here"
    return [], [], f"Linux distribution {name or ident!r} is not mapped to a STIG"


def _cisco(target, facts: dict) -> tuple[list[str], list[str], str | None]:
    name = str(facts.get("os_name") or "")
    tags = {str(t).lower() for t in (getattr(target, "tags", None) or [])}
    role = str((getattr(target, "options", None) or {}).get("role") or "").lower()
    if not role:
        role = "router" if "router" in tags and "switch" not in tags else "switch"
    role = "Router" if role.startswith("rout") else "Switch"
    if not name:
        return [], [], "no IOS facts yet (IOS or IOS-XE unknown); scan the device or set options.stig_products"
    xe = bool(re.search(r"IOS[\s-]?XE", name, re.I))
    if not xe and not re.search(r"\bIOS\b", name, re.I):
        return [], [], f"Cisco platform {name!r} is not IOS or IOS-XE"
    return [f"Cisco_IOS{'-XE' if xe else ''}_{role}"], [f"os_name {name!r}, role {role.lower()}"], None


def products_for(target, collected: Mapping[str, Any] | None = None) -> tuple[list[str], list[str], str | None]:
    """(product keys, reasons, why-not) for one target."""
    opt = getattr(target, "options", None) or {}
    override = opt.get("stig_products")
    if isinstance(override, str):
        override = [s.strip() for s in override.split(",") if s.strip()]
    if override:
        return [str(k) for k in override], ["options.stig_products"], None
    facts = _facts_of(target, collected)
    t = target.asset_type
    if t == "windows":
        return _windows(target, facts)
    if t == "linux":
        return _linux(target, facts)
    if t == "cisco_ios":
        return _cisco(target, facts)
    if t == "kubernetes":
        return ["Kubernetes"], ["asset type kubernetes"], None
    if t == "containers":
        return ["Container_Platform"], ["asset type containers"], None
    return [], [], f"no content rules for asset type {t!r}"


# -- choosing entries -----------------------------------------------------------------------------

def _newest(entries: Iterable[Entry]) -> Entry | None:
    best = None
    for e in entries:
        if best is None or (e.version or (0, 0), e.upload_date or "") > (best.version or (0, 0), best.upload_date or ""):
            best = e
    return best


def _held_version(held: Iterable[dict], product_key: str, kind: str) -> tuple[int, int] | None:
    best = None
    for r in held:
        if r.get("product_key") == product_key and r.get("kind") == kind and r.get("version"):
            v = tuple(int(x) for x in r["version"])
            if best is None or v > best:
                best = v
    return best


def _row(e: Entry, want: ProductWant | None, **extra) -> dict:
    d = {"filename": e.filename, "url": e.url, "product_key": e.product_key, "kind": e.kind,
         "version": list(e.version) if e.version else None, "version_label": e.version_label,
         "upload_date": e.upload_date, "title": e.title, "sunset": e.sunset}
    if want is not None:
        d["targets"] = list(want.targets)
    d.update(extra)
    return d


def select(entries: list[Entry], targets: Iterable, collected: Mapping[str, Mapping] | None = None,
           held: Iterable[dict] = (), *, include_automation: bool = False, include_compilation: bool = False,
           extra_products: Iterable[str] = (), allowed_hosts: Iterable[str] = ALLOWED_HOSTS,
           allow_http: bool = False) -> Selection:
    """Work out wanted, current, update and skipped entries. Pure: no I/O."""
    collected = collected or {}
    held = list(held)
    hosts = frozenset(allowed_hosts)

    def ok(e: Entry) -> bool:
        return e.allowed_by(hosts, allow_http)

    sel = Selection()
    for t in targets:
        if not getattr(t, "in_scope", True):
            sel.skipped.append({"target_id": t.id, "reason": "target is out of scope"})
            continue
        keys, why, no = products_for(t, collected.get(t.id))
        if no:
            sel.skipped.append({"target_id": t.id, "reason": f"unsupported host: {no}"})
            continue
        for k in keys:
            w = sel.products.setdefault(k, ProductWant(product_key=k, targets=[], reasons=[]))
            if t.id not in w.targets:
                w.targets.append(t.id)
            w.reasons.extend(r for r in why if r not in w.reasons)
            if t.asset_type in SCAP_TYPES:
                w.scap = True
    for k in extra_products:
        sel.products.setdefault(k, ProductWant(product_key=k, targets=[], reasons=["requested"]))

    by_product: dict[str, list[Entry]] = {}
    for e in entries:
        if e.product_key:
            by_product.setdefault(e.product_key.lower(), []).append(e)

    wanted: list[tuple[Entry, ProductWant | None]] = []
    for key, want in sorted(sel.products.items()):
        cands = by_product.get(key.lower(), [])
        if not cands:
            sel.skipped.append({"product_key": key, "reason": "not matching: no entry in the index for this product"})
            continue
        kinds = list(GUIDE_KINDS[:1])
        if want.scap:
            kinds.append("scap_benchmark")
        if include_automation:
            kinds.append("automation")
        for kind in kinds:
            pool = [e for e in cands if e.kind == kind]
            if kind == "manual_stig" and not pool:
                pool = [e for e in cands if e.kind == "srg"]
                if pool:
                    kind = "srg"
            if not pool:
                if kind != "automation":
                    sel.skipped.append({"product_key": key, "kind": kind,
                                        "reason": f"not matching: no {kind.replace('_', ' ')} for this product"})
                continue
            live = [e for e in pool if not e.sunset]
            for e in pool:
                if e.sunset:
                    sel.skipped.append(_row(e, None, reason="sunset: DISA has retired this release"))
            if not live:
                continue
            allowed = [e for e in live if ok(e)]
            for e in live:
                if not ok(e):
                    sel.skipped.append(_row(e, None, reason=f"external host {e.host}: not on the allow-list"))
            best = _newest(allowed)
            if best is None:
                continue
            for e in allowed:
                if e is not best and kind != "automation":
                    sel.skipped.append(_row(e, None, reason=f"superseded by {best.filename}"))
            wanted.append((best, want))
    if include_compilation:
        comp = _newest(e for e in entries if e.kind == "compilation" and not e.sunset and ok(e)
                       and (e.product_key or "").lower().startswith("srg-stig_library"))
        if comp is not None:
            wanted.append((comp, None))

    for e, want in wanted:
        row = _row(e, want)
        sel.wanted.append(row)
        hv = _held_version(held, e.product_key or "", e.kind)
        exact = any(r.get("filename") == e.filename for r in held)
        if exact or (hv is not None and e.version is not None and hv >= tuple(e.version)):
            sel.current.append(dict(row, held_version=list(hv) if hv else None))
        else:
            sel.updates.append(dict(row, held_version=list(hv) if hv else None))
    return sel
