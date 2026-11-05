"""Which inventory assets does a STIG release or a bulletin apply to?

A fixed table maps benchmark ids, DISA STIG titles and product names to an asset type and optional
OS/product matchers. Each inventory target is checked against the best facts available, in order:

  1. facts saved by the latest scan of that target (scans/<id>/raw/<target_id>/collected.json, facts.*)
  2. target.options hints (os, os_name, os_version, product)
  3. the latest discovery record linked to the target (os_guess, CDP platform, kube node OS image)
  4. asset type alone (reported as basis "type": run a scan to confirm)

Scan facts or hints that contradict the matcher exclude the target. A discovery guess that names a
different OS family does not exclude (nmap OS guesses such as "Linux 5.0 - 5.14" are too coarse), but
one that names the right family at a different major version does (a node reporting "Rocky Linux 8.9"
is not a RHEL 9 host). Missing facts never exclude.
"""
from __future__ import annotations

import glob
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext
    from cyberthunder.inventory.targets import Target
    from cyberthunder.store import StateStore


@dataclass(frozen=True)
class Rule:
    name: str
    asset_type: str
    keys: tuple[str, ...]                 # benchmark ids / titles / product names that select this rule
    os_pattern: str | None = None         # regex against os_name (+ model, platform text)
    version_pattern: str | None = None    # regex against os_version (or the version found in os_name)


BENCHMARKS: tuple[Rule, ...] = (
    Rule("Red Hat Enterprise Linux 9", "linux",
         ("xccdf_org.ssgproject.content_benchmark_RHEL-9", "RHEL_9_STIG", "Red Hat Enterprise Linux 9"),
         r"red ?hat|rhel|rocky|alma|centos stream", r"^9(\.|$)"),
    Rule("Red Hat Enterprise Linux 8", "linux",
         ("xccdf_org.ssgproject.content_benchmark_RHEL-8", "RHEL_8_STIG", "Red Hat Enterprise Linux 8"),
         r"red ?hat|rhel|rocky|alma|centos stream", r"^8(\.|$)"),
    Rule("Canonical Ubuntu 22.04 LTS", "linux",
         ("xccdf_org.ssgproject.content_benchmark_UBUNTU-22.04", "U_CAN_Ubuntu_22-04_LTS_STIG",
          "Canonical Ubuntu 22.04", "Ubuntu 22.04"),
         r"ubuntu", r"^22\.04"),
    Rule("Microsoft Windows 11", "windows", ("MS_Windows_11_STIG", "Microsoft Windows 11", "Windows 11"),
         r"windows 11"),
    Rule("Microsoft Windows Server 2022", "windows",
         ("MS_Windows_Server_2022_STIG", "Microsoft Windows Server 2022", "Windows Server 2022"),
         r"server 2022"),
    Rule("Cisco IOS XE Switch NDM", "cisco_ios", ("Cisco IOS XE Switch NDM", "Cisco_IOS-XE_Switch_NDM_STIG"),
         r"ios[ -]?xe|cat9k|c9\d00|catalyst"),
    Rule("Cisco IOS XE Router", "cisco_ios",
         ("Cisco IOS XE Router NDM", "Cisco IOS XE Router RTR", "Cisco IOS XE Router", "Cisco_IOS-XE_Router"),
         r"ios[ -]?xe|isr|asr|csr|c8\d00"),
    Rule("Kubernetes", "kubernetes", ("Kubernetes", "Kubernetes_STIG")),
)

PRODUCTS: tuple[Rule, ...] = (
    Rule("openssh", "linux", ("openssh",)),
    Rule("kernel", "linux", ("kernel", "linux_kernel", "linux kernel")),
    Rule("iosxe", "cisco_ios", ("iosxe", "ios-xe", "ios xe"), r"ios[ -]?xe|cat9k|c9\d00|catalyst"),
    Rule("k3s", "kubernetes", ("k3s",), r"k3s"),
)


@dataclass
class Applicable:
    target: "Target"
    rule: str
    basis: str          # facts | hint | discovery | type
    reason: str
    facts: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"target": self.target.to_dict(), "rule": self.rule, "basis": self.basis, "reason": self.reason,
                "facts": self.facts}


def _norm(s: str) -> str:
    return re.sub(r"[\s_\-]+", " ", (s or "").lower()).strip()


def find_rule(benchmark_id: str | None = None, title: str | None = None, product: str | None = None) -> Rule:
    if product:
        p = _norm(product)
        for r in PRODUCTS:
            if any(_norm(k) == p for k in r.keys):
                return r
        raise ValueError(f"no applicability rule for product {product!r}; known: {[r.name for r in PRODUCTS]}")
    key = benchmark_id or title
    if not key:
        raise ValueError("give a benchmark id, a STIG title or a product name")
    k = _norm(key)
    for r in BENCHMARKS:                       # exact id/title first
        if any(_norm(x) == k for x in r.keys):
            return r
    # titles arrive decorated: "Red Hat Enterprise Linux 9 Security Technical Implementation Guide"
    best = None
    for r in BENCHMARKS:
        for x in r.keys:
            nx = _norm(x)
            if nx in k and (best is None or len(nx) > best[1]):
                best = (r, len(nx))
    if best:
        return best[0]
    raise ValueError(f"no applicability rule for {key!r}; known: {[r.name for r in BENCHMARKS]}")


def latest_scan_facts(state_root: Path, target_id: str, store: "StateStore | None" = None) -> dict | None:
    """Facts from the newest scan that collected this target, or None. collected.json files are the scanner's
    working files on disk; the run record that dates them is a store document, so the store reads it."""
    if store is None:
        from cyberthunder.store import StateStore
        store = StateStore(state_root)
    scans = Path(state_root) / "scans"
    hits = []
    # target ids come from operators; a bracket or asterisk in one must not widen the match
    for p in scans.glob(f"*/raw/{glob.escape(target_id)}/collected.json"):
        stamp = ""
        try:
            stamp = (store.load_scan_run(p.parents[2].name) or {}).get("started_at", "")
        except (ValueError, OSError):
            stamp = ""
        hits.append((stamp, p.stat().st_mtime, p))
    for _, _, p in sorted(hits, reverse=True):
        try:
            facts = (json.loads(p.read_text(encoding="utf-8")) or {}).get("facts") or {}
        except (ValueError, OSError):
            continue
        if facts:
            return facts
    return None


def _hint_facts(target: "Target") -> dict:
    o = target.options or {}
    out = {}
    if o.get("os_name") or o.get("os"):
        out["os_name"] = str(o.get("os_name") or o.get("os"))
    if o.get("os_version"):
        out["os_version"] = str(o["os_version"])
    if o.get("product"):
        out["model"] = str(o["product"])
    return out


def _discovery_facts(discovered: dict | None) -> dict:
    if not discovered:
        return {}
    f = discovered.get("facts", {})
    text = " ".join(x for x in (discovered.get("os_guess"), f.get("platform"), f.get("software"),
                                f.get("system_description"), f.get("os_image"), f.get("kubelet_version")) if x)
    return {"os_name": text} if text else {}


def _matches(rule: Rule, facts: dict) -> tuple[bool | None, str]:
    ok, why, _ = _match(rule, facts)
    return ok, why


def _match(rule: Rule, facts: dict) -> tuple[bool | None, str, str]:
    """(decision, why, basis of the decision). The decision is True/False when facts decide and None when
    they say nothing relevant; the basis is "os" for a family match/mismatch, "version" for a version one."""
    os_text = " ".join(str(facts.get(k) or "") for k in ("os_name", "model", "kernel")).strip()
    if not os_text:
        return None, "", ""
    if rule.os_pattern and not re.search(rule.os_pattern, os_text, re.I):
        return False, f"'{os_text[:80]}' does not match {rule.name}", "os"
    if rule.version_pattern:
        ver = str(facts.get("os_version") or "")
        if not ver:
            m = re.search(r"\b(\d+(?:\.\d+)?)\b", facts.get("os_name") or "")
            ver = m.group(1) if m else ""
        if not ver:
            return None, "", ""
        if not re.search(rule.version_pattern, ver):
            return False, f"version {ver} does not match {rule.name}", "version"
        return True, f"'{os_text[:80]}' version {ver}", "version"
    return True, f"'{os_text[:80]}'", "os"


def applicable_for(rule: Rule, targets: list["Target"], state_root: Path,
                   discovered_by_target: dict[str, dict] | None = None,
                   store: "StateStore | None" = None) -> list[Applicable]:
    if store is None:
        from cyberthunder.store import StateStore
        store = StateStore(state_root)
    out = []
    for t in targets:
        if t.asset_type != rule.asset_type:
            continue
        if not rule.os_pattern and not rule.version_pattern:
            out.append(Applicable(t, rule.name, "type", f"{t.asset_type} target; {rule.name} applies to every one"))
            continue
        decided = False
        for basis, facts in (("facts", latest_scan_facts(state_root, t.id, store) or {}),
                             ("hint", _hint_facts(t)),
                             ("discovery", _discovery_facts((discovered_by_target or {}).get(t.id)))):
            ok, why, what = _match(rule, facts)
            if ok is None:
                continue
            if ok is False and basis == "discovery" and what == "os":
                # a network OS guess ("Linux 5.0 - 5.14") is too coarse to rule a target out by family;
                # the right family at another major version is specific enough to exclude it
                continue
            decided = True
            if ok:
                out.append(Applicable(t, rule.name, basis, f"{t.asset_type} target; {why}", facts))
            break
        if not decided:
            out.append(Applicable(t, rule.name, "type",
                                  f"{t.asset_type} target; OS not yet known, scan to confirm {rule.name}"))
    return out


def applicable_targets(ctx: "AppContext", benchmark_id: str | None = None, title: str | None = None,
                       product: str | None = None) -> list[Applicable]:
    """Entry point for ingest (STIG deltas, bulletins): which inventory targets does this apply to?"""
    rule = find_rule(benchmark_id, title, product)
    discovered: dict[str, dict] = {}
    try:
        for a in (ctx.store.read_json(Path(ctx.store.root) / "discovery" / "assets.json", {}) or {}).values():
            if a.get("inventory_target_id"):
                discovered[a["inventory_target_id"]] = a
    except (ValueError, OSError, AttributeError):
        discovered = {}
    return applicable_for(rule, ctx.inventory.all(), Path(ctx.store.root), discovered, store=ctx.store)
