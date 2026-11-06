"""Detection score: how many of the seeded misconfigurations and intrusion indicators did the scan find.

Reads every range/answer_key/*.json. Each item has id, kind, what, fix_ref and an identifier: `check_id`
(older files use `stig_id`, the container and Kubernetes keys use `rule`, and some intrusion items carry
only a `detector` name). An item counts as found when an OPEN finding (a passing check is not a detection)
matches it by one of:
  - finding.rule_version == check_id        (a STIG ID, or the adapter's rule name)
  - finding.rule_id == check_id, ends with ":" + check_id, or starts with check_id + ":"
    (hunt ids put the object after the check: hunt:linux:cron_suspicious:/etc/cron.d/.sysupdate)
  - check_id appears in finding.citations   (CVE, CCI, ATT&CK, IAVM ...)
When the item also names an object (`container`, `object`), the finding's rule_id must end with it, so a
check that fires on two containers is credited to the one the key seeded. Items that carry only a detector
name match a finding whose rule_id is, or starts with, that detector name, or whose fix_ref equals the
item's fix_ref. A trailing run of x in a check id ("RHEL-09-232xxx") is a wildcard for the digits it replaces.

Scope: a key's `target` (or its `sim_target` on the simulated range) names the host its items are scored
against. When neither host is in the scan the items are reported as not scanned rather than matched against
other hosts. Items with a discovery:* check id are scored against the findings of the latest finished
discovery sweep, and an item `address` that is an IP must be the discovered host.

Keep answer keys out of any prompt: this module is for the scoreboard, not for the model.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

from cyberthunder.findings.schema import Finding
from cyberthunder.report.onepager import resolve_scan
from cyberthunder.report import access
from cyberthunder.report.render import ReportError

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext


def default_key_dir(ctx: "AppContext | None" = None) -> Path:
    env = os.environ.get("CT_ANSWER_KEY_DIR")
    if env:
        return Path(env)
    if ctx is not None and (Path(ctx.store.root) / "answer_key").is_dir():
        return Path(ctx.store.root) / "answer_key"
    return Path(__file__).resolve().parents[2] / "range" / "answer_key"


def load_answer_keys(key_dir: str | Path) -> tuple[list[dict], list[str]]:
    """Return (items, targets). Raises ReportError when the directory or its keys are unusable."""
    d = Path(key_dir)
    if not d.is_dir():
        raise ReportError(f"answer key directory not found: {d} (set CT_ANSWER_KEY_DIR or pass --key-dir)")
    items: list[dict] = []
    targets: list[str] = []
    files = sorted(d.glob("*.json"))
    if not files:
        raise ReportError(f"no answer key files (*.json) in {d}")
    for p in files:
        try:
            doc = json.loads(p.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as e:
            raise ReportError(f"{p.name} is not valid JSON: {e}") from e
        if doc.get("target"):
            targets.append(str(doc["target"]))
        for raw in doc.get("items", []):
            detector = raw.get("detector")
            check_id = raw.get("check_id") or raw.get("stig_id") or raw.get("rule") or None
            items.append({
                "id": str(raw["id"]), "kind": raw.get("kind", "misconfig"), "what": raw.get("what", ""),
                "check_id": check_id, "detector": detector, "fix_ref": raw.get("fix_ref"), "key": p.stem,
                "target": doc.get("target"), "sim_target": doc.get("sim_target"),
                "qualifier": raw.get("container") or raw.get("object") or None,
                "address": raw.get("address"),
                "authorization_scopes": doc.get("authorization_scopes"),
            })
    return items, targets


def _id_pattern(check_id: str) -> re.Pattern | None:
    m = re.fullmatch(r"(.*?)(x+)", check_id, flags=re.IGNORECASE)
    if m and m.group(1) and m.group(1)[-1].isdigit():
        return re.compile(re.escape(m.group(1)) + r"\d{%d}" % len(m.group(2)))
    return None


def _qualified(item: dict, f: Finding) -> bool:
    """The finding is on the object the item names (container, Kubernetes object, discovered address)."""
    q = item.get("qualifier")
    if q:
        # On an in-process control plane (k3s) the apiserver/kubelet are reported node-scoped
        # (rule id ends with ":-/node/<node>"), not as the static pods the simulated key names under
        # kube-system/pod/. Credit either representation for a control-plane object.
        cp_node = q.startswith("kube-system/pod/") and bool(re.search(r":-/node/[^/]+$", f.rule_id))
        if not (cp_node or f.rule_id == q or f.rule_id.endswith(":" + q) or q in f.tags):
            return False
    addr = item.get("address")
    if addr and f.rule_id.startswith("discovery:"):
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            return True                       # a description ("first linux target"), not an address
        return f.host in (addr, "discovered:" + addr)
    return True


def _matches(item: dict, f: Finding) -> bool:
    """One rule for every answer key; see the module docstring."""
    if not _qualified(item, f):
        return False
    cid = item["check_id"]
    if cid:
        pat = _id_pattern(cid)
        if pat is not None:
            if any(pat.fullmatch(x) for x in (f.rule_version, f.rule_id, *f.citations) if x):
                return True
        elif (f.rule_version == cid or f.rule_id == cid or f.rule_id.endswith(":" + cid)
              or f.rule_id.startswith(cid + ":") or cid in f.citations):
            return True
    else:
        # detector-only item (intrusion hunts): match a detector name
        for det in re.split(r"\s*\+\s*", item.get("detector") or ""):
            if det and (f.rule_id == det or f.rule_id.startswith((det + ".", det + ":")) or f.rule_id.endswith(":" + det)):
                return True
    # Fallback for any item: the finding carries the exact vetted fix the item maps to. This credits a
    # real-range finding (e.g. an OpenSCAP rule id) to an item whose check_id is the simulator's native id
    # when both resolve to the same fix, without loosening the id match itself.
    return bool(item.get("fix_ref") and f.fix_ref == item["fix_ref"])


def _discovery_findings(ctx: "AppContext") -> tuple[list[Finding], bool]:
    """(open findings of the latest finished discovery sweep, whether such a sweep exists)."""
    svc = getattr(ctx, "discovery", None)
    if svc is None:
        return [], False
    try:
        runs = list(svc.runs())
        for run in runs:
            if run.status == "finished":
                access.artifact(ctx, getattr(run, "authorization_scopes", None))
        swept = any(r.status == "finished" for r in runs)
        findings = list(svc.findings()) if swept else []
        access.observations(ctx, findings)
        return [f for f in findings if f.is_open], swept
    except PermissionError:
        raise
    except Exception:  # noqa: BLE001  - a broken discovery store must not stop the score card
        return [], False


def time_to_plan_s(ctx: "AppContext", run: dict) -> float | None:
    """Seconds from the scan starting to the first proposal created after it, from the audit log."""
    from datetime import datetime
    access.audit(ctx)
    start = run.get("started_at")
    if not start:
        return None
    try:
        t0 = datetime.fromisoformat(start)
        for rec in ctx.audit.records():
            if rec.get("action") == "proposal.create":
                t1 = datetime.fromisoformat(rec["ts"])
                if t1 >= t0:
                    return max((t1 - t0).total_seconds(), 0.0)
    except (ValueError, TypeError, KeyError):   # unparseable, or naive vs aware timestamps
        return None
    return None


def score(ctx: "AppContext", scan_id: str | None = None, key_dir: str | Path | None = None) -> dict:
    sid, run, findings = resolve_scan(ctx, scan_id)
    items, _targets = load_answer_keys(key_dir or default_key_dir(ctx))
    for item in items:
        access.artifact(ctx, item["authorization_scopes"],
                        targets=[t for t in (item.get("target"), item.get("sim_target")) if t])
    open_f = [f for f in findings if f.is_open]
    disc_f, swept = _discovery_findings(ctx)
    scanned = {f.host for f in findings} | set(run.get("targets") or [])
    out_items, by_kind = [], {}
    for it in items:
        # an answer key names a range host: score its items against that host only, so one host's finding
        # never satisfies another host's key; a host that was not scanned is reported, not guessed
        if (it["check_id"] or "").startswith("discovery:"):
            pool, covered = disc_f, swept
        else:
            host = next((h for h in (it.get("target"), it.get("sim_target")) if h and h in scanned), None)
            if host is not None:
                pool, covered = [f for f in open_f + disc_f if f.host == host], True
            elif it.get("target"):
                pool, covered = [], False
            else:
                pool, covered = open_f + disc_f, True
        ids = [f.id for f in pool if _matches(it, f)]
        out_items.append({"id": it["id"], "kind": it["kind"], "what": it["what"], "found": bool(ids),
                          "finding_ids": ids, "key": it["key"], "scanned": covered})
        k = by_kind.setdefault(it["kind"], {"seeded": 0, "found": 0, "share": 0.0})
        k["seeded"] += 1
        k["found"] += 1 if ids else 0
    for k in by_kind.values():
        k["share"] = round(k["found"] / k["seeded"], 4) if k["seeded"] else 0.0
    seeded = len(out_items)
    found = sum(1 for i in out_items if i["found"])
    return {"scan_id": sid, "seeded": seeded, "found": found,
            "not_scanned": sum(1 for i in out_items if not i["scanned"]),
            "share": round(found / seeded, 4) if seeded else 0.0,
            "by_kind": by_kind, "items": out_items, "time_to_plan_s": time_to_plan_s(ctx, run)}
