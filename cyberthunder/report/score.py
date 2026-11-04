"""Detection score: how many of the seeded misconfigurations and intrusion indicators did the scan find.

Reads every range/answer_key/*.json. Each item has id, kind, what, fix_ref and check_id (older files use
`stig_id`, or only a `detector` name for intrusion items). An item counts as found when an OPEN finding
(a passing check is not a detection) matches it by one of:
  - finding.rule_version == check_id        (a STIG ID)
  - finding.rule_id == check_id, or ends with ":" + check_id
  - check_id appears in finding.citations   (CVE, CCI, ATT&CK, IAVM ...)
Items that carry only a detector name (the hunt items) match a finding whose rule_id is, or starts with,
that detector name, or whose fix_ref equals the item's fix_ref. A trailing run of x in a check id
("RHEL-09-232xxx") is a wildcard for the digits it replaces.

Keep answer keys out of any prompt: this module is for the scoreboard, not for the model.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

from cyberthunder.findings.schema import Finding
from cyberthunder.report.onepager import resolve_scan
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
            check_id = raw.get("check_id") or raw.get("stig_id") or None
            items.append({
                "id": str(raw["id"]), "kind": raw.get("kind", "misconfig"), "what": raw.get("what", ""),
                "check_id": check_id, "detector": detector, "fix_ref": raw.get("fix_ref"), "key": p.stem,
                "target": doc.get("target"),
            })
    return items, targets


def _id_pattern(check_id: str) -> re.Pattern | None:
    m = re.fullmatch(r"(.*?)(x+)", check_id, flags=re.IGNORECASE)
    if m and m.group(1) and m.group(1)[-1].isdigit():
        return re.compile(re.escape(m.group(1)) + r"\d{%d}" % len(m.group(2)))
    return None


def _matches(item: dict, f: Finding) -> bool:
    cid = item["check_id"]
    if cid:
        pat = _id_pattern(cid)
        if pat is not None:
            return any(pat.fullmatch(x) for x in (f.rule_version, f.rule_id, *f.citations) if x)
        return (f.rule_version == cid or f.rule_id == cid or f.rule_id.endswith(":" + cid)
                or cid in f.citations)
    # detector-only item (intrusion hunts): match a detector name or the vetted fix it maps to
    for det in re.split(r"\s*\+\s*", item.get("detector") or ""):
        if det and (f.rule_id == det or f.rule_id.startswith((det + ".", det + ":")) or f.rule_id.endswith(":" + det)):
            return True
    return bool(item.get("fix_ref") and f.fix_ref == item["fix_ref"])


def time_to_plan_s(ctx: "AppContext", run: dict) -> float | None:
    """Seconds from the scan starting to the first proposal created after it, from the audit log."""
    from datetime import datetime
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
    items, targets = load_answer_keys(key_dir or default_key_dir(ctx))
    open_f = [f for f in findings if f.is_open]
    by_target = {t: [f for f in open_f if f.host == t] for t in set(targets)}
    out_items, by_kind = [], {}
    for it in items:
        # an answer key names a range host: score its items against that host only, so one host's finding
        # never satisfies another host's key; fall back to all hosts if the names differ
        pool = by_target.get(it.get("target") or "") or open_f
        ids = [f.id for f in pool if _matches(it, f)]
        out_items.append({"id": it["id"], "kind": it["kind"], "what": it["what"], "found": bool(ids),
                          "finding_ids": ids, "key": it["key"]})
        k = by_kind.setdefault(it["kind"], {"seeded": 0, "found": 0, "share": 0.0})
        k["seeded"] += 1
        k["found"] += 1 if ids else 0
    for k in by_kind.values():
        k["share"] = round(k["found"] / k["seeded"], 4) if k["seeded"] else 0.0
    seeded = len(out_items)
    found = sum(1 for i in out_items if i["found"])
    return {"scan_id": sid, "seeded": seeded, "found": found,
            "share": round(found / seeded, 4) if seeded else 0.0,
            "by_kind": by_kind, "items": out_items, "time_to_plan_s": time_to_plan_s(ctx, run)}
