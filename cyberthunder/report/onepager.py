"""Commander one-pager: BLUF, open findings by host and CAT, intrusion indicators, decisions, top risks.

Every number is computed from findings on disk, the approval gate and the audit chain. Nothing here is
written by a model; model text appears only as the quoted `explanation.risk` of a finding, with its citations.
"""
from __future__ import annotations

import shlex
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from cyberthunder.control.approvals import Proposal, ProposalState
from cyberthunder.findings.schema import RE_ATTACK, Finding, Severity
from cyberthunder.report.render import ReportError, render

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext

TOP_RISKS = 5
CITATION_ORDER = ("stig_id", "cve", "iavm", "attack", "cci", "group", "stig_rule")


# -- shared helpers (also used by poam, checklist, score) ---------------------------------
def is_hunt(f: Finding) -> bool:
    return f.source.lower().startswith("hunt") or "hunt" in [t.lower() for t in f.tags]


def attack_ids(f: Finding) -> list[str]:
    return [c for c in f.citations if RE_ATTACK.fullmatch(c)]


def resolve_scan(ctx: "AppContext", scan_id: str | None) -> tuple[str, dict, list[Finding]]:
    """Return (scan_id, run dict, findings). Raises ReportError with an instruction when nothing was scanned."""
    sid = scan_id or ctx.store.latest_scan_id()
    if not sid:
        raise ReportError("no scan runs on this node; run a scan first (cyberthunder scan run)")
    run = ctx.store.load_scan_run(sid) or {}
    findings = ctx.store.load_findings(sid)
    if not run and not findings:
        raise ReportError(f"scan {sid!r} not found under {ctx.store.scans_dir}")
    return sid, run, findings


def latest_proposals(ctx: "AppContext") -> dict[str, Proposal]:
    """Newest proposal per finding id (a finding can be re-proposed after a denial or rollback)."""
    out: dict[str, Proposal] = {}
    for p in sorted(ctx.gate.list(), key=lambda p: p.created_at):
        out[p.finding_id] = p
    return out


def state_time(p: Proposal, state: ProposalState) -> str | None:
    for h in reversed(p.history):
        if h.get("state") == state.value:
            return h.get("ts")
    return None


def _cat_label(sev: Severity) -> str:
    return sev.cat if sev.cat != "-" else sev.value


def _ordered_citations(f: Finding, extra: list[str] | None = None) -> list[str]:
    typed = {r.id: r.system for r in f.references}
    cites = list(dict.fromkeys([*f.citations, *(extra or [])]))
    cites.sort(key=lambda c: CITATION_ORDER.index(typed[c]) if typed.get(c) in CITATION_ORDER else len(CITATION_ORDER))
    return cites[:4]


def _link_line(ctx: "AppContext") -> str | None:
    """One line about the constrained link and the outbox. Duck-typed: the ingest module is built separately."""
    ing = getattr(ctx, "ingest", None)
    if ing is None:
        return None
    try:
        st = None
        link = getattr(ing, "link", None)
        for name in ("status", "state"):
            attr = getattr(link, name, None)
            st = attr() if callable(attr) else attr
            if st is not None and hasattr(st, "to_dict"):
                st = st.to_dict()
            if isinstance(st, dict):
                break
            st = None
        st = st or {}
        kbps = st.get("kbps", ctx.settings.link_kbps)
        connected = st.get("connected", ctx.settings.link_connected)
        waiting = None
        ob = getattr(ing, "outbox", None)
        for name in ("pending", "list"):
            fn = getattr(ob, name, None)
            if callable(fn):
                got = fn()
                waiting = len(got.get("pending", [])) if isinstance(got, dict) else len(list(got))
                break
        if waiting is None:
            waiting = len([p for p in ctx.store.outbox_dir.iterdir() if p.is_file()])
        state = "connected" if connected else "disconnected"
        return (f"Link {state} at {kbps:g} kbps. Outbox: {waiting} item(s) waiting to sync"
                f"{' (will send on reconnect)' if not connected and waiting else ''}.")
    except Exception as e:  # noqa: BLE001  - a broken link module must not stop the report
        return f"Link and outbox status unavailable: {e}"


# -- the report ---------------------------------------------------------------------------
def build_commander(ctx: "AppContext", scan_id: str | None, fmt: str) -> dict:
    sid, run, findings = resolve_scan(ctx, scan_id)
    v = ctx.audit.verify()
    open_f = [f for f in findings if f.is_open]
    hunt = [f for f in open_f if is_hunt(f)]
    props = ctx.gate.list()

    # open findings by host and CAT
    hosts: dict[str, dict] = {}
    for f in open_f:
        row = hosts.setdefault(f.host, {"host": f.host, "high": 0, "medium": 0, "low": 0, "total": 0, "hunt": 0})
        if f.severity.value in ("high", "medium", "low"):
            row[f.severity.value] += 1
        row["total"] += 1
        row["hunt"] += 1 if is_hunt(f) else 0
    by_host = sorted(hosts.values(), key=lambda r: (-r["high"], -r["total"], r["host"]))
    cat_totals = {k: sum(r[k] for r in by_host) for k in ("high", "medium", "low")}

    # decisions
    counts = {s.value: 0 for s in ProposalState}
    for p in props:
        counts[p.state.value] += 1
    verified = [{"title": p.title, "host": p.host, "decided_by": p.decided_by,
                 "verified_at": state_time(p, ProposalState.VERIFIED)}
                for p in props if p.state == ProposalState.VERIFIED]
    verified.sort(key=lambda r: r["verified_at"] or "")

    # top risks
    ranked = sorted(open_f, key=lambda f: (-f.severity.rank, not is_hunt(f), f.host, f.title))[:TOP_RISKS]
    top = []
    for f in ranked:
        ex = ctx.store.load_explanation(f.id) or {}
        top.append({"cat": _cat_label(f.severity), "host": f.host, "title": f.title,
                    "risk": (ex.get("risk") or "").strip(),
                    "citations": _ordered_citations(f, ex.get("citations"))})

    # BLUF: three sentences computed from the data
    scanned = len({f.host for f in findings}) or len(run.get("targets", []))
    s1 = (f"{len(open_f)} open finding(s) on {scanned} host(s): {cat_totals['high']} CAT I, "
          f"{cat_totals['medium']} CAT II, {cat_totals['low']} CAT III.")
    if hunt:
        tech = sorted({a for f in hunt for a in attack_ids(f)})
        s2 = (f"{len(hunt)} intrusion indicator(s) on {', '.join(sorted({f.host for f in hunt}))}"
              f"{' (ATT&CK ' + ', '.join(tech) + ')' if tech else ''} need immediate review.")
    else:
        s2 = "No intrusion indicators were found by the hunt checks."
    chain = "intact" if v.ok else "BROKEN"
    s3 = (f"{counts['verified']} change(s) verified, {counts['proposed']} awaiting approval, "
          f"{counts['rolled_back']} rolled back; audit chain {chain} over {v.count} records.")

    nxt = []
    if not v.ok:
        nxt.append(f"Investigate the audit chain before trusting this report: {v}.")
    if ctx.killswitch.is_engaged():
        nxt.append("Kill switch is engaged: no change will be applied until an operator releases it.")
    if hunt:
        nxt.append("Review intrusion indicators on " + ", ".join(sorted({f.host for f in hunt}))
                   + " with the system owner before any remediation that could destroy evidence.")
    if counts["proposed"]:
        nxt.append(f"Approve or deny {counts['proposed']} pending proposal(s) in the approval queue.")
    proposed_ids = {p.finding_id for p in props if p.state not in (ProposalState.DENIED, ProposalState.CANCELLED)}
    uncovered = [f for f in open_f if f.severity == Severity.HIGH and f.id not in proposed_ids]
    if uncovered:
        nxt.append(f"{len(uncovered)} CAT I finding(s) have no proposed fix: remediate by hand or add a library entry.")
    if counts["rolled_back"] or counts["failed"]:
        nxt.append(f"Review {counts['rolled_back'] + counts['failed']} rolled back or failed change(s) before re-proposing.")
    nxt.append("Rescan after approved changes to confirm closure, then regenerate this report.")

    cmd = " ".join(["python -m cyberthunder", "--state-dir", shlex.quote(str(ctx.store.root)),
                    "report commander", "--scan-id", sid, "--format", fmt])
    return {
        "node": ctx.settings.node, "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "scan_id": sid, "trigger": run.get("trigger", "unknown"),
        "audit": {"ok": v.ok, "count": v.count, "head": v.head, "detail": str(v)},
        "bluf": [s1, s2, s3], "by_host": by_host,
        "hunt": [{"host": f.host, "title": f.title, "attack": attack_ids(f)}
                 for f in sorted(hunt, key=lambda f: (f.host, f.title))],
        "decisions": counts, "verified": verified, "top": top,
        "link": _link_line(ctx), "next_actions": nxt, "command": cmd,
    }


def render_commander(ctx: "AppContext", scan_id: str | None, fmt: str) -> tuple[str, dict]:
    data = build_commander(ctx, scan_id, fmt)
    return render("commander", fmt, r=data), data
