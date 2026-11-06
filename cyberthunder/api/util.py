"""Helpers shared by the route modules: identity, response shapes (Finding+, Proposal+, ScanRun),
background work, optional services, and the multipart reader used by ingest uploads."""
from __future__ import annotations

import csv
import importlib
import json
import logging
import re
import threading
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterable

from fastapi import Depends, Header, HTTPException

from cyberthunder.api.deps import get_actor, get_ctx
from cyberthunder.control.approvals import AGENT_ACTORS, Proposal
from cyberthunder.findings.current import CurrentFindings, policy_block_reason, timestamp
from cyberthunder.findings.reassessment import ReassessmentView
from cyberthunder.findings.schema import (
    RE_CVE, RE_GROUP_ID, RE_STIG_ID, RE_STIG_RULE, Finding, Severity, Status, summarize,
)

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext

log = logging.getLogger(__name__)

TERMINAL_STATES = {"denied", "cancelled", "verified", "rolled_back", "failed"}
LIVE_STATES = {"proposed", "approved", "applying", "applied"}


# -- identity ---------------------------------------------------------------------------
# Prefixed machine identities ("agent:planner", "llm:explain") and the standing-policy identity ("policy:...")
# are never a person, whatever follows the colon.
MACHINE_PREFIXES = tuple(f"{a}:" for a in sorted(AGENT_ACTORS)) + ("policy:",)


def require_actor(x_actor: str | None = Header(default=None)) -> str:
    """Mutating requests must name the human acting. Machine identities are refused here so they can never
    reach an approval, denial, kill switch or policy edge through the API."""
    from cyberthunder.control.principal import current_principal
    principal = current_principal()
    if principal is not None and principal.verified:
        return principal.actor
    if not (x_actor or "").strip():
        raise HTTPException(400, "X-Actor header is required: type your name in Settings before making changes")
    from cyberthunder.control.identity import require_human
    try:
        actor = require_human(get_actor(x_actor))
    except PermissionError as e:
        raise HTTPException(400, str(e)) from None
    if len(actor) > 128:
        raise HTTPException(400, "actor name too long")
    return actor


CtxDep = Depends(get_ctx)
ActorDep = Depends(require_actor)


# -- optional services ----------------------------------------------------------------------
def demo_module():
    """cyberthunder.demo when it is part of this build, else None."""
    try:
        return importlib.import_module("cyberthunder.demo")
    except ModuleNotFoundError as e:
        if e.name and "cyberthunder.demo".startswith(e.name):
            return None
        raise


def call_first(obj: Any, names: Iterable[str], *args, **kwargs) -> Any:
    """Call the first method of `obj` that exists. Raises NotImplementedError when none does."""
    for n in names:
        fn = getattr(obj, n, None)
        if callable(fn):
            return fn(*args, **kwargs)
    raise NotImplementedError


def to_plain(obj: Any) -> Any:
    """Dataclass-ish result -> JSON-able structure."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if isinstance(obj, dict):
        return {k: to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_plain(v) for v in obj]
    if isinstance(obj, Path):
        return str(obj)
    return obj


# -- background work ------------------------------------------------------------------------
_threads: list[threading.Thread] = []
_threads_lock = threading.Lock()


def run_background(fn: Callable[[], Any], name: str, *, early_wait: float = 0.2) -> threading.Thread:
    """Run fn in a daemon thread. If it fails within `early_wait` seconds (missing feature, illegal state,
    kill switch, scope) the exception is re-raised here so the caller gets a real status code, not a 202
    for work that never started."""
    box: dict[str, BaseException] = {}

    def target() -> None:
        try:
            fn()
        except BaseException as e:  # noqa: BLE001  recorded for the caller and the log
            box["error"] = e
            log.warning("background task %s failed: %s", name, e)

    from contextvars import copy_context
    inherited = copy_context()
    t = threading.Thread(target=inherited.run, args=(target,), name=name, daemon=True)
    with _threads_lock:
        _threads[:] = [x for x in _threads if x.is_alive()]
        _threads.append(t)
    t.start()
    t.join(early_wait)
    if "error" in box:
        raise box["error"]
    return t


def wait_background(timeout: float = 10.0) -> None:
    """Join background work started by the API (tests and orderly shutdown)."""
    with _threads_lock:
        threads = list(_threads)
    for t in threads:
        t.join(timeout)


# -- shapes ----------------------------------------------------------------------------------
def scan_plus(run) -> dict:
    d = run.to_dict()
    d["progress"] = run.progress
    return d


def target_brief(ctx: "AppContext", target_id: str | None) -> dict | None:
    if not target_id:
        return None
    try:
        t = ctx.inventory.get(target_id)
    except KeyError:
        return {"id": target_id, "name": target_id, "asset_type": None, "simulated": False, "known": False}
    return {"id": t.id, "name": t.name, "asset_type": t.asset_type, "simulated": t.simulated}


def _explanation(ctx: "AppContext", finding_id: str) -> dict | None:
    try:
        e = ctx.explain.get(finding_id)
    except Exception as exc:  # noqa: BLE001  explanations are optional decoration
        log.debug("explanation lookup failed for %s: %s", finding_id, exc)
        return None
    return to_plain(e) if e is not None else None


def _fix_for(ctx: "AppContext", finding: Finding):
    try:
        return ctx.library.resolve(finding)
    except Exception as exc:  # noqa: BLE001
        log.debug("fix lookup failed for %s: %s", finding.id, exc)
        return None


def proposal_for(ctx: "AppContext", finding_id: str) -> Proposal | None:
    try:
        return ctx.engine.proposal_for_finding(finding_id)
    except Exception:  # noqa: BLE001  engine absent or skeleton: look in the gate directly
        ps = [p for p in ctx.gate.list() if p.finding_id == finding_id]
        live = [p for p in ps if p.state.value not in TERMINAL_STATES]
        return (live or ps or [None])[-1]


def _parse_ts(v: str | None) -> datetime | None:
    try:
        t = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def remediated_by(finding: Finding, p: Proposal | None) -> dict | None:
    return CurrentFindings([p] if p else []).assess(finding).remediated


def effective(finding: Finding, p: Proposal | None) -> Finding:
    return CurrentFindings([p] if p else []).assess(finding).finding


def current_proposals(ctx: "AppContext") -> dict[str, Proposal]:
    """finding id -> its current proposal (newest live one, else newest of any state), from one gate read."""
    try:
        props = list(ctx.gate.list())
    except Exception as exc:  # noqa: BLE001  a missing gate leaves findings as scanned
        log.debug("proposal listing failed: %s", exc)
        return {}
    out: dict[str, Proposal] = {}
    for p in props:
        from cyberthunder.security.resources import visible_record
        if not visible_record(ctx, p):
            continue
        cur = out.get(p.finding_id)
        if cur is None or p.state.value not in TERMINAL_STATES or cur.state.value in TERMINAL_STATES:
            out[p.finding_id] = p
    return out


def finding_assurance(ctx: "AppContext", finding: Finding, *, now=None, reviews=None) -> dict:
    from cyberthunder.findings.confidence import assess_for_context
    from cyberthunder.findings.review import ReviewService
    return {"confidence": assess_for_context(ctx, finding, now=now),
            "review": (reviews or ReviewService(ctx)).summary(finding, now=now)}


def finding_plus(ctx: "AppContext", finding: Finding, with_proposal: bool = True,
                 assurance: dict | None = None, *, lifecycle: CurrentFindings | None = None) -> dict:
    d = finding.to_dict()
    d["scanner_status"] = finding.status.value
    d.update(assurance if assurance is not None else finding_assurance(ctx, finding))
    d["categories"] = finding_categories(finding)
    d["cat"] = finding.severity.cat
    d["explanation"] = _explanation(ctx, finding.id)
    fix = _fix_for(ctx, finding)
    d["fix"] = fix.to_dict() if fix is not None else None
    current = (lifecycle or CurrentFindings.for_context(ctx)).assess(finding)
    d["status"] = current.finding.status.value
    d["remediated"] = current.remediated
    d["rollback"] = current.rollback
    d["needs_rescan"] = current.needs_rescan
    if with_proposal:
        p = proposal_for(ctx, finding.id)
        from cyberthunder.security.resources import visible_record
        if p is not None and (p.host != finding.host or not visible_record(ctx, p)):
            p = None
        d["proposal"] = {"id": p.id, "state": p.state.value} if p is not None else None
    return d


def proposal_plus(ctx: "AppContext", p: Proposal) -> dict:
    from cyberthunder.control.policy import evaluate_for_context

    d = p.to_dict()
    from cyberthunder.remediation.maintenance import MaintenanceService
    d["maintenance"] = MaintenanceService(ctx).summary(p)
    fix = ctx.library.get(p.fix_ref)
    d["fix"] = fix.to_dict() if fix is not None else None
    finding = None
    try:
        finding = ctx.store.get_finding(p.finding_id)
    except Exception as exc:  # noqa: BLE001
        log.debug("finding lookup failed for proposal %s: %s", p.id, exc)
    from cyberthunder.security.resources import visible_record
    if finding is not None and (finding.host != p.host or not visible_record(ctx, finding)):
        finding = None
    d["finding"] = finding_plus(ctx, finding, with_proposal=False) if finding is not None else None
    target = None
    try:
        target = ctx.inventory.get(p.host)
    except KeyError:
        pass
    policy = None
    if fix is not None and finding is not None and target is not None:
        try:
            policy = evaluate_for_context(ctx, fix, finding, target).to_dict()
            blocked = policy_block_reason(ctx, finding)
            if blocked:
                policy = {**policy, "auto_eligible": False, "reasons": [blocked]}
        except Exception as exc:  # noqa: BLE001  a bad policy rule must not hide the proposal
            policy = {"auto_eligible": False, "rule": None, "reasons": [f"policy evaluation failed: {exc}"]}
    d["policy"] = policy
    sev = finding.severity if finding is not None else Severity.UNKNOWN
    d["severity"] = sev.value
    d["cat"] = sev.cat
    d["target"] = target_brief(ctx, p.host)
    if d["target"] is not None and d["target"].get("asset_type") is None and fix is not None:
        d["target"]["asset_type"] = fix.asset_type
    return d


def get_proposal(ctx: "AppContext", pid: str) -> Proposal:
    try:
        p = ctx.gate.get(pid)
        from cyberthunder.security.resources import check_record
        check_record(ctx, p)
        return p
    except KeyError:
        if getattr(ctx.settings, "auth_mode", "dev") != "dev":
            raise PermissionError("proposal is unavailable to this account") from None
        raise KeyError(f"unknown proposal {pid!r}") from None


def get_finding(ctx: "AppContext", fid: str, scan_id: str | None = None) -> Finding:
    f = ctx.store.get_finding(fid, scan_id)
    if f is None:
        if getattr(ctx.settings, "auth_mode", "dev") != "dev":
            raise PermissionError("finding is unavailable to this account")
        raise KeyError(f"unknown finding {fid!r}")
    from cyberthunder.security.resources import check_record
    check_record(ctx, f)
    return f


# -- findings listing --------------------------------------------------------------------------
def _split(v: str | None) -> set[str]:
    return {x.strip().lower() for x in (v or "").split(",") if x.strip()}


MISSING = "__missing__"
CATEGORIES = ("stig", "cve", "hunt", "other")
SORT_FIELDS = {"default", "severity", "host", "asset_type", "category", "title", "rule_id", "rule_version", "source",
               "collected_at", "observed_at", "benchmark", "benchmark_release", "confidence", "review"}
REASSESSMENT_LABELS = {"not_reassessed": "Not reassessed", "no_known_gap": "No known gap", "unknown": "Unknown"}
CONFIDENCE_ORDER = {"low": 1, "medium": 2, "high": 3}
REVIEW_ORDER = {"unreviewed": 0, "needs_investigation": 1, "confirmed": 2, "false_positive": 3, "not_applicable": 4,
                "risk_accepted": 5, "risk_expired": 6, "risk_reopened": 7, "risk_revoked": 8}


def review_filter_values(review: dict) -> set[str]:
    values = {review.get("disposition", "unreviewed")}
    status = review.get("risk_acceptance_status", "none")
    if status in {"expired", "reopened", "revoked"}:
        values.add("risk_" + status)
    return values


def finding_categories(f: Finding) -> list[str]:
    """Classify identifiers and scanner provenance, never title keywords or severity."""
    systems = {r.system.strip().lower() for r in f.references if r.id.strip()}
    source = f.source.strip().lower()
    identifiers = " ".join(f.citations)
    stig = bool(systems & {"stig_rule", "stig_id"}) or any(
        re.search(pattern.pattern, identifiers, re.I) for pattern in (RE_STIG_RULE, RE_STIG_ID, RE_GROUP_ID)
    ) or source in {
        "evaluate-stig", "powerstig", "windows-stig", "ckl", "cklb",
    }
    # OpenSCAP and SCC also run non-STIG content. Require a STIG identifier or benchmark there.
    stig = stig or bool(re.search(r"(?:^|[^a-z])stig(?:$|[^a-z])", (f.benchmark or "").lower()))
    cve = "cve" in systems or bool(RE_CVE.search(identifiers.upper())) or source in {"cve", "nvd", "iavm"}
    hunt = source == "hunt" or bool(systems & {"attack", "mitre_attack"}) or bool(
        re.search(r"(?:^|[:/_-])hunt(?:$|[:/_-])", f.rule_id.lower()))
    categories = [name for name, match in (("stig", stig), ("cve", cve), ("hunt", hunt)) if match]
    return categories or ["other"]


def _facet_value(value: str | None) -> str:
    return (value or "").strip().casefold() or MISSING


def _filter_values(value: str | None) -> set[str]:
    """CSV quoting allows benchmark names and releases containing commas."""
    if not value or not value.strip():
        return set()
    try:
        rows = list(csv.reader([value], skipinitialspace=True, strict=True))
    except csv.Error as exc:
        raise ValueError(f"invalid filter list: {exc}") from None
    if len(rows) != 1 or any(not item.strip() for item in rows[0]):
        raise ValueError("filter lists must contain non-empty values")
    return {_facet_value(item) for item in rows[0]}


def finding_facets(findings: list[Finding], assurance: dict | None = None, *, reassessments: dict | None = None) -> dict:
    """Options and counts from the complete view, independent of filters and pagination."""
    facets: dict[str, dict[str, dict]] = {name: {} for name in (
        "host", "asset_type", "source", "status", "severity", "category", "benchmark", "benchmark_release")}
    for f in findings:
        for name, options in facets.items():
            values = finding_categories(f) if name == "category" else [getattr(f, name)]
            for value in values:
                if isinstance(value, (Status, Severity)):
                    value = value.value
                key = _facet_value(value)
                label = (value or "").strip() or "Not recorded"
                entry = options.setdefault(key, {"value": key, "label": label, "count": 0})
                entry["label"] = min(entry["label"], label)  # stable even if input order changes
                entry["count"] += 1
    for name, field in (("confidence", "grade"), ("review", "disposition")):
        facets[name] = {}
        for f in findings:
            assessed = (assurance or {}).get(f.id, {}).get(name, {})
            values = review_filter_values(assessed) if name == "review" else {assessed.get(field, "unknown")}
            for value in values:
                entry = facets[name].setdefault(value, {"value": value, "label": value.replace("_", " ").capitalize(), "count": 0})
                entry["count"] += 1
    facets["reassessment"] = {}
    for f in findings:
        value = (reassessments or {}).get(f.id, {}).get("status", "unknown")
        entry = facets["reassessment"].setdefault(value, {"value": value, "label": REASSESSMENT_LABELS[value], "count": 0})
        entry["count"] += 1
    return {name: sorted(options.values(), key=lambda o: (o["value"] == MISSING, o["value"]))
            for name, options in facets.items()}


def filter_findings(findings: list[Finding], *, host: str | None = None, status: str | None = None,
                    severity: str | None = None, source: str | None = None, asset_type: str | None = None,
                    category: str | None = None, benchmark: str | None = None, benchmark_release: str | None = None,
                    q: str | None = None) -> list[Finding]:
    """Each filter takes one value or a comma-separated list. Severity accepts high|medium|low or 'CAT I'."""
    axes = {name: _filter_values(value) for name, value in (
        ("host", host), ("source", source), ("asset_type", asset_type),
        ("benchmark", benchmark), ("benchmark_release", benchmark_release))}
    statuses = _filter_values(status)
    for s in statuses:
        if s not in {x.value for x in Status}:
            raise ValueError(f"unknown status {s!r}")
    sevs = set()
    for s in _filter_values(severity):
        parsed = Severity.parse(s)
        if parsed == Severity.UNKNOWN and s != "unknown":
            raise ValueError(f"unknown severity {s!r}")
        sevs.add(parsed.value)
    categories = _filter_values(category)
    if categories - set(CATEGORIES):
        raise ValueError(f"unknown category {sorted(categories - set(CATEGORIES))[0]!r}")
    needle = (q or "").strip().casefold()
    out = []
    for f in findings:
        if any(values and _facet_value(getattr(f, name)) not in values for name, values in axes.items()):
            continue
        if statuses and f.status.value not in statuses:
            continue
        if sevs and f.severity.value not in sevs:
            continue
        if categories and not categories.intersection(finding_categories(f)):
            continue
        if needle and not any(needle in (v or "").casefold() for v in (
                f.title, f.host, f.source, f.benchmark, f.benchmark_release, *f.citations)):
            continue
        out.append(f)
    return out


def sort_findings(findings: list[Finding], sort_by: str, sort_dir: str, *, assurance: dict | None = None,
                  reassessments: dict | None = None) -> list[Finding]:
    if sort_by not in SORT_FIELDS:
        raise ValueError(f"unknown sort field {sort_by!r}")
    if sort_dir not in {"asc", "desc"}:
        raise ValueError(f"unknown sort direction {sort_dir!r}; use asc or desc")
    if sort_by == "default":
        if sort_dir != "asc":
            raise ValueError("choose an explicit sort field before changing direction")
        return sorted(findings, key=lambda f: (-f.severity.rank, f.status != Status.OPEN, f.host,
                                               f.rule_version or f.rule_id, f.id))

    def key(f: Finding):
        if sort_by == "confidence":
            grade = (assurance or {}).get(f.id, {}).get("confidence", {}).get("grade", "unknown")
            return CONFIDENCE_ORDER.get(grade)
        if sort_by == "review":
            disposition = (assurance or {}).get(f.id, {}).get("review", {}).get("disposition", "unreviewed")
            return REVIEW_ORDER.get(disposition)
        if sort_by == "severity":
            return None if f.severity == Severity.UNKNOWN else f.severity.rank
        if sort_by == "category":
            return tuple(sorted(finding_categories(f)))
        if sort_by == "collected_at":
            return _parse_ts(f.collected_at)
        if sort_by == "observed_at":
            return timestamp((reassessments or {}).get(f.id, {}).get("observation", {}).get("observed_at"))
        return (getattr(f, sort_by) or "").strip().casefold() or None

    # Missing/invalid values remain last in both directions; ties always use ascending finding id.
    ordered = sorted(findings, key=lambda f: f.id)
    present = [f for f in ordered if key(f) is not None]
    missing = [f for f in ordered if key(f) is None]
    return sorted(present, key=key, reverse=sort_dir == "desc") + missing


def list_findings(ctx: "AppContext", *, scan_id: str | None, limit: int, offset: int,
                  sort_by: str = "default", sort_dir: str = "asc", **filters) -> dict:
    from cyberthunder.security.resources import check_record, visible_record
    if scan_id:
        record = ctx.store.load_scan_run(scan_id)
        if record is None:
            if getattr(ctx.settings, "auth_mode", "dev") != "dev":
                raise PermissionError("scan is unavailable to this account")
            raise KeyError(f"unknown scan {scan_id!r}")
        check_record(ctx, record)
    sid = scan_id or ctx.store.latest_scan_id()
    if sid and not visible_record(ctx, ctx.store.load_scan_run(sid) or {}):
        sid = None
    # The default view includes partial overlays; sid remains its baseline metadata anchor.
    all_f = ctx.store.load_findings(scan_id) if scan_id else ctx.store.load_findings()
    all_f = [f for f in all_f if visible_record(ctx, f)]
    # Filters and the summary count a verified fix as closed, so the open totals move when a fix lands.
    lifecycle = CurrentFindings.for_context(ctx)
    scanned = {f.id: f for f in all_f}
    now = [lifecycle.assess(f).finding for f in all_f]
    from cyberthunder.findings.review import ReviewService
    assessed_at = datetime.now(timezone.utc)
    reviews = ReviewService(ctx)
    assurance = {f.id: finding_assurance(ctx, f, now=assessed_at, reviews=reviews) for f in all_f}
    confidence_filter = _filter_values(filters.pop("confidence", None))
    review_filter = _filter_values(filters.pop("review", None))
    reassessment_filter = _filter_values(filters.pop("reassessment", None))
    if confidence_filter - {"high", "medium", "low", "unknown"}:
        raise ValueError("unknown confidence grade")
    if review_filter - set(REVIEW_ORDER):
        raise ValueError("unknown review disposition")
    if reassessment_filter - set(REASSESSMENT_LABELS):
        raise ValueError("unknown reassessment status")
    sel = filter_findings(now, **filters)
    sel = [f for f in sel if (not confidence_filter or assurance[f.id]["confidence"]["grade"] in confidence_filter)
           and (not review_filter or review_filter & review_filter_values(assurance[f.id]["review"]))]
    # Derive from immutable observations for the entire authorized view. Page decoration
    # (explanation/fix/proposal lookups) is deliberately separate from query derivation.
    history = ReassessmentView(ctx, scan_id=scan_id)
    observations = [f.to_dict() for f in all_f]
    annotations = history.assess_many(observations)
    # Access can alternate without permanently removing a row or indexed run.
    # Bound retries so concurrent policy changes cannot occupy a request forever.
    for _ in range(4):
        readable = [f for f in all_f if visible_record(ctx, f)]
        if len(readable) != len(all_f):
            if not readable:
                raise PermissionError("finding is unavailable to this account")
            # Off-page observations still influence summary and facets. Remove revoked
            # contributors and rebuild the authorized view, not just its returned rows.
            all_f = readable
            allowed = {f.id for f in all_f}
            now = [f for f in now if f.id in allowed]
            sel = [f for f in sel if f.id in allowed]
            observations = [f.to_dict() for f in all_f]
            annotations = history.assess_many(observations)
            continue
        reassessments = {f.id: annotation for f, annotation in zip(all_f, annotations)}
        selected = [f for f in sel if not reassessment_filter or reassessments[f.id]["status"] in reassessment_filter]
        selected = sort_findings(selected, sort_by, sort_dir, assurance=assurance, reassessments=reassessments)
        page = [finding_plus(ctx, scanned[f.id], assurance=assurance[f.id], lifecycle=lifecycle)
                for f in selected[offset: offset + limit]]
        # Storage reads in page decoration or baseline/history checks can race revocation.
        # Re-derive filters, counts and page boundaries if readable history has changed.
        if scan_id:
            check_record(ctx, ctx.store.load_scan_run(scan_id) or {})
        baseline = (ctx.store.load_scan_run(sid) or {}) if sid and not scan_id else None
        if baseline is not None and not visible_record(ctx, baseline):
            sid = None
        for finding in page:
            check_record(ctx, finding)
        # Page authorization reads persisted inventory/policy too. Recheck history
        # afterwards even when every returned observation remains readable.
        checked = history.assess_many(observations)
        if checked != annotations:
            annotations = checked
            continue
        if scan_id:
            check_record(ctx, history.runs.get(scan_id, {}))
        elif sid and not visible_record(ctx, baseline):
            sid = None
        if any(not visible_record(ctx, f) for f in all_f):
            continue
        break
    else:
        raise HTTPException(status_code=409, detail="Findings view changed during authorization; retry the query.")
    for finding in page:
        finding["reassessment"] = reassessments[finding["id"]]
    return {"findings": page, "total": len(selected), "scan_id": sid,
            "view": "scan" if scan_id else "current", "summary": summarize(now), "limit": limit, "offset": offset,
            "unfiltered_total": len(now), "facets": finding_facets(now, assurance, reassessments=reassessments),
            "sort_by": sort_by, "sort_dir": sort_dir}


# -- link / outbox fallbacks ----------------------------------------------------------------------
def link_state(ctx: "AppContext") -> dict:
    """Link state from the ingest service when present, else link.json, else the settings defaults."""
    svc = getattr(ctx, "ingest", None)
    if svc is not None:
        try:
            return to_plain(call_first(svc, ("link_state", "get_link", "link")))
        except Exception as e:  # noqa: BLE001  fall back to the file
            log.debug("ingest link state unavailable: %s", e)
    from cyberthunder.ingest.link import Link
    return Link(ctx.store, ctx.settings).state().to_dict()


def outbox_pending(ctx: "AppContext") -> int | None:
    svc = getattr(ctx, "ingest", None)
    if svc is not None:
        try:
            ob = getattr(svc, "outbox", None)
            if ob is not None and callable(getattr(ob, "list", None)):
                listing = ob.list()           # the service exposes its Outbox object
            else:
                listing = call_first(svc, ("outbox", "outbox_state"))
            return len((to_plain(listing) or {}).get("pending", []))
        except Exception as e:  # noqa: BLE001
            log.debug("ingest outbox unavailable: %s", e)
    if getattr(getattr(ctx, "settings", None), "auth_mode", "dev") != "dev":
        # Never fall back from a denied filtered listing to unfiltered disk counts.
        return None
    d = ctx.store.outbox_dir
    if not d.exists():
        return 0
    files = [p for p in d.iterdir() if p.is_file() and not p.name.endswith(".tmp") and not p.name.startswith(".")]
    # Each queued entry is a payload plus its .meta.json; count entries, not files.
    metas = [p for p in files if p.name.endswith(".meta.json")]
    return len(metas) if metas else len(files)


# -- multipart (stdlib; keeps the dependency list as it is) -----------------------------------------
MAX_UPLOAD = 64 * 1024 * 1024
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(name: str | None, default: str = "upload.bin") -> str:
    base = Path((name or "").replace("\\", "/")).name
    base = _SAFE.sub("_", base).strip("._")
    return base[:120] or default


def parse_multipart(body: bytes, content_type: str) -> dict[str, dict]:
    """Minimal multipart/form-data reader: {field: {"filename": str|None, "content_type": str, "data": bytes}}."""
    m = re.search(r'boundary="?([^";]+)"?', content_type or "", re.I)
    if not m:
        raise ValueError("multipart request without a boundary")
    delim = b"--" + m.group(1).encode("latin-1")
    out: dict[str, dict] = {}
    for part in body.split(delim)[1:]:
        if part.startswith(b"--"):
            break
        if part.startswith(b"\r\n"):
            part = part[2:]
        head, sep, data = part.partition(b"\r\n\r\n")
        if not sep:
            continue
        if data.endswith(b"\r\n"):
            data = data[:-2]
        headers: dict[str, str] = {}
        for line in head.decode("utf-8", "replace").split("\r\n"):
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        disp = headers.get("content-disposition", "")
        name = re.search(r'\bname="([^"]*)"', disp)
        fname = re.search(r'\bfilename="([^"]*)"', disp)
        if not name:
            continue
        out[name.group(1)] = {"filename": fname.group(1) if fname else None,
                              "content_type": headers.get("content-type", "application/octet-stream"),
                              "data": data}
    return out


def parse_json_bytes(data: bytes) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"not valid JSON: {e}") from e
