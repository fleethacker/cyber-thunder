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

    t = threading.Thread(target=target, name=name, daemon=True)
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


def _verified_at(p: Proposal | None) -> str | None:
    if p is None or p.state.value != "verified":
        return None
    for h in reversed(p.history or []):
        if h.get("state") == "verified":
            return h.get("ts")
    return p.decided_at or p.created_at


def remediated_by(finding: Finding, p: Proposal | None) -> dict | None:
    """An open finding whose current proposal was verified after the finding was collected has been fixed,
    even though the scan that reported it still says open. A later scan that finds it open again wins."""
    if not finding.is_open:
        return None
    vts = _verified_at(p)
    if vts is None:
        return None
    v, c = _parse_ts(vts), _parse_ts(finding.collected_at)
    if v is not None and c is not None and v < c:
        return None
    return {"proposal_id": p.id, "verified_at": vts, "scan_status": finding.status.value}


def effective(finding: Finding, p: Proposal | None) -> Finding:
    """The finding as it stands now: a verified fix makes an open result not_a_finding."""
    return replace(finding, status=Status.NOT_A_FINDING) if remediated_by(finding, p) else finding


def current_proposals(ctx: "AppContext") -> dict[str, Proposal]:
    """finding id -> its current proposal (newest live one, else newest of any state), from one gate read."""
    try:
        props = list(ctx.gate.list())
    except Exception as exc:  # noqa: BLE001  a missing gate leaves findings as scanned
        log.debug("proposal listing failed: %s", exc)
        return {}
    out: dict[str, Proposal] = {}
    for p in props:
        cur = out.get(p.finding_id)
        if cur is None or p.state.value not in TERMINAL_STATES or cur.state.value in TERMINAL_STATES:
            out[p.finding_id] = p
    return out


def finding_plus(ctx: "AppContext", finding: Finding, with_proposal: bool = True) -> dict:
    d = finding.to_dict()
    d["categories"] = finding_categories(finding)
    d["cat"] = finding.severity.cat
    d["explanation"] = _explanation(ctx, finding.id)
    fix = _fix_for(ctx, finding)
    d["fix"] = fix.to_dict() if fix is not None else None
    if with_proposal:
        p = proposal_for(ctx, finding.id)
        d["proposal"] = {"id": p.id, "state": p.state.value} if p is not None else None
        rem = remediated_by(finding, p)
        d["remediated"] = rem
        if rem is not None:
            d["status"] = Status.NOT_A_FINDING.value
    return d


def proposal_plus(ctx: "AppContext", p: Proposal) -> dict:
    from cyberthunder.control.policy import evaluate

    d = p.to_dict()
    fix = ctx.library.get(p.fix_ref)
    d["fix"] = fix.to_dict() if fix is not None else None
    finding = None
    try:
        finding = ctx.store.get_finding(p.finding_id)
    except Exception as exc:  # noqa: BLE001
        log.debug("finding lookup failed for proposal %s: %s", p.id, exc)
    d["finding"] = finding_plus(ctx, finding, with_proposal=False) if finding is not None else None
    target = None
    try:
        target = ctx.inventory.get(p.host)
    except KeyError:
        pass
    policy = None
    if fix is not None and finding is not None and target is not None:
        try:
            policy = evaluate(ctx.policy, fix, finding, target).to_dict()
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
        return ctx.gate.get(pid)
    except KeyError:
        raise KeyError(f"unknown proposal {pid!r}") from None


def get_finding(ctx: "AppContext", fid: str, scan_id: str | None = None) -> Finding:
    f = ctx.store.get_finding(fid, scan_id)
    if f is None:
        raise KeyError(f"unknown finding {fid!r}")
    return f


# -- findings listing --------------------------------------------------------------------------
def _split(v: str | None) -> set[str]:
    return {x.strip().lower() for x in (v or "").split(",") if x.strip()}


MISSING = "__missing__"
CATEGORIES = ("stig", "cve", "hunt", "other")
SORT_FIELDS = {"default", "severity", "host", "asset_type", "category", "title", "rule_id", "rule_version", "source",
               "collected_at", "benchmark", "benchmark_release"}


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


def finding_facets(findings: list[Finding]) -> dict:
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


def sort_findings(findings: list[Finding], sort_by: str, sort_dir: str) -> list[Finding]:
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
        if sort_by == "severity":
            return None if f.severity == Severity.UNKNOWN else f.severity.rank
        if sort_by == "category":
            return tuple(sorted(finding_categories(f)))
        if sort_by == "collected_at":
            return _parse_ts(f.collected_at)
        return (getattr(f, sort_by) or "").strip().casefold() or None

    # Missing/invalid values remain last in both directions; ties always use ascending finding id.
    ordered = sorted(findings, key=lambda f: f.id)
    present = [f for f in ordered if key(f) is not None]
    missing = [f for f in ordered if key(f) is None]
    return sorted(present, key=key, reverse=sort_dir == "desc") + missing


def list_findings(ctx: "AppContext", *, scan_id: str | None, limit: int, offset: int,
                  sort_by: str = "default", sort_dir: str = "asc", **filters) -> dict:
    if scan_id and ctx.store.load_scan_run(scan_id) is None:
        raise KeyError(f"unknown scan {scan_id!r}")
    sid = scan_id or ctx.store.latest_scan_id()
    # The default view includes partial overlays; sid remains its baseline metadata anchor.
    all_f = ctx.store.load_findings(scan_id) if scan_id else ctx.store.load_findings()
    # Filters and the summary count a verified fix as closed, so the open totals move when a fix lands.
    props = current_proposals(ctx) if all_f else {}
    scanned = {f.id: f for f in all_f}
    now = [effective(f, props.get(f.id)) for f in all_f]
    sel = filter_findings(now, **filters)
    sel = sort_findings(sel, sort_by, sort_dir)
    page = sel[offset: offset + limit]
    return {"findings": [finding_plus(ctx, scanned.get(f.id, f)) for f in page], "total": len(sel), "scan_id": sid,
            "view": "scan" if scan_id else "current", "summary": summarize(now), "limit": limit, "offset": offset,
            "unfiltered_total": len(now), "facets": finding_facets(now), "sort_by": sort_by, "sort_dir": sort_dir}


# -- link / outbox fallbacks ----------------------------------------------------------------------
def link_state(ctx: "AppContext") -> dict:
    """Link state from the ingest service when present, else link.json, else the settings defaults."""
    svc = getattr(ctx, "ingest", None)
    if svc is not None:
        try:
            return to_plain(call_first(svc, ("link_state", "get_link", "link")))
        except Exception as e:  # noqa: BLE001  fall back to the file
            log.debug("ingest link state unavailable: %s", e)
    s = ctx.settings
    st = {"kbps": s.link_kbps, "latency_ms": s.link_latency_ms, "connected": s.link_connected}
    try:
        saved = ctx.store.read_json(ctx.store.link_state, {}) or {}
        st.update({k: saved[k] for k in ("kbps", "latency_ms", "connected") if k in saved})
    except (OSError, ValueError) as e:
        log.debug("link state file unreadable: %s", e)
    return st


def outbox_pending(ctx: "AppContext") -> int:
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
