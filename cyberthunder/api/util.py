"""Helpers shared by the route modules: identity, response shapes (Finding+, Proposal+, ScanRun),
background work, optional services, and the multipart reader used by ingest uploads."""
from __future__ import annotations

import importlib
import json
import logging
import re
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterable

from fastapi import Depends, Header, HTTPException

from cyberthunder.api.deps import get_actor, get_ctx
from cyberthunder.control.approvals import AGENT_ACTORS, Proposal
from cyberthunder.findings.schema import Finding, Severity, Status, summarize

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext

log = logging.getLogger(__name__)

TERMINAL_STATES = {"denied", "cancelled", "verified", "rolled_back", "failed"}
LIVE_STATES = {"proposed", "approved", "applying", "applied"}


# -- identity ---------------------------------------------------------------------------
def require_actor(x_actor: str | None = Header(default=None)) -> str:
    """Mutating requests must name the human acting. Machine identities are refused here so they can never
    reach an approval, denial, kill switch or policy edge through the API."""
    if not (x_actor or "").strip():
        raise HTTPException(400, "X-Actor header is required: type your name in Settings before making changes")
    actor = get_actor(x_actor)
    low = actor.lower()
    if low in AGENT_ACTORS or low.startswith("policy:"):
        raise HTTPException(400, f"actor {actor!r} is reserved for the machine; a named person must act")
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


def finding_plus(ctx: "AppContext", finding: Finding, with_proposal: bool = True) -> dict:
    d = finding.to_dict()
    d["cat"] = finding.severity.cat
    d["explanation"] = _explanation(ctx, finding.id)
    fix = _fix_for(ctx, finding)
    d["fix"] = fix.to_dict() if fix is not None else None
    if with_proposal:
        p = proposal_for(ctx, finding.id)
        d["proposal"] = {"id": p.id, "state": p.state.value} if p is not None else None
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


def filter_findings(findings: list[Finding], *, host: str | None = None, status: str | None = None,
                    severity: str | None = None, source: str | None = None, asset_type: str | None = None,
                    q: str | None = None) -> list[Finding]:
    """Each filter takes one value or a comma-separated list. Severity accepts high|medium|low or 'CAT I'."""
    hosts, sources, types = _split(host), _split(source), _split(asset_type)
    statuses = _split(status)
    for s in statuses:
        if s not in {x.value for x in Status}:
            raise ValueError(f"unknown status {s!r}")
    sevs = set()
    for s in _split(severity):
        parsed = Severity.parse(s)
        if parsed == Severity.UNKNOWN and s != "unknown":
            raise ValueError(f"unknown severity {s!r}")
        sevs.add(parsed.value)
    needle = (q or "").strip().lower()
    out = []
    for f in findings:
        if hosts and f.host.lower() not in hosts:
            continue
        if statuses and f.status.value not in statuses:
            continue
        if sevs and f.severity.value not in sevs:
            continue
        if sources and f.source.lower() not in sources:
            continue
        if types and (f.asset_type or "").lower() not in types:
            continue
        if needle and not any(needle in (v or "").lower() for v in (f.title, f.rule_id, f.rule_version)):
            continue
        out.append(f)
    return out


def list_findings(ctx: "AppContext", *, scan_id: str | None, limit: int, offset: int, **filters) -> dict:
    if scan_id and ctx.store.load_scan_run(scan_id) is None:
        raise KeyError(f"unknown scan {scan_id!r}")
    sid = scan_id or ctx.store.latest_scan_id()
    all_f = ctx.store.load_findings(sid) if sid else []
    sel = filter_findings(all_f, **filters)
    sel.sort(key=lambda f: (-f.severity.rank, f.status != Status.OPEN, f.host, f.rule_version or f.rule_id))
    page = sel[offset: offset + limit]
    return {"findings": [finding_plus(ctx, f) for f in page], "total": len(sel), "scan_id": sid,
            "summary": summarize(all_f), "limit": limit, "offset": offset}


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
            ob = call_first(svc, ("outbox", "outbox_state"))
            return len((to_plain(ob) or {}).get("pending", []))
        except Exception as e:  # noqa: BLE001
            log.debug("ingest outbox unavailable: %s", e)
    d = ctx.store.outbox_dir
    if not d.exists():
        return 0
    return sum(1 for p in d.iterdir() if p.is_file() and not p.name.endswith(".tmp") and not p.name.startswith("."))


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
