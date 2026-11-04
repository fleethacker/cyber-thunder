"""Ingest over the constrained link (STIG release deltas, IAVM/CVE bulletins), link emulation and the
sync-on-reconnect outbox. The work is done by ctx.ingest; these routes validate input and shape output.

Uploads are read with a small standard-library multipart reader (no extra dependency) and saved under
<state_dir>/ingest/uploads/ before the service sees them.

Service methods used (first name found wins):
  link_state()                         -> {kbps, latency_ms, connected}
  set_link(changes, actor=)            -> link state (audits link.change, flushes the outbox on reconnect)
  ingest_stig(path, actor=)            -> DeltaReport
  get_delta(delta_id)                  -> DeltaReport            (falls back to history()['deltas'])
  ingest_bulletin(bulletin, actor=)    -> {bulletin_id, hosts_affected, findings, scan_id}
  history()                            -> {deltas, bulletins}
  outbox()                             -> {connected, pending, synced}
  sync(actor=)                         -> {sent, bytes, seconds}
  check_updates / last_update_check / pull / pull_job / held_content / write_manifest / import_dir
                                       -> DISA content updates (cyberthunder/ingest/content/)
"""
from __future__ import annotations

import inspect

from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from cyberthunder.api import util
from cyberthunder.api.errors import MappedRoute, feature, requires, unavailable
from cyberthunder.api.routes.scans import start_scan
from cyberthunder.api.schemas import LinkBody
from cyberthunder.api.util import ActorDep, CtxDep, call_first, finding_plus, to_plain
from cyberthunder.findings.schema import Finding

router = APIRouter(tags=["ingest"], route_class=MappedRoute)


def _svc(ctx, what: str = "ingest"):
    return requires(getattr(ctx, "ingest", None), what)


async def _read_upload(request: Request, ctx, *, json_ok: bool) -> tuple[Path | None, object | None]:
    """Return (saved upload path, None) for multipart, or (None, parsed JSON body) otherwise."""
    ctype = request.headers.get("content-type", "")
    length = int(request.headers.get("content-length") or 0)
    if length > util.MAX_UPLOAD:
        raise HTTPException(413, f"upload larger than {util.MAX_UPLOAD // (1024 * 1024)} MB")
    body = await request.body()
    if len(body) > util.MAX_UPLOAD:
        raise HTTPException(413, f"upload larger than {util.MAX_UPLOAD // (1024 * 1024)} MB")
    if ctype.lower().startswith("multipart/form-data"):
        parts = util.parse_multipart(body, ctype)
        part = parts.get("file")
        if part is None or not part["data"]:
            raise ValueError("multipart upload needs a non-empty 'file' field")
        if json_ok and not part.get("filename"):
            return None, util.parse_json_bytes(part["data"])
        up = ctx.store.ingest_dir / "uploads" / ctx.store.new_id()
        up.mkdir(parents=True, exist_ok=True)
        dest = up / util.safe_filename(part.get("filename"))
        dest.write_bytes(part["data"])
        return dest, None
    if not body:
        raise ValueError("send a multipart 'file' or a JSON body")
    return None, util.parse_json_bytes(body)


# -- link -------------------------------------------------------------------------------------
@router.get("/ingest/link")
def get_link(ctx=CtxDep) -> dict:
    svc = _svc(ctx, "link emulation")
    with feature("link emulation"):
        return to_plain(call_first(svc, ("link_state", "get_link", "link")))


@router.put("/ingest/link")
def put_link(body: LinkBody, ctx=CtxDep, actor: str = ActorDep) -> dict:
    svc = _svc(ctx, "link emulation")
    changes = body.model_dump(exclude_none=True)
    if not changes:
        raise ValueError("nothing to change: send kbps, latency_ms or connected")
    with feature("link emulation"):
        fn = getattr(svc, "set_link", None) or getattr(svc, "update_link", None)
        if fn is None:
            raise NotImplementedError
        params = inspect.signature(fn).parameters
        if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
            return to_plain(fn(actor=actor, **changes))        # IngestService.set_link(*, actor, **changes)
        return to_plain(fn(changes, actor=actor))              # positional-changes style


# -- STIG release deltas ---------------------------------------------------------------------------
@router.post("/ingest/stig")
async def ingest_stig(request: Request, ctx=CtxDep, actor: str = ActorDep) -> dict:
    svc = _svc(ctx, "STIG ingest")
    path, data = await _read_upload(request, ctx, json_ok=False)
    if path is None:
        if not isinstance(data, dict) or not data.get("path"):
            raise ValueError("JSON body must be {\"path\": \"<file on this node>\"}")
        path = Path(str(data["path"])).expanduser()
        if not path.is_file():
            raise ValueError(f"no such file on this node: {path}")
    with feature("STIG ingest"):
        return to_plain(call_first(svc, ("ingest_stig", "stig_delta", "ingest_stig_release"), path, actor=actor))


def _find_delta(svc, delta_id: str) -> dict:
    try:
        d = call_first(svc, ("get_delta", "delta"), delta_id)
    except NotImplementedError:
        hist = to_plain(call_first(svc, ("history",))) or {}
        d = next((x for x in hist.get("deltas", []) if x.get("id") == delta_id), None)
    d = to_plain(d)
    if not d:
        raise KeyError(f"unknown STIG delta {delta_id!r}")
    return d


@router.post("/ingest/stig/{delta_id}/rescan", status_code=202)
def rescan_delta(delta_id: str, ctx=CtxDep, actor: str = ActorDep) -> dict:
    svc = _svc(ctx, "STIG ingest")
    with feature("STIG ingest"):
        delta = _find_delta(svc, delta_id)
    rules = list(delta.get("rescan_rule_ids") or [])
    if not rules:
        raise ValueError(f"delta {delta_id} changes no rules that need a rescan")
    return start_scan(ctx, actor, rule_filter=rules, trigger="stig_delta")


# -- bulletins -----------------------------------------------------------------------------------
def _finding_out(ctx, f) -> dict:
    if isinstance(f, Finding):
        return finding_plus(ctx, f)
    if isinstance(f, dict) and "severity" in f and "host" in f:
        return finding_plus(ctx, Finding.from_dict(f))
    return to_plain(f)


@router.post("/ingest/bulletin")
async def ingest_bulletin(request: Request, ctx=CtxDep, actor: str = ActorDep) -> dict:
    svc = _svc(ctx, "bulletin ingest")
    path, data = await _read_upload(request, ctx, json_ok=True)
    if path is not None:
        data = util.parse_json_bytes(path.read_bytes())
    if not isinstance(data, dict) or not data.get("id"):
        raise ValueError("bulletin must be a JSON object with at least an 'id'")
    if not isinstance(data.get("cves", []), list) or not isinstance(data.get("affected", []), list):
        raise ValueError("bulletin 'cves' and 'affected' must be lists")
    with feature("bulletin ingest"):
        res = to_plain(call_first(svc, ("ingest_bulletin", "bulletin", "match_bulletin"), data, actor=actor)) or {}
    if isinstance(res, dict) and "findings" in res:
        res["findings"] = [_finding_out(ctx, f) for f in (res.get("findings") or [])]
    return res


@router.get("/ingest/history")
def history(ctx=CtxDep) -> dict:
    svc = _svc(ctx)
    with feature("ingest"):
        h = to_plain(call_first(svc, ("history",))) or {}
    h.setdefault("deltas", [])
    h.setdefault("bulletins", [])
    return h


# -- outbox ------------------------------------------------------------------------------------
@router.get("/outbox")
def outbox(ctx=CtxDep) -> dict:
    svc = _svc(ctx, "outbox")
    with feature("outbox"):
        ob = getattr(svc, "outbox", None)
        if ob is None:
            raise NotImplementedError
        listing = ob.list() if callable(getattr(ob, "list", None)) else (ob() if callable(ob) else ob)
        out = to_plain(listing) or {}
        for key in ("pending", "synced"):
            out[key] = [_outbox_entry(e) for e in (out.get(key) or [])]
        out["connected"] = bool(util.link_state(ctx).get("connected", False))
        return out


def _outbox_entry(e: Any) -> Any:
    """The documented entry shape (created_at, seconds, id) alongside the outbox's own field names."""
    if not isinstance(e, dict):
        return e
    e = dict(e)
    e.setdefault("created_at", e.get("enqueued_at"))
    e.setdefault("seconds", e.get("transfer_seconds"))
    e.setdefault("synced_at", None)
    e.setdefault("id", e.get("name"))
    return e


@router.post("/outbox/sync")
def outbox_sync(ctx=CtxDep, actor: str = ActorDep) -> dict:
    svc = _svc(ctx, "outbox")
    if not util.link_state(ctx).get("connected", False):
        raise HTTPException(409, "link is disconnected; the outbox syncs automatically on reconnect")
    with feature("outbox"):
        ob = getattr(svc, "outbox", None)
        if ob is not None and callable(getattr(ob, "sync", None)):
            return to_plain(ob.sync(actor=actor))
        return to_plain(call_first(svc, ("sync", "sync_outbox", "flush"), actor=actor))


# -- DISA content updates ------------------------------------------------------------------------
# Read-only egress to the two allow-listed DoD hosts; nothing here changes an asset. The service refuses
# with LinkDisconnected (409) when the link is down and IngestError (400) on any other refusal.
class UpdateCheckBody(BaseModel):
    source: Literal["live", "snapshot"] = "live"


class PullBody(BaseModel):
    filenames: list[str] | None = Field(default=None, max_length=200)
    all_matching: bool = False
    pace: bool = False


class ImportDirBody(BaseModel):
    path: str


def _content_svc(ctx):
    svc = _svc(ctx, "content updates")
    if not callable(getattr(svc, "check_updates", None)):
        raise unavailable("content updates")
    return svc


@router.get("/ingest/updates")
def get_updates(ctx=CtxDep) -> dict:
    svc = _content_svc(ctx)
    last = to_plain(svc.last_update_check()) or {"checked_at": None, "wanted": [], "updates": [], "current": [],
                                                 "skipped": []}
    last["index_estimate"] = svc.content.index_estimate()
    last["connected"] = bool(util.link_state(ctx).get("connected", False))
    return last


@router.post("/ingest/updates/check")
def check_updates(body: UpdateCheckBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    svc = _content_svc(ctx)
    return to_plain(svc.check_updates(actor, source=(body or UpdateCheckBody()).source))


@router.post("/ingest/updates/pull", status_code=202)
def pull_updates(body: PullBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    svc = _content_svc(ctx)
    b = body or PullBody()
    if not b.all_matching and not b.filenames:
        raise ValueError("send {\"filenames\": [...]} or {\"all_matching\": true}")
    return to_plain(svc.pull(actor, filenames=None if b.all_matching else b.filenames, all_matching=b.all_matching,
                             pace=b.pace, background=True))


@router.get("/ingest/updates/jobs/{job_id}")
def pull_job(job_id: str, ctx=CtxDep) -> dict:
    return to_plain(_content_svc(ctx).pull_job(job_id))


@router.get("/ingest/content")
def held_content(ctx=CtxDep) -> dict:
    return to_plain(_content_svc(ctx).held_content())


@router.post("/ingest/manifest")
def write_manifest(ctx=CtxDep, actor: str = ActorDep) -> dict:
    return to_plain(_content_svc(ctx).write_manifest(actor))


@router.post("/ingest/import-dir")
def import_dir(body: ImportDirBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    svc = _content_svc(ctx)
    if body is None or not body.path.strip():
        raise ValueError("send {\"path\": \"<folder on this node>\"}")
    p = Path(body.path.strip()).expanduser()
    if not p.is_dir():
        raise ValueError(f"no such folder on this node: {p}")
    return to_plain(svc.import_dir(p, actor))
