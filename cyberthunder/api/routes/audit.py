"""Audit: list, verify, and a live Server-Sent Events stream that the UI tails.

The log file is the source of truth (the CLI may append to it from another process), so every read
goes to the file rather than to in-memory counters."""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import AsyncIterator, Awaitable, Callable

from fastapi import APIRouter, Header, Query, Request
from fastapi.responses import StreamingResponse

from cyberthunder.api.errors import MappedRoute
from cyberthunder.api.util import CtxDep
from cyberthunder.audit.chain import GENESIS

router = APIRouter(tags=["audit"], route_class=MappedRoute)

POLL_S = 0.5
KEEPALIVE_S = 15.0


@router.get("/audit")
def list_audit(ctx=CtxDep, after_seq: int = Query(0, ge=0), limit: int = Query(200, ge=1, le=5000),
               action: str | None = None, actor: str | None = None, subject: str | None = None) -> dict:
    """`action` matches exactly or as a prefix ending in '.', e.g. 'proposal.' for every proposal edge."""
    out: list[dict] = []
    head, count = GENESIS, 0
    for rec in ctx.audit.records():
        count, head = rec.get("seq", count), rec.get("hash", head)
        if rec.get("seq", 0) <= after_seq or len(out) >= limit:
            continue
        a = rec.get("action", "")
        if action and not (a == action or (action.endswith(".") and a.startswith(action))):
            continue
        if actor and rec.get("actor") != actor:
            continue
        if subject and rec.get("subject") != subject:
            continue
        out.append(rec)
    return {"records": out, "head": head, "count": count}


@router.get("/audit/verify")
def verify_audit(ctx=CtxDep) -> dict:
    v = ctx.audit.verify()
    return {"ok": v.ok, "count": v.count, "head": v.head, "bad_seq": v.bad_seq, "reason": v.reason}


def _sse(rec: dict) -> str:
    return f"id: {rec.get('seq')}\nevent: audit\ndata: {json.dumps(rec, ensure_ascii=False, sort_keys=True)}\n\n"


async def audit_events(path: Path, after_seq: int, is_disconnected: Callable[[], Awaitable[bool]], *,
                       poll_s: float = POLL_S, keepalive_s: float = KEEPALIVE_S,
                       max_seconds: float | None = None, authorize=None) -> AsyncIterator[str]:
    """Replay records with seq > after_seq, then tail the file. Only whole lines are consumed, so a record
    being written while we read is picked up on the next poll."""
    offset = 0
    started = last_sent = time.monotonic()
    yield "retry: 2000\n\n"
    while True:
        if authorize is not None:
            try:
                authorize()
            except PermissionError:
                yield 'event: session-expired\ndata: {"detail":"authorization no longer valid"}\n\n'
                return
        if path.exists():
            size = path.stat().st_size
            if size < offset:          # file replaced (should never happen to an append-only log): start over
                offset = 0
            if size > offset:
                with path.open("rb") as fh:
                    fh.seek(offset)
                    data = fh.read()
                end = data.rfind(b"\n")
                if end >= 0:
                    offset += end + 1
                    for raw in data[: end + 1].splitlines():
                        if authorize is not None:
                            try:
                                authorize()
                            except PermissionError:
                                return
                        raw = raw.strip()
                        if not raw:
                            continue
                        try:
                            rec = json.loads(raw.decode("utf-8"))
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            continue   # /audit/verify reports corruption; the stream just skips it
                        if rec.get("seq", 0) > after_seq:
                            after_seq = rec["seq"]
                            last_sent = time.monotonic()
                            yield _sse(rec)
        if await is_disconnected():
            return
        now = time.monotonic()
        if max_seconds is not None and now - started >= max_seconds:
            return
        if now - last_sent >= keepalive_s:
            last_sent = now
            yield ": keepalive\n\n"
        await asyncio.sleep(poll_s)


@router.get("/audit/stream")
async def stream_audit(request: Request, ctx=CtxDep, after_seq: int | None = Query(None, ge=0),
                       max_seconds: float | None = Query(None, gt=0, le=86400),
                       last_event_id: str | None = Header(default=None)) -> StreamingResponse:
    """`max_seconds` ends the stream after that long (clients on a poor link may prefer short polls);
    EventSource reconnects resume from the Last-Event-ID header."""
    start = after_seq
    if start is None:
        try:
            start = int(last_event_id) if last_event_id else 0
        except ValueError:
            start = 0
    from cyberthunder.control.principal import authorize
    gen = audit_events(Path(ctx.audit.path), start, request.is_disconnected, max_seconds=max_seconds,
                       authorize=lambda: authorize(ctx, "audit"))
    return StreamingResponse(gen, media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
