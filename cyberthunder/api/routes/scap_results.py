"""Bounded container OS XCCDF upload; accepts bytes and explicit declarations only."""
import asyncio
from contextlib import suppress
from threading import Event

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from cyberthunder.api.access import SCOPED
from cyberthunder.api.errors import MappedRoute
from cyberthunder.api.util import ActorDep, CtxDep
from cyberthunder.control.principal import authorize
from cyberthunder.control.roles import WRITE_ACTIONS
from cyberthunder.ingest.scap_results import MAX_UPLOAD_BYTES, guard_kill, import_actor, import_results, parse_upload

# Register this exact route with the existing fail-closed registries. Kept with the sidecar
# so it can be integrated without editing the shared identity-policy implementation.
WRITE_ACTIONS[("POST", "/ingest/scap-results")] = "import"
SCOPED.add(("POST", "/ingest/scap-results"))
router = APIRouter(tags=["ingest"], route_class=MappedRoute)


@router.post("/ingest/scap-results")
async def import_scap_results(request: Request, ctx=CtxDep, actor: str = ActorDep):
    actor = import_actor(actor)
    authorize(ctx, "import", actor=actor)
    guard_kill(ctx, actor)
    if request.headers.get("content-type", "").lower() not in {"application/json", "application/json; charset=utf-8"}:
        raise HTTPException(415, "send application/json with xml_base64 and manifest")
    length = request.headers.get("content-length")
    if length is not None:
        if not length.isascii() or not length.isdigit() or len(length) > 12:
            raise HTTPException(400, "invalid upload content length")
        if int(length) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, "SCAP upload exceeds the size limit")
    body = bytearray()
    async for chunk in request.stream():
        authorize(ctx, "import", actor=actor)
        guard_kill(ctx, actor)
        if len(body) + len(chunk) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, "SCAP upload exceeds the size limit")
        body.extend(chunk)
    cancelled = Event()

    async def disconnected():
        # The request body has been consumed; only this task reads disconnects.
        while True:
            if (await request.receive())["type"] == "http.disconnect":
                cancelled.set()
                return

    watcher = asyncio.create_task(disconnected())
    try:
        data, manifest = await run_in_threadpool(parse_upload, bytes(body))
        return await run_in_threadpool(import_results, ctx, data, manifest, actor=actor, cancelled=cancelled)
    except PermissionError:
        raise
    except OSError:
        raise HTTPException(503, "SCAP import storage is unavailable") from None
    finally:
        # Direct task cancellation can abandon a running thread. That thread must
        # observe cancellation at its next guard, including after publication waits.
        cancelled.set()
        watcher.cancel()
        with suppress(asyncio.CancelledError):
            await watcher
