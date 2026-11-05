"""Managed vulnerability database status, updates and offline transfers."""
from __future__ import annotations

import tempfile
import threading
from pathlib import Path

import anyio
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from cyberthunder.api.errors import MappedRoute, error_response, requires
from cyberthunder.api.util import ActorDep, CtxDep, to_plain

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"], route_class=MappedRoute)


class DatabaseSettingsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision: int = Field(ge=0)
    auto_update: bool | None = None
    interval_hours: int | None = Field(default=None, ge=1, le=168)
    include_java: bool | None = None


class DatabaseUpdateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    include_java: bool = True


def _service(ctx):
    return requires(getattr(ctx, "vulnerabilities", None), "vulnerability data")


@router.get("")
def status(ctx=CtxDep) -> dict:
    return to_plain(_service(ctx).status())


@router.put("/settings")
def settings(body: DatabaseSettingsBody, ctx=CtxDep, actor: str = ActorDep) -> dict:
    return to_plain(_service(ctx).save_settings(body.model_dump(exclude_none=True), actor=actor))


@router.post("/update", status_code=202)
def update(body: DatabaseUpdateBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    return to_plain(_service(ctx).update(actor=actor, include_java=(body or DatabaseUpdateBody()).include_java,
                                        background=True))


@router.get("/jobs")
def jobs(ctx=CtxDep) -> dict:
    return {"jobs": to_plain(_service(ctx).jobs())}


@router.get("/jobs/{job_id}")
def job(job_id: str, ctx=CtxDep) -> dict:
    return to_plain(_service(ctx).job(job_id))


@router.post("/import")
async def import_bundle(request: Request, ctx=CtxDep, actor: str = ActorDep) -> dict:
    service = _service(ctx)
    ctx.killswitch.guard("vulnerabilities.import", actor)
    limit = int(getattr(ctx.settings, "vulnerability_max_bundle_bytes", 4 * 1024 * 1024 * 1024))
    if limit <= 0:
        raise ValueError("vulnerability bundle upload limit must be positive")
    length = request.headers.get("content-length")
    if length is not None:
        if not length.isascii() or not length.isdigit() or len(length) > 12:
            raise ValueError("invalid Content-Length")
        if int(length) > limit:
            raise HTTPException(413, "vulnerability bundle exceeds the upload limit")
    media = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media not in {"application/zip", "application/octet-stream"}:
        raise ValueError("upload a ZIP as the raw application/zip request body")
    directory = ctx.store.root / "vulnerabilities" / "uploads"
    directory.mkdir(parents=True, exist_ok=True)
    path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="bundle-", suffix=".zip", dir=directory, delete=False) as stream:
            path = Path(stream.name)
            size = 0
            async for chunk in request.stream():
                ctx.killswitch.guard("vulnerabilities.import", actor)
                size += len(chunk)
                if size > limit:
                    raise HTTPException(413, "vulnerability bundle exceeds the upload limit")
                stream.write(chunk)
        if size == 0:
            raise ValueError("the uploaded vulnerability bundle is empty")
        ctx.killswitch.guard("vulnerabilities.import", actor)
        return to_plain(await run_in_threadpool(service.import_bundle, path, actor=actor))
    finally:
        if path is not None:
            path.unlink(missing_ok=True)


class _ExportResponse(Response):
    def __init__(self, service, root: Path, actor: str):
        super().__init__()
        self.service, self.root, self.actor = service, root, actor

    async def __call__(self, scope, receive, send):
        bundle = None
        finished = False
        ownership = threading.Lock()

        def acquire():
            nonlocal bundle
            created = self.service.export_lease(actor=self.actor)
            with ownership:
                # Direct task cancellation can abandon a worker despite an AnyIO
                # shield. A late result must close itself instead of losing its lease.
                if finished:
                    created.close()
                else:
                    bundle = created
            return created

        try:
            try:
                # Acquire inside the response lifetime, before headers or a path
                # are exposed. A response that is never called owns no resources.
                with anyio.CancelScope(shield=True):
                    created = await run_in_threadpool(acquire)
                path = Path(created.path)
                if not path.resolve().is_relative_to(self.root.resolve()):
                    raise RuntimeError("vulnerability export is outside application state")
                response = FileResponse(path, media_type="application/zip",
                                        filename="cyberthunder-vulnerability-data.zip")
            except Exception as exc:
                response = error_response(exc)
                if response is None:
                    raise
            # A path-send extension may open the file after the response returns.
            # Stream file bytes here so the lease covers the actual file lifetime.
            extensions = dict(scope.get("extensions", {}))
            extensions.pop("http.response.pathsend", None)
            await response({**scope, "extensions": extensions}, receive, send)
        finally:
            with ownership:
                finished = True
                if bundle is not None:
                    bundle.close()


@router.post("/export")
def export_bundle(ctx=CtxDep, actor: str = ActorDep) -> Response:
    return _ExportResponse(_service(ctx), ctx.store.root, actor)
