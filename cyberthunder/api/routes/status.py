"""GET /status: one call for the header bar (kill switch, audit head, model, link, outbox)."""
from __future__ import annotations

from fastapi import APIRouter

from cyberthunder.api import util
from cyberthunder.api.errors import MappedRoute
from cyberthunder.api.util import CtxDep

router = APIRouter(tags=["status"], route_class=MappedRoute)


@router.get("/status")
def get_status(ctx=CtxDep) -> dict:
    st = ctx.status()
    st["link"] = util.link_state(ctx)
    st["outbox"] = {"pending": util.outbox_pending(ctx)}
    return st
