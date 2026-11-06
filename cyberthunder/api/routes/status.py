"""GET /status: one call for the header bar (kill switch, audit head, model, link, outbox)."""
from __future__ import annotations

from fastapi import APIRouter

from cyberthunder.api import util
from cyberthunder.api.errors import MappedRoute
from cyberthunder.api.util import CtxDep

router = APIRouter(tags=["status"], route_class=MappedRoute)


@router.get("/status")
def get_status(ctx=CtxDep) -> dict:
    if getattr(ctx.settings, "auth_mode", "dev") != "dev":
        from cyberthunder.control.principal import require_current
        try:
            global_details = ctx.access.allows(require_current("read.all"), "read.all", None)
            global_details = global_details and all(ctx.may_access(target, "read") for target in ctx.inventory.all())
        except PermissionError:
            global_details = False
        if not global_details:
            from cyberthunder import PRODUCT, __version__
            kill = ctx.killswitch.status()
            return {"product": PRODUCT, "version": __version__, "node": "Restricted node",
                    "global_details": False,
                    "kill": {"engaged": kill["engaged"], "by": None, "reason": None, "at": None, "via": None},
                    "audit": {"count": None, "head": None, "verified": None, "detail": "Global audit access is required"},
                    "policy": {"enabled": None, "signed_by": None, "rules": None},
                    "adapters": ctx.adapters.types(), "fixes": len(ctx.library.all()), "demo": False,
                    "targets": sum(ctx.may_access(target, "read") for target in ctx.inventory.all()),
                    "llm": None, "link": None, "outbox": {"pending": None}}
    st = ctx.status()
    st["global_details"] = True
    st["link"] = util.link_state(ctx)
    st["outbox"] = {"pending": util.outbox_pending(ctx)}
    return st


@router.get("/runtime/context")
def get_runtime_context() -> dict:
    from cyberthunder.inventory.deployment import runtime_context
    return runtime_context()
