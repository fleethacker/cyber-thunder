"""Demo controls for the simulated range: load simulated targets, reset them to the seeded state, and the
clearly labelled "force verification failure on next apply" toggle. Delegates to cyberthunder.demo.

Module functions used (first found wins):
  status(ctx)                                  -> {loaded, targets, simulate_verify_fail_next}
  load(ctx, actor=)                            -> {targets} or [Target]
  reset(ctx, actor=)                           -> {ok}
  set_simulate_verify_fail(ctx, value, actor=) -> any
  consume_simulate_verify_fail(ctx)            -> bool  (used by POST /proposals/{id}/apply)
"""
from __future__ import annotations

from fastapi import APIRouter

from cyberthunder.api import util
from cyberthunder.api.errors import MappedRoute, feature, requires
from cyberthunder.api.schemas import DemoToggleBody
from cyberthunder.api.util import ActorDep, CtxDep, call_first, to_plain

router = APIRouter(tags=["demo"], route_class=MappedRoute)


def _simulated(ctx) -> list[dict]:
    return [t.to_dict() for t in ctx.inventory.all() if t.simulated]


def _status(ctx, demo) -> dict:
    st: dict = {}
    if demo is not None:
        try:
            st = to_plain(call_first(demo, ("status", "demo_status"), ctx)) or {}
        except NotImplementedError:
            st = {}
    targets = st.get("targets")
    if targets is None:
        targets = _simulated(ctx)
    return {"available": demo is not None, "loaded": bool(st.get("loaded", bool(targets))),
            "targets": to_plain(targets), "simulate_verify_fail_next": bool(st.get("simulate_verify_fail_next", False))}


@router.get("/demo")
def demo_status(ctx=CtxDep) -> dict:
    return _status(ctx, util.demo_module())


@router.post("/demo/load")
def demo_load(ctx=CtxDep, actor: str = ActorDep) -> dict:
    demo = requires(util.demo_module(), "demo")
    with feature("demo"):
        res = to_plain(call_first(demo, ("load", "load_demo"), ctx, actor=actor))
    if isinstance(res, list):
        res = {"targets": res}
    res = res or {}
    res.setdefault("targets", _simulated(ctx))
    return res


@router.post("/demo/reset")
def demo_reset(ctx=CtxDep, actor: str = ActorDep) -> dict:
    demo = requires(util.demo_module(), "demo")
    with feature("demo"):
        res = to_plain(call_first(demo, ("reset", "reset_demo"), ctx, actor=actor))
    out = res if isinstance(res, dict) else {}
    out.setdefault("ok", True if res is None else bool(res))
    return out


@router.put("/demo")
def demo_toggle(body: DemoToggleBody, ctx=CtxDep, actor: str = ActorDep) -> dict:
    """Arm or disarm the forced verification failure for the next apply (demonstration control)."""
    demo = requires(util.demo_module(), "demo")
    with feature("demo verify-fail toggle"):
        call_first(demo, ("set_simulate_verify_fail_next", "set_simulate_verify_fail", "arm_simulate_verify_fail"), ctx,
                   body.simulate_verify_fail_next, actor=actor)
    return _status(ctx, demo)
