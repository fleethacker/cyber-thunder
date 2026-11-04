"""Targets. The inventory is the scope: every add, change and removal is audited, and an in_scope change
is recorded as `scope.change` with the before and after values."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Body, HTTPException

from cyberthunder.api.errors import MappedRoute
from cyberthunder.api.util import ActorDep, CtxDep, to_plain
from cyberthunder.inventory.targets import Target
from cyberthunder.transport.base import TransportError

log = logging.getLogger(__name__)
router = APIRouter(tags=["targets"], route_class=MappedRoute)

READ_ONLY_FIELDS = {"id", "added_at", "last_scan"}


def _build(data: dict) -> Target:
    """Validate through the dataclass so asset type and transport rules live in one place."""
    if not isinstance(data, dict):
        raise ValueError("target must be a JSON object")
    try:
        return Target.from_dict(data)
    except TypeError as e:
        raise ValueError(f"invalid target fields: {e}") from e


@router.get("/targets")
def list_targets(ctx=CtxDep) -> dict:
    return {"targets": [t.to_dict() for t in ctx.inventory.all()]}


@router.post("/targets", status_code=201)
def add_target(data: dict = Body(...), ctx=CtxDep, actor: str = ActorDep) -> dict:
    tid = str(data.get("id") or "").strip()
    if not tid:
        raise ValueError("id is required")
    if not data.get("name"):
        data = {**data, "name": tid}
    t = _build({**data, "id": tid})
    if tid in {x.id for x in ctx.inventory.all()}:
        raise HTTPException(409, f"target {tid!r} already exists")
    ctx.inventory.add(t)
    ctx.save_inventory(actor, "inventory.add", {"target": t.to_dict()})
    return t.to_dict()


@router.put("/targets/{target_id}")
def update_target(target_id: str, data: dict = Body(...), ctx=CtxDep, actor: str = ActorDep) -> dict:
    current = ctx.inventory.get(target_id)
    if not isinstance(data, dict):
        raise ValueError("body must be a JSON object")
    if "id" in data and data["id"] != target_id:
        raise ValueError("a target id cannot be changed; remove and add it instead")
    changes = {k: v for k, v in data.items() if k not in READ_ONLY_FIELDS}
    before = current.to_dict()
    updated = _build({**before, **changes})
    changed = sorted(k for k in changes if before.get(k) != getattr(updated, k))
    if not changed:
        return current.to_dict()
    ctx.inventory.add(updated)
    if "in_scope" in changed:
        ctx.save_inventory(actor, "scope.change", {
            "target": target_id, "before": {"in_scope": before["in_scope"]}, "after": {"in_scope": updated.in_scope},
            "fields": changed})
    else:
        ctx.save_inventory(actor, "inventory.update", {"target": target_id, "fields": changed})
    return updated.to_dict()


@router.delete("/targets/{target_id}")
def remove_target(target_id: str, ctx=CtxDep, actor: str = ActorDep) -> dict:
    t = ctx.inventory.get(target_id)
    ctx.inventory.remove(target_id)
    ctx.save_inventory(actor, "inventory.remove", {"target": target_id, "asset_type": t.asset_type,
                                                   "was_in_scope": t.in_scope})
    return {"ok": True}


@router.post("/targets/{target_id}/discover")
def discover_target(target_id: str, ctx=CtxDep, actor: str = ActorDep) -> dict:
    """Read-only: open the transport and ask the adapter what the asset is. Scope is enforced first."""
    target = ctx.inventory.assert_in_scope(target_id)
    try:
        adapter = ctx.adapter_for(target)
    except KeyError:
        raise NotImplementedError(f"adapter for {target.asset_type} not available on this build") from None
    try:
        transport = ctx.transport_for(target)
    except KeyError as e:
        raise TransportError(f"cannot open transport for {target_id}: {e}") from e
    try:
        with transport:
            facts = adapter.discover(target, transport)
    except (TransportError, NotImplementedError):
        raise
    except Exception as e:  # noqa: BLE001  adapter failures surface as 503 with the message
        log.warning("discover failed on %s: %s", target_id, e)
        ctx.audit.append("inventory.discover", actor, {"target": target_id, "error": str(e)},
                         subject=target_id, outcome="error")
        raise TransportError(f"discover failed on {target_id}: {e}") from e
    result = to_plain(facts)
    ctx.audit.append("inventory.discover", actor, {"target": target_id, "hostname": result.get("hostname"),
                                                   "os_name": result.get("os_name")}, subject=target_id)
    return result
