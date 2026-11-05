"""Targets. The inventory is the scope: every add, change and removal is audited, and an in_scope change
is recorded as `scope.change` with the before and after values."""
from __future__ import annotations

import logging
import re

from fastapi import APIRouter, Body, HTTPException

from cyberthunder.api.errors import MappedRoute
from cyberthunder.api.util import ActorDep, CtxDep, to_plain
from cyberthunder.inventory.targets import Target
from cyberthunder.inventory.host import HostConnectionTransport, host_registration, persisted_target, readiness
from cyberthunder.inventory.targets import ScopeViolation
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.transport.base import TransportError

log = logging.getLogger(__name__)
router = APIRouter(tags=["targets"], route_class=MappedRoute)

READ_ONLY_FIELDS = {"id", "added_at", "last_scan"}
# The id names files and directories (scan workdirs, snapshots), so it must be a plain name.
TARGET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
BOOL_FIELDS = ("in_scope", "sudo", "simulated")


def _check_types(data: dict) -> None:
    """JSON types the dataclass does not enforce. A string 'no' for in_scope would otherwise be truthy."""
    for k in BOOL_FIELDS:
        if k in data and not isinstance(data[k], bool):
            raise ValueError(f"{k} must be true or false")
    port = data.get("port")
    if port is not None and (isinstance(port, bool) or not isinstance(port, int)):
        raise ValueError("port must be an integer or null")
    if "tags" in data and not (isinstance(data["tags"], list) and all(isinstance(t, str) for t in data["tags"])):
        raise ValueError("tags must be a list of strings")
    if "options" in data and not isinstance(data["options"], dict):
        raise ValueError("options must be an object")


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
    if not TARGET_ID.match(tid):
        raise ValueError("id must start with a letter or digit and use only letters, digits, '.', '_' or '-' "
                         "(64 characters at most)")
    _check_types(data)
    if not data.get("name"):
        data = {**data, "name": tid}
    t = _build({**data, "id": tid})
    try:
        ctx.inventory.add_new(t)
    except FileExistsError:
        raise HTTPException(409, f"target {tid!r} already exists")
    ctx.audit.append("inventory.add", actor, {"target": t.to_dict()})
    return t.to_dict()


@router.post("/targets/register-host", status_code=201)
def register_host(data: dict = Body(...), ctx=CtxDep, actor: str = ActorDep) -> dict:
    target, reason = host_registration(data)
    try:
        ctx.inventory.add_new(target)
    except FileExistsError:
        raise HTTPException(409, f"target {target.id!r} already exists") from None
    ctx.audit.append("inventory.add", actor, {"target": target.to_dict(), "registration": "deployment_host", "reason": reason},
                     subject=target.id)
    ctx.audit.append("scope.change", actor, {"target": target.id, "before": None,
                     "after": {"in_scope": target.in_scope}, "reason": reason, "explicit_choice": True}, subject=target.id)
    return target.to_dict()


@router.get("/targets/{target_id}/readiness")
def target_readiness(target_id: str, ctx=CtxDep) -> dict:
    return readiness(ctx, persisted_target(ctx.inventory, target_id))


@router.put("/targets/{target_id}")
def update_target(target_id: str, data: dict = Body(...), ctx=CtxDep, actor: str = ActorDep) -> dict:
    current = ctx.inventory.get(target_id)
    if not isinstance(data, dict):
        raise ValueError("body must be a JSON object")
    if "id" in data and data["id"] != target_id:
        raise ValueError("a target id cannot be changed; remove and add it instead")
    changes = {k: v for k, v in data.items() if k not in READ_ONLY_FIELDS}
    _check_types(changes)
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
    try:
        target = persisted_target(ctx.inventory, target_id, require_scope=True)
        ctx.killswitch.guard(f"inventory.discover:{target_id}", actor)
        try:
            adapter = ctx.adapter_for(target)
        except KeyError:
            raise NotImplementedError(f"adapter for {target.asset_type} not available on this build") from None
        fields = ("asset_type", "transport", "address", "port", "username", "credential_ref", "sudo", "simulated", "options")
        declared = {key: getattr(target, key) for key in fields}

        def guard():
            current = persisted_target(ctx.inventory, target_id, require_scope=True)
            if any(getattr(current, key) != value for key, value in declared.items()):
                raise ScopeViolation("target connection declarations changed; retry with the current inventory")
            ctx.killswitch.guard(f"inventory.discover:{target_id}", actor)

        ctx.audit.append("inventory.discover_started", actor, {"target": target_id}, subject=target_id)
        guard()
        try:
            transport = ctx.transport_for(target)
        except KeyError as e:
            raise TransportError(f"cannot open transport for {target_id}: {e}") from e
        try:
            guard()
        except Exception:
            transport.close()
            raise
        with transport:
            guard()
            checked = HostConnectionTransport(transport, guard) if target.asset_type in {"linux", "windows"} else transport
            facts = adapter.discover(target, checked)
            guard()
    except (ScopeViolation, KillSwitchEngaged):
        ctx.audit.append("inventory.discover", actor, {"target": target_id, "reason": "scope or kill guard refused access"},
                         subject=target_id, outcome="blocked")
        raise
    except (TransportError, NotImplementedError, KeyError) as e:
        ctx.audit.append("inventory.discover", actor, {"target": target_id, "error_type": type(e).__name__},
                         subject=target_id, outcome="error")
        raise
    except Exception as e:  # noqa: BLE001  adapter diagnostics can contain sensitive connection data
        log.warning("discover failed on %s (%s)", target_id, type(e).__name__)
        ctx.audit.append("inventory.discover", actor, {"target": target_id, "error_type": type(e).__name__},
                         subject=target_id, outcome="error")
        raise TransportError(f"connection test failed on {target_id} ({type(e).__name__})") from None
    result = to_plain(facts)
    ctx.audit.append("inventory.discover", actor, {"target": target_id, "hostname": result.get("hostname"),
                                                   "os_name": result.get("os_name")}, subject=target_id)
    return result
