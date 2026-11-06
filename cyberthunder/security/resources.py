"""Persisted artifact ownership survives target moves, deletion and identifier reuse."""
from __future__ import annotations

from cyberthunder.control.principal import authorize
from cyberthunder.inventory.host import persisted_target


def target_scope(target) -> dict:
    return {"version": 1, "target_id": target.id, "environment": target.environment,
            "authorization_id": target.authorization_id}


def capture(ctx, target_ids) -> list[dict]:
    return [target_scope(persisted_target(ctx.inventory, tid)) for tid in sorted(set(target_ids))]


def authorize_artifact(ctx, scopes, action: str = "read") -> None:
    if getattr(getattr(ctx, "settings", None), "auth_mode", "dev") == "dev":
        return
    if isinstance(scopes, dict):
        scopes = [scopes]
    if not isinstance(scopes, list) or not scopes or len(scopes) > 10000:
        raise PermissionError("artifact ownership is unavailable; a new authorized observation is required")
    for scope in scopes:
        try:
            if not isinstance(scope, dict) or set(scope) != {"version", "target_id", "environment", "authorization_id"}:
                raise ValueError
            current = persisted_target(ctx.inventory, scope["target_id"])
            if scope != target_scope(current):
                raise ValueError
            authorize(ctx, action, target=current)
        except (KeyError, ValueError, TypeError):
            raise PermissionError("artifact belongs to an unavailable or changed target") from None


def visible_artifact(ctx, scopes, action: str = "read") -> bool:
    try:
        authorize_artifact(ctx, scopes, action)
        return True
    except PermissionError:
        return False


def object_scopes(obj):
    value = obj if isinstance(obj, dict) else obj.to_dict()
    if "host" in value:
        scope = value.get("authorization_scope")
        return scope if isinstance(scope, dict) and scope.get("target_id") == value["host"] else None
    scopes = value.get("authorization_scopes")
    targets = value.get("targets")
    if (isinstance(scopes, list) and isinstance(targets, list)
            and all(isinstance(t, str) and t for t in targets)
            and all(isinstance(s, dict) and isinstance(s.get("target_id"), str) for s in scopes)
            and set(targets) == {s.get("target_id") for s in scopes}):
        return scopes
    return None


def check_record(ctx, obj, action: str = "read") -> None:
    authorize_artifact(ctx, object_scopes(obj), action)


def visible_record(ctx, obj, action: str = "read") -> bool:
    return visible_artifact(ctx, object_scopes(obj), action)
