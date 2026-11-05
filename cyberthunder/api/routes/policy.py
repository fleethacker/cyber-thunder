"""Standing approval policy. Off by default. Enabling it is a signed act: the server records the actor as
signer, the time, and requires a reason. Every change bumps the version and is audited."""
from __future__ import annotations

from datetime import time as dtime

from fastapi import APIRouter

from cyberthunder.api import util
from cyberthunder.api.errors import MappedRoute
from cyberthunder.api.schemas import EvaluateBody, PolicyBody
from cyberthunder.api.util import ActorDep, CtxDep
from cyberthunder.control.policy import AutomationPolicy, PolicyRule, evaluate_for_context
from cyberthunder.findings.schema import utcnow
from cyberthunder.inventory.targets import ASSET_TYPES
from cyberthunder.remediation.library import DISRUPTION_RANK

router = APIRouter(tags=["policy"], route_class=MappedRoute)

SEVERITIES = ("high", "medium", "low")
LIST_FIELDS = ("asset_types", "fix_allowlist", "target_allowlist")
BOOL_FIELDS = ("allow_reboot", "allow_patch", "allow_service_restart")


def _check_types(d: dict) -> dict:
    """JSON types the dataclass does not enforce. Null lists mean 'empty' (any)."""
    d = dict(d)
    name = d.get("name")
    for k in LIST_FIELDS:
        if k in d and d[k] is None:
            d[k] = []
        elif k in d and not (isinstance(d[k], list) and all(isinstance(x, str) for x in d[k])):
            raise ValueError(f"rule {name}: {k} must be a list of strings")
    for k in BOOL_FIELDS:
        if k in d and not isinstance(d[k], bool):
            raise ValueError(f"rule {name}: {k} must be true or false")
    for k in ("name", "max_disruption", "max_severity", "window_start", "window_end"):
        if d.get(k) is not None and not isinstance(d[k], str):
            raise ValueError(f"rule {name}: {k} must be a string")
    return d


def parse_rule(d: dict) -> PolicyRule:
    if not isinstance(d, dict):
        raise ValueError("each rule must be an object")
    d = _check_types(d)
    try:
        r = PolicyRule(**d)
    except TypeError as e:
        raise ValueError(f"invalid policy rule: {e}") from e
    if not str(r.name or "").strip():
        raise ValueError("every rule needs a name")
    if r.max_disruption not in DISRUPTION_RANK:
        raise ValueError(f"rule {r.name}: max_disruption must be one of {list(DISRUPTION_RANK)}")
    if r.max_severity is not None and r.max_severity not in SEVERITIES:
        raise ValueError(f"rule {r.name}: max_severity must be one of {list(SEVERITIES)} or null")
    bad = [a for a in r.asset_types if a not in ASSET_TYPES]
    if bad:
        raise ValueError(f"rule {r.name}: unknown asset types {bad}")
    if bool(r.window_start) != bool(r.window_end):
        raise ValueError(f"rule {r.name}: set both window_start and window_end, or neither")
    for w in (r.window_start, r.window_end):
        if w:
            try:
                dtime.fromisoformat(w)
            except ValueError:
                raise ValueError(f"rule {r.name}: window time {w!r} is not HH:MM") from None
    return r


@router.get("/policy")
def get_policy(ctx=CtxDep) -> dict:
    return ctx.policy.to_dict()


@router.put("/policy")
def put_policy(body: PolicyBody, ctx=CtxDep, actor: str = ActorDep) -> dict:
    cur: AutomationPolicy = ctx.policy
    rules = [parse_rule(r) for r in body.rules] if body.rules is not None else list(cur.rules)
    names = [r.name for r in rules]
    if len(set(names)) != len(names):
        raise ValueError("rule names must be unique")
    reason = (body.reason or "").strip() or None
    enabled = cur.enabled if body.enabled is None else body.enabled
    if enabled:
        if not reason:
            raise ValueError("enabling a standing approval policy requires a reason")
        if not rules:
            raise ValueError("enabling a standing approval policy requires at least one rule")
        new = AutomationPolicy(enabled=True, signed_by=actor, signed_at=utcnow(), reason=reason, rules=rules,
                               version=cur.version + 1)
    else:
        # disabled: keep the last signature for the record, note who changed it in the audit log
        new = AutomationPolicy(enabled=False, signed_by=cur.signed_by, signed_at=cur.signed_at,
                               reason=reason or cur.reason, rules=rules, version=cur.version + 1)
    ctx.save_policy(new, actor)
    return new.to_dict()


@router.post("/policy/evaluate")
def evaluate_policy(body: EvaluateBody, ctx=CtxDep) -> dict:
    p = util.get_proposal(ctx, body.proposal_id)
    fix = ctx.library.get(p.fix_ref)
    if fix is None:
        raise KeyError(f"fix {p.fix_ref!r} is not in the library")
    finding = util.get_finding(ctx, p.finding_id)
    target = ctx.inventory.get(p.host)
    return evaluate_for_context(ctx, fix, finding, target).to_dict()
