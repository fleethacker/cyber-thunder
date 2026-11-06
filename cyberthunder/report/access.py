"""Export authorization over the artifacts actually consumed by a report.

Historical ownership must be checked before aggregation. A current inventory
lookup cannot establish who owned an old observation. Development mode retains
legacy reports, but never upgrades their missing ownership.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import dataclass, field
from functools import wraps
from types import SimpleNamespace

from cyberthunder.control.principal import authorize

_collection = ContextVar("report_ownership", default=None)


@dataclass
class _Ownership:
    ctx: object
    scopes: list = field(default_factory=list)
    complete: bool = True


def verified_mode(ctx):
    return getattr(getattr(ctx, "settings", None), "auth_mode", "dev") != "dev"


def artifact(ctx, scopes, *, targets=None):
    active = _collection.get()
    if verified_mode(ctx):
        from cyberthunder.security.resources import authorize_artifact
        authorize_artifact(ctx, scopes, "export")
    scopes = [scopes] if isinstance(scopes, dict) else scopes
    valid = (isinstance(scopes, list) and bool(scopes)
             and all(isinstance(s, dict) and set(s) == {"version", "target_id", "environment", "authorization_id"}
                     and type(s["version"]) is int and s["version"] == 1
                     and all(isinstance(s[k], str) and s[k] for k in ("target_id", "environment", "authorization_id"))
                     for s in scopes))
    if not valid or (targets is not None and {s["target_id"] for s in scopes} != set(targets)):
        if verified_mode(ctx):
            raise PermissionError("report contributor does not match its recorded ownership")
        if active is not None and active.ctx is ctx:
            active.complete = False
        return
    if active is not None and active.ctx is ctx:
        for scope in scopes:
            if scope not in active.scopes:
                active.scopes.append(deepcopy(scope))


def observations(ctx, findings):
    for finding in findings:
        artifact(ctx, getattr(finding, "authorization_scope", None), targets=[finding.host])
    return findings


def visible(ctx, scopes, *, targets=None):
    if not verified_mode(ctx):
        return True
    from cyberthunder.security.resources import visible_artifact
    if not visible_artifact(ctx, scopes, "export"):
        return False
    try:
        artifact(ctx, scopes, targets=targets)
        return True
    except PermissionError:
        return False


def proposals(ctx):
    items = list(ctx.gate.list())
    for proposal in items:
        artifact(ctx, getattr(proposal, "authorization_scope", None), targets=[proposal.host])
    return items


def scan(ctx, run):
    artifact(ctx, run.get("authorization_scopes"), targets=run.get("targets") or [])


def audit(ctx):
    # Audit is an explicit global permission; node export does not imply it.
    authorize(ctx, "audit")


def lifecycle(ctx):
    from cyberthunder.findings.current import CurrentFindings
    if not verified_mode(ctx):
        return CurrentFindings.for_context(ctx)
    items = proposals(ctx)
    audit(ctx)
    records = list(ctx.audit.records())
    by_id = {p.id: p for p in items}
    for record in records:
        if record.get("action") not in {"remediation.rollback", "remediation.rollback_mutation"}:
            continue
        details = record.get("details") or {}
        proposal = by_id.get(record.get("subject"))
        # Results attached to an immutable proposal inherit its checked owner.
        # Orphan results need their own scope; a target ID alone is insufficient.
        if proposal is None or details.get("target_id", proposal.host) != proposal.host:
            artifact(ctx, details.get("authorization_scope"), targets=[details.get("target_id")])
    view = SimpleNamespace(gate=SimpleNamespace(list=lambda: items),
                           audit=SimpleNamespace(records=lambda: records), store=ctx.store)
    return CurrentFindings.for_context(view)


def current_scopes(ctx):
    active = _collection.get()
    return deepcopy(active.scopes) if active is not None and active.ctx is ctx and active.complete else []


def finish(ctx, scopes):
    """Recheck before publishing; capture only after every historic scope matched."""
    if not verified_mode(ctx):
        return scopes
    from cyberthunder.security.resources import capture
    artifact(ctx, scopes)
    current = capture(ctx, [s["target_id"] for s in scopes])
    if sorted(current, key=lambda s: s["target_id"]) != sorted(scopes, key=lambda s: s["target_id"]):
        raise PermissionError("report ownership changed during rendering")
    return deepcopy(scopes)


@contextmanager
def collecting(ctx):
    active = _collection.get()
    if active is not None and active.ctx is ctx:
        yield active
        return
    ownership = _Ownership(ctx)
    token = _collection.set(ownership)
    try:
        yield ownership
    finally:
        _collection.reset(token)


def rendered(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        authorize(self.ctx, "export")
        with collecting(self.ctx):
            result = method(self, *args, **kwargs)
            scopes = current_scopes(self.ctx)
            if scopes:
                finish(self.ctx, scopes)
            authorize(self.ctx, "export")
            return result
    return wrapped
