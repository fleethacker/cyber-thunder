"""Real principal/policy boundaries for inert service-job fixtures."""
from __future__ import annotations

import json
import time
from types import MethodType

from cyberthunder.context import AppContext
from cyberthunder.control.access import AccessPolicy
from cyberthunder.control.principal import Principal


def enable_auth(ctx, *, node=(), grants=(), subject="job-owner"):
    principal = Principal("https://identity.example.test", subject, "Fixture operator", kind="human",
                          roles=("admin", "analyst", "approver", "auditor"), expires_at=time.time() + 300,
                          auth_time=int(time.time()), acr="urn:ct:test:strong")
    path = ctx.store.root / "auth" / "access.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "entries": [{
        "issuer": principal.issuer, "subject": principal.subject, "node_actions": list(node),
        "grants": list(grants)}]}), encoding="utf-8")
    ctx.settings.auth_mode = "oidc"
    ctx.settings.step_up_acr_values = ("urn:ct:test:strong",)
    ctx.access = AccessPolicy(path)
    ctx.authorize = MethodType(AppContext.authorize, ctx)
    return principal


def revoke(ctx):
    ctx.access.path.write_text(json.dumps({"version": 1, "entries": []}), encoding="utf-8")
