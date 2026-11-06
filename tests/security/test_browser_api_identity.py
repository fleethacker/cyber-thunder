"""Real signed browser sessions at the application API boundary."""
from contextvars import copy_context
from dataclasses import replace
import json
import time

import pytest
from fastapi.testclient import TestClient

from cyberthunder.api.app import create_app
from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.control.access import AccessPolicy
from cyberthunder.control.principal import Principal, current_principal, principal_scope, require_current
from cyberthunder.findings.schema import Finding
from cyberthunder.inventory.targets import Target
from cyberthunder.remediation.library import FixEntry
from cyberthunder.security.oidc import OIDCValidator
from tests.security.test_sessions import crypto, provider, configured, ORIGIN, ISSUER, advance


@pytest.fixture
def browser_api(state_dir, configured, provider, monkeypatch):
    config, access = configured
    ctx = AppContext(Settings(state_dir=state_dir, auth_mode="dev", security_mode="range",
                              llm_backend="template", auto_propose=False, explain_precompute=False))
    ctx.inventory.add(Target("alpha", "Alpha", "linux", transport="simulated", simulated=True))
    ctx.inventory.save()
    finding = Finding(host="alpha", source="fixture", rule_id="fixture-rule", title="Change setting",
                      severity="medium", status="open", asset_type="linux")
    ctx.store.save_scan_run({"id": "browser-fixture", "targets": ["alpha"], "status": "done"})
    ctx.store.save_findings("browser-fixture", [finding])
    ctx.library.add(FixEntry("fixture:setting", "Change setting", "linux", [finding.rule_id],
                             payload="reviewed setting"))
    ctx.settings.auth_mode = "oidc"
    ctx.settings.step_up_acr_values = ("urn:ct:test:strong",)
    ctx.session_config = replace(config, step_up_acr_values=ctx.settings.step_up_acr_values)
    path = state_dir / "auth" / "access.json"
    path.parent.mkdir(mode=0o700)
    path.write_text(json.dumps({"version": 1, "entries": [{"issuer": ISSUER, "subject": "operator-123",
        "node_actions": [], "grants": [{"target_ids": ["alpha"],
        "actions": ["read", "approve", "discover"]}]},
        {"issuer": ISSUER, "subject": "fixture-proposer", "node_actions": [],
         "grants": [{"target_ids": ["alpha"], "actions": ["read", "propose"]}]}]}))
    path.chmod(0o600)
    ctx.access = AccessPolicy(path)
    ctx.gate.authorizer = ctx.authorize
    ctx.gate.separation_policy = ctx.access.approval_identity_source
    ctx.killswitch.authorizer = ctx.authorize
    proposer = Principal(ISSUER, "fixture-proposer", "Fixture proposer", kind="human", roles=("analyst",),
                         expires_at=time.time() + 300)
    with principal_scope(proposer):
        item = ctx.engine.propose(ctx.store.get_finding(finding.id), actor=proposer.actor)
    provider.access_changes.update(ct_kind="human", ct_roles=["analyst", "approver"])
    provider.id_changes.update(auth_time=int(time.time()), acr="urn:ct:test:strong", amr=["fixture"])
    monkeypatch.setattr("cyberthunder.api.auth.make_validator", lambda *_: OIDCValidator(access))
    app = create_app(ctx)
    with TestClient(app, base_url=ORIGIN) as client:
        yield ctx, item, client, app


def sign_in(client, provider):
    login = client.get("/auth/login", follow_redirects=False)
    assert login.status_code == 303, login.text
    callback = client.get("/auth/callback?" + provider.authorize(login.headers["location"]), follow_redirects=False)
    assert callback.status_code == 303, callback.text
    status = client.get("/auth/status").json()
    assert status["authenticated"] is True
    return {"Origin": ORIGIN, "X-CSRF-Token": status["csrf_token"]}, status


def test_signed_browser_session_drives_verified_approval_without_browser_tokens(browser_api, provider):
    ctx, item, client, _ = browser_api
    assert client.get("/api/v1/targets").status_code == 401
    headers, status = sign_in(client, provider)
    assert status["principal"]["verified"] is True
    assert status["principal"]["subject"] == "operator-123"
    assert not {"access_token", "refresh_token", "id_token"}.intersection(status)
    assert client.get("/api/v1/targets").status_code == 200
    path = f"/api/v1/proposals/{item.id}/approve"
    assert client.post(path, json={}, headers={"X-Actor": "administrator"}).status_code in {401, 403}
    response = client.post(path, json={}, headers={**headers, "X-Actor": "forged administrator"})
    assert response.status_code == 200, response.text
    assert response.headers["Cache-Control"] == "no-store"
    assert "Authorization" in response.headers["Vary"]
    saved = ctx.gate.get(item.id)
    assert saved.decided_principal["sub"] == "operator-123"
    assert saved.decided_by != "forged administrator"
    assert "forged administrator" not in ctx.audit.path.read_text()
    assert client.post("/auth/logout", headers=headers).status_code == 204
    assert client.get("/api/v1/targets").status_code == 401


def test_logout_revokes_already_copied_request_context(browser_api, provider, monkeypatch):
    ctx, _, client, _ = browser_api
    headers, _ = sign_in(client, provider)
    captured = []
    original = ctx.may_access
    def capture(target, action="read"):
        captured.append(copy_context())
        return original(target, action)
    monkeypatch.setattr(ctx, "may_access", capture)
    assert client.get("/api/v1/targets").status_code == 200
    assert captured and captured[0].run(require_current, "read").subject == "operator-123"
    assert current_principal() is None
    assert client.post("/auth/logout", headers=headers).status_code == 204
    with pytest.raises(PermissionError):
        captured[0].run(require_current, "read")


def test_passive_status_poll_does_not_extend_idle_session(browser_api, provider, monkeypatch):
    _, _, client, app = browser_api
    sign_in(client, provider)
    duration = app.state.sessions.config.idle_timeout_s
    advance(monkeypatch, duration - 1)
    assert client.get("/auth/status").json()["authenticated"] is True
    advance(monkeypatch, 2)
    assert client.get("/auth/status").json()["authenticated"] is False
    assert client.get("/api/v1/targets").status_code == 401
