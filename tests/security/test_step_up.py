"""Step-up policy and the core authorization boundary, independent of HTTP."""
from dataclasses import replace
from contextvars import copy_context
import json
import time
from types import SimpleNamespace

import pytest

from cyberthunder.config import Settings
from cyberthunder.control.principal import principal_scope
from cyberthunder.security.step_up import StepUpPolicy, StepUpRequired, require_step_up
from tests.security.test_identity_boundary import verified_app, identity, headers

ACR = "urn:ct:test:strong"


@pytest.mark.parametrize("claims,reason", [
    ({"auth_time": None}, "invalid_authentication_time"),
    ({"auth_time": True}, "invalid_authentication_time"),
    ({"auth_time": "1000"}, "invalid_authentication_time"),
    ({"auth_time": 1000.0}, "invalid_authentication_time"),
    ({"auth_time": float("nan")}, "invalid_authentication_time"),
    ({"auth_time": -1}, "invalid_authentication_time"),
    ({"auth_time": 1001}, "future_authentication_time"),
    ({"auth_time": 699}, "authentication_too_old"),
    ({"acr": None}, "assurance_not_accepted"),
    ({"acr": "urn:ct:test:stronger"}, "assurance_not_accepted"),
    ({"acr": "URN:CT:TEST:STRONG"}, "assurance_not_accepted"),
    ({"acr": "999", "amr": ["cac", "mfa"]}, "assurance_not_accepted"),
    ({"kind": "workload"}, "human_authentication_required"),
])
def test_exact_assurance_and_numeric_date_fail_closed(claims, reason):
    principal = SimpleNamespace(**({"verified": True, "kind": "human", "auth_time": 1000, "acr": ACR} | claims))
    with pytest.raises(StepUpRequired) as caught:
        StepUpPolicy(acr_values=(ACR,)).require(principal, now=1000)
    assert caught.value.reason == reason
    assert set(caught.value.challenge()) == {"reason", "max_age", "acr_values"}


def test_age_boundary_multiple_exact_acrs_and_explicit_dev():
    policy = StepUpPolicy(acr_values=(ACR, "urn:ct:test:alternate"))
    principal = replace(identity(), auth_time=700)
    policy.require(principal, now=1000)
    policy.require(replace(principal, acr="urn:ct:test:alternate"), now=1000)
    require_step_up(Settings(auth_mode="dev"), None, "approve")
    require_step_up(Settings(auth_mode="oidc"), None, "read")
    with pytest.raises(StepUpRequired, match="Fresh authentication"):
        require_step_up(Settings(auth_mode="oidc"), identity(), "approve")


@pytest.mark.parametrize("changes", [
    {"step_up_max_age_s": True}, {"step_up_max_age_s": 0}, {"step_up_max_age_s": 3601},
    {"step_up_max_age_s": "300"}, {"step_up_acr_values": [ACR]}, {"step_up_acr_values": (ACR, ACR)},
    {"step_up_acr_values": ("one two",)}, {"step_up_acr_values": ('bad"value',)},
    {"step_up_acr_values": ("bad\nvalue",)}, {"step_up_acr_values": ("",)},
    {"step_up_acr_values": tuple(str(n) for n in range(9))}, {"step_up_acr_values": ("x" * 129,)},
])
def test_settings_reject_invalid_policy(changes):
    with pytest.raises(ValueError, match="step-up"):
        Settings(**changes)
    with pytest.raises(ValueError, match="step-up"):
        Settings.from_env(**changes)


@pytest.mark.parametrize("name,value", [
    ("CT_STEP_UP_MAX_AGE_SECONDS", ""), ("CT_STEP_UP_MAX_AGE_SECONDS", "junk"),
    ("CT_STEP_UP_MAX_AGE_SECONDS", "300.0"), ("CT_STEP_UP_MAX_AGE_SECONDS", " 300"),
    ("CT_STEP_UP_ACR_VALUES", '"urn:ct:test:strong"'), ("CT_STEP_UP_ACR_VALUES", '[null]'),
    ("CT_STEP_UP_ACR_VALUES", '["same", "same"]'), ("CT_STEP_UP_ACR_VALUES", ""),
])
def test_environment_never_falls_back_from_invalid_values(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match="step-up"):
        Settings.from_env()


def test_environment_keeps_exact_configured_values(monkeypatch):
    monkeypatch.setenv("CT_STEP_UP_MAX_AGE_SECONDS", "120")
    monkeypatch.setenv("CT_STEP_UP_ACR_VALUES", json.dumps([ACR, "urn:ct:test:alternate"]))
    settings = Settings.from_env()
    assert StepUpPolicy.from_settings(settings) == StepUpPolicy(120, (ACR, "urn:ct:test:alternate"))


@pytest.mark.parametrize("action,target", [("approve", "alpha"), ("admin", "alpha"), ("kill.release", None), ("policy", None)])
def test_direct_core_refusal_is_audited_and_fresh_principal_is_allowed(verified_app, action, target):
    ctx, _, _, _, _ = verified_app
    if action == "policy":
        policy = json.loads(ctx.access.path.read_text())
        policy["entries"][0]["node_actions"].append("policy")
        ctx.access.path.write_text(json.dumps(policy))
    person = identity(roles=("approver", "admin"))
    old = replace(person, auth_time=int(time.time()) - 600)
    with principal_scope(old), pytest.raises(StepUpRequired):
        ctx.authorize(action, actor=old.actor, target=target)
    records = [json.loads(line) for line in ctx.audit.path.read_text().splitlines()]
    denied = [r for r in records if r["action"] == "authorization.denied"][-1]
    assert denied["outcome"] == "rejected"
    assert denied["details"]["step_up"]["reason"] == "authentication_too_old"
    assert denied["actor"] == person.actor
    with principal_scope(person):
        assert ctx.authorize(action, actor=person.actor, target=target) == person


def test_direct_approval_cannot_bypass_step_up_or_role_and_resource_grants(verified_app):
    ctx, proposals, _, _, _ = verified_app
    old = replace(identity(), auth_time=int(time.time()) - 600)
    with principal_scope(old), pytest.raises(StepUpRequired):
        ctx.gate.approve(proposals["alpha"].id, actor=old.actor)
    assert ctx.gate.get(proposals["alpha"].id).state.value == "proposed"
    for person, target in [(identity(roles=("viewer",)), "alpha"),
                           (identity(kind="workload"), "alpha"), (identity(), "beta")]:
        with principal_scope(person), pytest.raises(PermissionError) as caught:
            ctx.authorize("approve", actor=person.actor, target=target)
        assert not isinstance(caught.value, StepUpRequired)


def test_bulk_preflight_returns_a_challenge_instead_of_hiding_it_in_item_errors(verified_app):
    ctx, proposals, tokens, client, _ = verified_app
    h = headers(tokens, replace(identity(), auth_time=int(time.time()) - 600))
    result = client.post("/api/v1/proposals/bulk", headers=h, json={"action": "approve", "ids": [proposals["alpha"].id]})
    assert result.status_code == 401 and result.json()["error"] == "insufficient_user_authentication"
    assert ctx.gate.get(proposals["alpha"].id).state.value == "proposed"


def test_step_up_denial_never_proceeds_if_audit_is_unavailable(verified_app, monkeypatch):
    ctx, proposals, tokens, client, _ = verified_app
    def unavailable(*args, **kwargs):
        raise OSError("private storage detail")
    monkeypatch.setattr(ctx.audit, "append", unavailable)
    result = client.post(f"/api/v1/proposals/{proposals['alpha'].id}/approve", json={},
        headers=headers(tokens, replace(identity(), auth_time=int(time.time()) - 600)))
    assert result.status_code == 503
    assert result.json() == {"detail": "authorization audit unavailable"}
    assert ctx.gate.get(proposals["alpha"].id).state.value == "proposed"


def test_api_challenge_does_not_disclose_claims_and_keeps_policy_server_owned(verified_app):
    ctx, proposals, tokens, client, _ = verified_app
    person = replace(identity(), auth_time=int(time.time()) - 600, acr="private-unaccepted-value")
    response = client.post(f"/api/v1/proposals/{proposals['alpha'].id}/approve",
        headers=headers(tokens, person), json={"max_age": 99999, "acr": ACR, "auth_time": int(time.time())})
    assert response.status_code == 401
    assert response.json()["error"] == "insufficient_user_authentication"
    assert response.json()["step_up"] == {"reason": "authentication_too_old", "max_age": 300, "acr_values": [ACR]}
    assert response.headers["WWW-Authenticate"] == f'Bearer error="insufficient_user_authentication", max_age="300", acr_values="{ACR}"'
    assert response.headers["Cache-Control"] == "no-store"
    assert "private-unaccepted-value" not in response.text
    assert ctx.gate.get(proposals["alpha"].id).state.value == "proposed"


def test_copied_core_context_cannot_reuse_a_previous_freshness_decision(verified_app, monkeypatch):
    ctx, _, _, _, _ = verified_app
    now = time.time()
    person = replace(identity(), auth_time=int(now) - 299)
    with principal_scope(person):
        ctx.authorize("approve", actor=person.actor, target="alpha")
        captured = copy_context()
    monkeypatch.setattr("cyberthunder.security.step_up.time.time", lambda: now + 3)
    with pytest.raises(StepUpRequired) as caught:
        captured.run(ctx.authorize, "approve", actor=person.actor, target="alpha")
    assert caught.value.reason == "authentication_too_old"
