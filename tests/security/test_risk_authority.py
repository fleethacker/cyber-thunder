"""Separate risk authority at service and registered API boundaries; no live identity provider."""
from dataclasses import replace
import json
import time

import pytest

from cyberthunder.control.principal import principal_scope
from cyberthunder.control.roles import route_action
from cyberthunder.findings.review import ReviewService
from tests.findings.test_risk_acceptance import accept, revoke
from tests.security.test_identity_boundary import verified_app, identity, headers


@pytest.fixture
def risk_app(verified_app):
    ctx, proposals, tokens, client, app = verified_app
    document = json.loads(ctx.access.path.read_text())
    # An exact account grant for alpha, independent of its ordinary review grant.
    document["entries"][0]["grants"].append({"actions": ["risk.accept"], "target_ids": ["alpha"], "environments": ["alpha"]})
    ctx.access.path.write_text(json.dumps(document), encoding="utf-8")
    finding = next(f for f in ctx.store.current_findings() if f.host == "alpha")
    yield ctx, ReviewService(ctx), finding, tokens, client, document
    assert ctx.audit.verify().ok


def write_policy(ctx, document):
    ctx.access.path.write_text(json.dumps(document), encoding="utf-8")


def body(service, finding):
    from datetime import datetime, timedelta, timezone
    view = service.summary(finding)
    return dict(reason="Owner documented temporary operational constraint", supporting_evidence="Approved maintenance schedule",
                expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                expected_revision=view["revision"], evidence_fingerprint=view["evidence_fingerprint"])


def test_registered_routes_record_exact_acted_account_and_assurance(risk_app):
    ctx, service, finding, tokens, client, _ = risk_app
    person = replace(identity(), amr=("pwd", "otp"), session_id="private-session-reference")
    # Core records all validated evidence; API fixture validator intentionally models only a subset.
    with principal_scope(person):
        result = accept(service, finding, actor=person.actor)
    assert result["current"]["reviewed_principal"] == person.evidence()
    assert "private-session-reference" not in json.dumps(result)
    pending = next(r for r in ctx.audit.records() if r["action"] == "finding.risk_acceptance" and r["outcome"] == "pending")
    assert pending["details"]["event"] == result["current"]
    path = f"/api/v1/findings/{finding.id}/risk-acceptance"
    payload = body(service, finding)
    payload.pop("expires_at"); payload.pop("supporting_evidence")
    revoked = client.post(path + "/revoke", json=payload, headers=headers(tokens))
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["risk_acceptance_status"] == "revoked"
    saved = client.put(path, json=body(service, finding), headers=headers(tokens))
    assert saved.status_code == 200, saved.text
    assert saved.json()["current"]["reviewed_by"] == person.actor
    assert saved.json()["current"]["reviewed_principal"]["acr"] == person.acr
    assert route_action("PUT", "/api/v1/findings/{finding_id}/risk-acceptance") == "risk.accept"
    assert route_action("POST", "/api/v1/findings/{finding_id}/risk-acceptance/revoke") == "risk.accept"
    assert "risk.accept" in client.get("/api/v1/whoami", headers=headers(tokens)).json()["permissions"]


@pytest.mark.parametrize("case", ["review_only", "other_account", "other_target", "other_environment", "group",
    "wildcard_target", "wildcard_environment", "missing_environment", "missing_target", "node_only", "no_grants",
    "same_person_other_account"])
def test_explicit_account_environment_target_grant_cannot_be_inferred(risk_app, case):
    ctx, service, finding, tokens, client, doc = risk_app
    row = doc["entries"][0]
    grant = row["grants"].pop()
    person = identity()
    if case == "review_only":
        row["grants"][0]["actions"] = ["read", "review"]
    elif case == "no_grants":
        row["grants"] = []
    elif case == "node_only":
        row["node_actions"].append("risk.accept")
    elif case == "group":
        doc["entries"].append(dict(issuer=person.issuer, group="operators", node_actions=[], grants=[grant]))
        person = replace(person, groups=("operators",))
    else:
        row["grants"].append(grant)
        if case == "other_account":
            person = identity("second-user")
        elif case == "other_target":
            grant["target_ids"] = ["beta"]
        elif case == "other_environment":
            grant["environments"] = ["beta"]
        elif case == "wildcard_target":
            grant["target_ids"] = ["*"]
        elif case == "wildcard_environment":
            grant["environments"] = ["*"]
        elif case == "missing_environment":
            grant.pop("environments")
        elif case == "missing_target":
            grant.pop("target_ids")
        elif case == "same_person_other_account":
            doc.update(version=2, approval_identity=dict(mode="person", version=1, namespace="fixture", revision=1))
            row["person_id"] = "same-person"
            doc["entries"].append(dict(issuer=person.issuer, subject="other-login", person_id="same-person",
                node_actions=[], grants=[dict(actions=["read", "review"], target_ids=["alpha"], environments=["alpha"])]))
            person = identity("other-login")
    write_policy(ctx, doc)
    with principal_scope(person), pytest.raises(PermissionError):
        accept(service, finding, actor=person.actor)
    response = client.put(f"/api/v1/findings/{finding.id}/risk-acceptance", json=body(service, finding), headers=headers(tokens, person))
    assert response.status_code == 403, response.text
    assert service.summary(finding)["revision"] == 0


@pytest.mark.parametrize("case", ["stale", "expired", "wrong_acr", "no_acr", "no_config", "no_auth_time",
    "future_auth", "workload", "admin", "typed_actor", "no_identity", "revoked_session"])
@pytest.mark.parametrize("operation", ["accept", "revoke"])
def test_missing_current_human_assurance_denies_accept_and_revoke(risk_app, case, operation):
    ctx, service, finding, _, _, _ = risk_app
    person = identity()
    if operation == "revoke":
        with principal_scope(person):
            accept(service, finding, actor=person.actor)
    before = service.history(finding)
    actor = person.actor
    changes = {"stale": dict(auth_time=int(time.time()) - 301), "expired": dict(expires_at=time.time() - 1),
               "wrong_acr": dict(acr="weak"), "no_acr": dict(acr=None), "no_auth_time": dict(auth_time=None),
               "future_auth": dict(auth_time=int(time.time()) + 60), "workload": dict(kind="workload"),
               "admin": dict(roles=("admin",))}
    person = replace(person, **changes.get(case, {}))
    if case == "workload":
        actor = person.actor
    if case == "typed_actor":
        actor = "Typed Name"
    if case == "no_config":
        ctx.settings.step_up_acr_values = ()
    if case == "no_identity":
        person = None
    def validity():
        if case == "revoked_session":
            raise PermissionError("session revoked")
    with principal_scope(person, validity=validity), pytest.raises(PermissionError):
        (accept if operation == "accept" else revoke)(service, finding, actor=actor)
    assert service.history(finding) == before


@pytest.mark.parametrize("change", ["grant", "session", "assurance", "ownership"])
@pytest.mark.parametrize("operation", ["accept", "revoke"])
def test_current_authority_rechecked_after_pending_audit(risk_app, monkeypatch, change, operation):
    ctx, service, finding, _, _, doc = risk_app
    person = identity()
    if operation == "revoke":
        with principal_scope(person):
            accept(service, finding, actor=person.actor)
    before = service.history(finding)
    pending = False
    append = ctx.audit.append
    def audit(*args, **kwargs):
        nonlocal pending
        result = append(*args, **kwargs)
        if args[0] == "finding.risk_acceptance" and kwargs.get("outcome") == "pending":
            pending = True
            if change == "grant":
                doc["entries"][0]["grants"].pop()
                write_policy(ctx, doc)
            if change == "assurance":
                ctx.settings.step_up_acr_values = ("different-assurance",)
            if change == "ownership":
                ctx.inventory.get("alpha").environment = "new-owner"
                ctx.inventory.save()
        return result
    def validity():
        if pending and change == "session":
            raise PermissionError("revoked")
    monkeypatch.setattr(ctx.audit, "append", audit)
    with principal_scope(person, validity=validity), pytest.raises(PermissionError):
        (accept if operation == "accept" else revoke)(service, finding, actor=person.actor)
    assert pending and service.history(finding) == before


def test_api_challenge_no_typed_provenance_and_no_generic_reversal(risk_app):
    _, service, finding, tokens, client, _ = risk_app
    path = f"/api/v1/findings/{finding.id}"
    stale = replace(identity(), auth_time=int(time.time()) - 301)
    response = client.put(path + "/risk-acceptance", json=body(service, finding), headers=headers(tokens, stale))
    assert response.status_code == 401 and response.json()["error"] == "insufficient_user_authentication"
    assert "max_age" in response.headers["WWW-Authenticate"]
    for extra in (dict(actor="Typed"), dict(identity_verified=True), dict(reviewed_principal=identity().evidence())):
        result = client.put(path + "/risk-acceptance", json=body(service, finding) | extra, headers=headers(tokens))
        assert result.status_code == 400, result.text
    assert client.put(path + "/risk-acceptance?scan_id=scan-both", json=body(service, finding), headers=headers(tokens)).status_code == 400
    payload = body(service, finding)
    assert client.put(path + "/review", json=payload | dict(disposition="risk_accepted"), headers=headers(tokens)).status_code == 400
    assert client.put(path + "/risk-acceptance", json=payload, headers=headers(tokens)).status_code == 200
    assert client.put(path + "/review", json=body(service, finding) | dict(disposition="unreviewed"), headers=headers(tokens)).status_code == 409


def test_saved_receipt_never_grants_revocation_or_apply(risk_app):
    ctx, service, finding, tokens, client, doc = risk_app
    with principal_scope(identity()):
        accepted = accept(service, finding, actor=identity().actor)
    doc["entries"][0]["grants"] = [dict(actions=["read", "review"], target_ids=["alpha"], environments=["alpha"])]
    write_policy(ctx, doc)
    with principal_scope(identity()), pytest.raises(PermissionError):
        revoke(service, finding, actor=identity().actor)
    assert service.history(finding) == accepted
    proposal = next(p for p in ctx.gate.list() if p.host == "alpha")
    response = client.post(f"/api/v1/proposals/{proposal.id}/apply", json={}, headers=headers(tokens))
    assert response.status_code == 403
    doc["entries"][0]["grants"][0]["actions"].append("risk.accept")
    write_policy(ctx, doc)
    with principal_scope(identity()):
        assert revoke(service, finding, actor=identity().actor)["risk_acceptance_status"] == "revoked"
    # Even a correctly authorized revocation is not an apply grant or an approval.
    assert client.post(f"/api/v1/proposals/{proposal.id}/apply", json={}, headers=headers(tokens)).status_code == 403
    assert ctx.gate.get(proposal.id).state.value == "proposed"
