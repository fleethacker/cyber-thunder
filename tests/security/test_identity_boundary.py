"""Identity and resource boundaries using a controlled validated-token adapter, never real credentials."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import time

import pytest
from fastapi.testclient import TestClient

from cyberthunder.api.app import create_app
from cyberthunder.api.auth import validate_bind
from cyberthunder.api.util import run_background
from cyberthunder.audit.chain import verify_file
from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.control.access import AccessPolicy, ACTIONS
from cyberthunder.control.principal import Principal, current_principal, principal_scope, require_current
from cyberthunder.control.roles import permissions
from cyberthunder.findings.schema import Finding, Severity, Status
from cyberthunder.inventory.targets import Target
from cyberthunder.remediation.library import FixEntry


def identity(subject="first-user", roles=("analyst", "approver"), kind="human"):
    return Principal("https://identity.example.test", subject, "Test operator", roles=roles,
                     kind=kind, expires_at=time.time() + 300)


def proposal(ctx, target):
    finding = next(f for f in ctx.store.load_findings("scan-both") if f.host == target)
    return ctx.gate.propose(actor=current_principal().actor, finding_id=finding.id, host=target, title="Test change",
                            fix_ref="fixture:setting", fix_preview="reviewed setting", rollback_plan="restore",
                            risk="test fixture")


@pytest.fixture
def verified_app(state_dir, monkeypatch):
    ctx = AppContext(Settings(state_dir=state_dir, auth_mode="dev", security_mode="range",
                              llm_backend="template", auto_propose=False, explain_precompute=False))
    for tid in ("alpha", "beta"):
        ctx.inventory.add(Target(tid, tid, "linux", transport="simulated", simulated=True, environment=tid))
    ctx.inventory.save()
    ctx.store.save_scan_run({"id": "scan-both", "targets": ["alpha", "beta"], "status": "done"})
    ctx.store.save_findings("scan-both", [Finding(host=tid, asset_type="linux", source="fixture",
        rule_id="test-rule", title="Finding on " + tid, severity=Severity.MEDIUM,
        status=Status.OPEN) for tid in ("alpha", "beta")])
    ctx.settings.auth_mode = "oidc"
    path = state_dir / "auth" / "access.json"
    path.parent.mkdir(mode=0o700)
    path.write_text(json.dumps({"version": 1, "entries": [
        {"issuer": identity().issuer, "subject": subject,
         "node_actions": ["kill.engage", "kill.release", "audit"],
         "grants": [{"target_ids": [tid], "actions": sorted(ACTIONS - {"read.all"})}]}
        for subject, tid in (("first-user", "alpha"), ("second-user", "beta"),
                            ("fixture-proposer", "alpha"), ("fixture-proposer-beta", "beta"))]}))
    path.chmod(0o600)
    ctx.access = AccessPolicy(path)
    ctx.gate.authorizer = ctx.authorize
    ctx.killswitch.authorizer = ctx.authorize
    ctx.library.add(FixEntry("fixture:setting", "Test change", "linux", ["test-rule"], payload="reviewed setting"))
    proposals = {}
    for subject, tid in (("fixture-proposer", "alpha"), ("fixture-proposer-beta", "beta")):
        with principal_scope(identity(subject, roles=("analyst",))):
            proposals[tid] = proposal(ctx, tid)
    tokens = {}

    class Validator:
        def validate(self, token):
            p = tokens[token]
            if p.expires_at <= time.time():
                raise ValueError("expired")
            return {"iss": p.issuer, "sub": p.subject, "name": p.display_name, "ct_kind": p.kind,
                    "ct_roles": list(p.roles), "exp": p.expires_at}

    monkeypatch.setattr("cyberthunder.api.auth.make_validator", lambda *_: Validator())
    app = create_app(ctx)
    with TestClient(app) as client:
        yield ctx, proposals, tokens, client, app


def headers(tokens, principal=None):
    principal = principal or identity()
    token = "fixture-" + str(len(tokens))
    tokens[token] = principal
    return {"Authorization": "Bearer " + token, "X-Actor": "forged administrator"}


def test_every_api_route_requires_a_valid_token(verified_app):
    ctx, _, _, client, app = verified_app
    seen = 0
    import re
    for template, methods in app.openapi()["paths"].items():
        if not template.startswith("/api/v1"):
            continue
        path = re.sub(r"\{[^}]+\}", "unknown", template)
        for method in methods:
            method = method.upper()
            response = client.request(method, path, headers={"X-Actor": "administrator"}, json={})
            assert response.status_code == 401, (method, path, response.text)
            seen += 1
    assert seen > 60
    assert all(p.state.value == "proposed" for p in ctx.gate.list())


def test_targets_and_findings_filter_before_counts_facets_and_pagination(verified_app):
    _, _, tokens, client, _ = verified_app
    h = headers(tokens)
    assert [t["id"] for t in client.get("/api/v1/targets", headers=h).json()["targets"]] == ["alpha"]
    result = client.get("/api/v1/findings?limit=1", headers=h)
    assert result.status_code == 200, result.text
    doc = result.json()
    assert doc["unfiltered_total"] == doc["total"] == 1
    assert doc["findings"][0]["host"] == "alpha"
    assert "beta" not in json.dumps(doc)


def test_limited_account_status_does_not_need_global_history_access(verified_app):
    ctx, _, tokens, client, _ = verified_app
    before = len(ctx.audit)
    h = headers(tokens)
    response = client.get("/api/v1/status", headers=h)
    assert response.status_code == 200, response.text
    doc = response.json()
    assert doc["global_details"] is False and doc["targets"] == 1
    assert doc["audit"]["count"] is None and doc["outbox"]["pending"] is None
    assert doc["link"] is None and doc["llm"] is None
    assert "beta" not in json.dumps(doc)
    assert len(ctx.audit) == before
    assert client.get("/api/v1/whoami", headers=h).json()["principal"]["sub"] == "first-user"


def test_cross_target_proposal_access_and_approval_are_denied(verified_app):
    ctx, proposals, tokens, client, _ = verified_app
    h = headers(tokens)
    pid = proposals["beta"].id
    for method, path in (("GET", f"/proposals/{pid}"), ("POST", f"/proposals/{pid}/approve"),
                         ("POST", f"/proposals/{pid}/apply"), ("POST", f"/proposals/{pid}/rollback")):
        response = client.request(method, "/api/v1" + path, headers=h, json={})
        assert response.status_code == 403, response.text
    assert ctx.gate.get(pid).state.value == "proposed"


def test_approval_uses_verified_subject_and_hash_covered_provenance(verified_app):
    ctx, proposals, tokens, client, _ = verified_app
    p = identity()
    response = client.post(f"/api/v1/proposals/{proposals['alpha'].id}/approve", headers=headers(tokens, p), json={})
    assert response.status_code == 200, response.text
    assert ctx.gate.get(proposals["alpha"].id).decided_by == p.actor
    assert ctx.gate.get(proposals["alpha"].id).decided_principal["sub"] == p.subject
    assert ctx.gate.get(proposals["alpha"].id).history[-1]["principal"]["sub"] == p.subject
    rows = [json.loads(line) for line in ctx.audit.path.read_text().splitlines()]
    record = next(row for row in rows if row["action"] == "proposal.approved")
    assert record["v"] == 2 and record["principal"]["sub"] == p.subject
    assert "forged administrator" not in json.dumps(rows)
    assert verify_file(ctx.audit.path).ok
    record["principal"]["sub"] = "altered"
    ctx.audit.path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    assert not verify_file(ctx.audit.path).ok


@pytest.mark.parametrize("identity_options", [{"roles": ("admin",)}, {"kind": "workload"}])
def test_admin_role_and_service_accounts_cannot_approve(verified_app, identity_options):
    ctx, proposals, tokens, client, _ = verified_app
    # Mint the short-lived fixture when the case runs, not during suite collection.
    person = identity(**identity_options)
    response = client.post(f"/api/v1/proposals/{proposals['alpha'].id}/approve",
                           headers=headers(tokens, person), json={})
    assert response.status_code == 403
    assert ctx.gate.get(proposals["alpha"].id).state.value == "proposed"


def test_gate_direct_calls_do_not_accept_typed_actor_or_wrong_resource(verified_app):
    ctx, proposals, _, _, _ = verified_app
    with pytest.raises(PermissionError):
        ctx.gate.approve(proposals["alpha"].id, "administrator")
    p = identity()
    with principal_scope(p):
        with pytest.raises(PermissionError):
            ctx.gate.approve(proposals["alpha"].id, "administrator")
        with pytest.raises(PermissionError):
            ctx.gate.approve(proposals["beta"].id, p.actor)
        with pytest.raises(PermissionError):
            ctx.gate.cancel(proposals["beta"].id, p.actor)


def test_request_context_does_not_cross_accounts_or_leak_after_background_work(verified_app):
    _, _, tokens, client, _ = verified_app
    people = [identity(), identity("second-user")]
    hs = [headers(tokens, p) for p in people]
    with ThreadPoolExecutor(max_workers=2) as pool:
        docs = list(pool.map(lambda h: client.get("/api/v1/whoami", headers=h).json(), hs))
    assert [doc["principal"]["sub"] for doc in docs] == [p.subject for p in people]
    seen = []
    with principal_scope(people[0]):
        thread = run_background(lambda: seen.append(require_current("scan").actor), "identity-test")
        thread.join(2)
    assert seen == [people[0].actor]
    assert current_principal() is None
    assert client.get("/api/v1/whoami").status_code == 401


@pytest.mark.parametrize("method", ["start_apply", "applied", "verified", "failed", "rolled_back"])
def test_gate_machine_edges_still_require_account_and_target_permission(verified_app, method):
    ctx, proposals, _, _, _ = verified_app
    with pytest.raises(PermissionError):
        getattr(ctx.gate, method)(proposals["alpha"].id)
    with principal_scope(identity()):
        with pytest.raises(PermissionError):
            getattr(ctx.gate, method)(proposals["beta"].id)


def test_unknown_routes_and_methods_have_no_implicit_read_permission():
    from cyberthunder.control.roles import route_action
    assert route_action("GET", "/new/unreviewed") is None
    assert route_action("POST", "/targets") == "admin"
    assert route_action("PATCH", "/targets") is None


def test_local_cli_cannot_bypass_verified_mode(monkeypatch, capsys, tmp_path):
    from cyberthunder.cli import main
    monkeypatch.setenv("CT_AUTH_MODE", "oidc")
    assert main(["--state-dir", str(tmp_path), "proposals", "list"]) == 2
    assert "authenticated API" in capsys.readouterr().err
    assert not (tmp_path / "proposals.json").exists()


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.1", "localhost.example.test"])
def test_unverified_network_binding_refused(host):
    with pytest.raises(ValueError, match="loopback"):
        validate_bind(Settings(auth_mode="dev", security_mode="range"), host)


def test_network_requires_tls_and_fleet_requires_verified_identity():
    with pytest.raises(ValueError, match="TLS"):
        validate_bind(Settings(auth_mode="oidc", security_mode="range"), "0.0.0.0")
    with pytest.raises(ValueError, match="verified"):
        validate_bind(Settings(auth_mode="dev", security_mode="fleet"), "127.0.0.1")
    validate_bind(Settings(auth_mode="mesh", security_mode="fleet"), "0.0.0.0")


def test_identity_keys_include_issuer_and_expiration_is_checked_again():
    p = identity()
    assert p.actor != replace(p, issuer="https://another.example.test").actor
    assert "approve" not in permissions(replace(p, kind="workload"))
    with principal_scope(replace(p, expires_at=time.time() - 1)):
        with pytest.raises(PermissionError, match="expired"):
            require_current("approve")
