"""Real account selection and publication guards with synthetic vSphere wire I/O."""
from __future__ import annotations

import base64
import json
import logging
import socket
import threading
import time
from dataclasses import replace
from types import SimpleNamespace
from urllib.parse import quote
from xml.sax.saxutils import escape

import pytest

from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.control.principal import operation_scope, principal_scope
from cyberthunder.control.principal import Principal
from cyberthunder.discovery.service import DiscoveryService, SCOPE_COMPLETE
from cyberthunder.discovery.sources import vsphere, vsphere_access, vsphere_client as wire
from cyberthunder.inventory.targets import Target
from cyberthunder.security.credentials import bind_target, CredentialError
from tests.security.canary_helpers import CanaryProbe
from tests.security.test_kube_credentials import cert_material

from .vsphere_support import PASSWORD, Response, Server


def identity(subject="alice", **kw):
    fields = dict(issuer="https://identity.example.test", subject=subject, display_name="Fixture operator",
                  kind="human", roles=("analyst", "auditor"), expires_at=time.time() + 600)
    fields.update(kw)
    return Principal(**fields)


def account(subject="alice", *, group=None, target="vc", environment="A", ref="ALICE_VC"):
    return {"issuer": identity().issuer, "group" if group else "subject": group or subject,
            "node_actions": ["discover", "read.all", "audit"],
            "grants": [{"target_ids": [target], "environments": [environment], "actions": ["discover", "read"],
                        "credential": {"username": subject + "@lab", "credential_ref": ref,
                                       "sudo": False, "options": {"transport": "vsphere"}}}]}


@pytest.fixture
def configured(state_dir, monkeypatch):
    ctx = AppContext(Settings(state_dir=state_dir, auth_mode="oidc", security_mode="fleet",
                              llm_backend="template", auto_propose=False, explain_precompute=False))
    path = state_dir / "auth" / "access.json"
    path.parent.mkdir(mode=0o700)

    def policy(entries):
        path.write_text(json.dumps({"version": 1, "entries": entries}), encoding="utf-8")
        path.chmod(0o600)

    policy([account(), account("bob", target="vc-b", environment="B", ref="BOB_VC")])
    target = Target("vc", "Inventory A", "linux", transport="vsphere", address="10.20.0.2", environment="A",
                    username="inventory-root", credential_ref="SHARED", options={
                        "hypervisor": "vsphere", "vsphere": {"endpoint": "https://vc.lab/sdk", "tls_trust": "system",
                                                               "username": "shared@lab", "credential_ref": "SHARED"}})
    other = replace(target, id="vc-b", name="Inventory B", environment="B", address="10.20.0.3",
                    options={"hypervisor": "vsphere", "vsphere": {"endpoint": "https://other.lab/sdk", "tls_trust": "system"}})
    ctx.inventory.add_new(target)
    ctx.inventory.add_new(other)
    monkeypatch.setenv("CT_CRED_ALICE_VC", PASSWORD)
    monkeypatch.setenv("CT_CRED_BOB_VC", "different-fixture-password")
    monkeypatch.setenv("CT_CRED_SHARED", "shared-must-not-be-used")
    svc = DiscoveryService(ctx)
    svc.set_scopes(["10.20.0.0/24"], "Fixture setup", "Fixture endpoint and guest range")
    monkeypatch.setattr(svc, "_passive", lambda scope, run: ([], SCOPE_COMPLETE))
    monkeypatch.setattr(ctx, "transport_for", lambda _: pytest.fail("vSphere cannot borrow an OS transport"))
    server = Server(monkeypatch)
    original_connect = socket.socket.connect
    monkeypatch.setattr(socket.socket, "connect", lambda *_: pytest.fail("no real network allowed"))
    monkeypatch.setattr(socket.socket, "connect_ex", lambda *_: pytest.fail("no real network allowed"))
    monkeypatch.setattr(socket, "create_connection", lambda *_a, **_k: pytest.fail("no real network allowed"))
    return SimpleNamespace(ctx=ctx, svc=svc, target=target, other=other, server=server,
                           policy=policy, path=path, who=identity(), original_connect=original_connect)


def sweep(f, *, who=None, validity=None, background=False):
    who = who or f.who
    with principal_scope(who, validity=validity), operation_scope("discover"):
        return f.svc.sweep(mode="passive", actor=who.actor, background=background)


def grant(f):
    return vsphere.source_guard(f.ctx, f.target, f.svc.scopes(), f.who.actor,
                                lambda s: f.svc._guard_scope(s, f.who.actor))


def assert_no_candidates(f):
    assert not f.svc.list_assets()
    for run in f.svc.runs():
        assert f.svc.run_assets(run.id) == []


def test_verified_sweep_selects_only_requester_account_and_retains_offline_metadata(configured):
    f = configured
    before = [t.to_dict() for t in f.ctx.inventory.all()]
    run = sweep(f)
    assert run.status == "finished"
    rows = {a.facts["vsphere_ref"]: a for a in f.svc.run_assets(run.id) if vsphere.is_observation(a)}
    assert len(rows) == 4 and rows["vm-102"].facts["offline"] and rows["vm-102"].address is None
    assert rows["vm-101"].id != rows["vm-102"].id and rows["vm-103"].address is None
    assert all(a.facts["reported_by"] == "vc" for a in rows.values())
    assert {c.endpoint.url for c in f.server.connections} == {"https://vc.lab:443/sdk"}
    login = next(xml for method, xml, _, _ in f.server.calls if method == "Login")
    assert login.findtext(f"{{{wire.VIM}}}userName") == "alice@lab"
    assert login.findtext(f"{{{wire.VIM}}}password") == PASSWORD
    assert [t.to_dict() for t in f.ctx.inventory.all()] == before
    evidence = [r for r in f.ctx.audit.records() if r["action"] == "credential.use"]
    assert len(evidence) == 1 and evidence[0]["actor"] == f.who.actor
    assert evidence[0]["details"]["subject"] == "alice"
    assert evidence[0]["details"]["target"]["authorization_id"] == f.target.authorization_id
    assert evidence[0]["details"]["action"] == "discover"
    assert evidence[0]["details"]["credential_source"] == "environment"
    for value in (PASSWORD, "session-fixture-only", "shared-must-not-be-used"):
        probe = CanaryProbe(value)
        probe.tree(f.ctx.store.root)
        probe.assert_clean()
    assert f.ctx.audit.verify().ok


@pytest.mark.parametrize("change", ["none", "ssh", "ntlm", "key", "sudo", "no-user", "no-ref", "scan-only"])
def test_acl_or_wrong_transport_binding_cannot_use_inventory_credentials(configured, monkeypatch, change):
    f = configured
    row = account()
    c = row["grants"][0]["credential"]
    if change == "none":
        row["grants"][0].pop("credential")
    elif change == "ssh":
        c["options"] = {}
    elif change == "ntlm":
        c["options"] = {"transport": "ntlm"}
    elif change == "key":
        c["credential_ref"] = None
        c["options"] = {"key_file": "/fixture/unused-key"}
    elif change == "sudo":
        c["sudo"] = True
    elif change == "no-user":
        c["username"] = None
    elif change == "no-ref":
        c["credential_ref"] = None
    else:
        row["grants"].append({"target_ids": ["vc"], "actions": ["scan"], "credential": c})
        row["grants"][0].pop("credential")
    f.policy([row])
    monkeypatch.setattr(vsphere_access, "os", SimpleNamespace(environ={}))
    with principal_scope(f.who), operation_scope("discover"), pytest.raises(PermissionError):
        grant(f)
    assert not f.server.calls


@pytest.mark.parametrize("change", ["issuer", "subject", "group-as-subject", "target", "environment", "operation", "actor", "expired"])
def test_explicit_account_resource_and_operation_boundaries(configured, change):
    f = configured
    who, actor, operation = f.who, f.who.actor, "discover"
    if change == "issuer":
        who = replace(who, issuer="https://foreign.example.test")
    elif change == "subject":
        who = identity("bob")
    elif change == "group-as-subject":
        f.policy([account(group="operators")])
        who = identity("operators")
    elif change == "target":
        row = account(target="vc-b")
        f.policy([row])
    elif change == "environment":
        f.policy([account(environment="B")])
    elif change == "operation":
        operation = "scan"
    elif change == "actor":
        actor = identity("bob").actor
    else:
        who = replace(who, expires_at=time.time() - 1)
    if change != "actor":
        actor = who.actor
    with principal_scope(who), operation_scope(operation), pytest.raises(PermissionError):
        vsphere.source_guard(f.ctx, f.target, f.svc.scopes(), actor, lambda _: None)
    assert not f.server.calls


@pytest.mark.parametrize("roles,kind,allowed", [
    (("analyst",), "human", True), (("analyst",), "workload", True),
    (("admin",), "human", False), (("admin",), "workload", False),
    (("viewer",), "human", False), (("approver",), "human", False),
])
def test_roles_are_separate_from_account_grant_and_workload_cannot_approve(configured, roles, kind, allowed):
    f = configured
    who = replace(f.who, roles=roles, kind=kind)
    if allowed:
        assert sweep(f, who=who).status == "finished"
        with principal_scope(who), pytest.raises(PermissionError):
            f.ctx.authorize("approve", actor=who.actor, target=f.target)
    else:
        with pytest.raises(PermissionError):
            sweep(f, who=who)
        assert not f.server.calls


def test_trusted_group_selection_and_ambiguous_subject_group_conflict(configured):
    f = configured
    who = replace(f.who, groups=("operators",))
    f.policy([account(group="operators")])
    assert sweep(f, who=who).status == "finished"
    row = account(group="operators", ref="BOB_VC")
    row["grants"][0]["credential"]["username"] = "other@lab"
    f.policy([account(), row])
    before = len(f.server.calls)
    with principal_scope(who), operation_scope("discover"), pytest.raises(PermissionError):
        grant(f)
    assert len(f.server.calls) == before


@pytest.mark.parametrize("change", ["endpoint", "address", "port", "trust", "generation", "environment", "account", "principal", "mode"])
def test_captured_access_cannot_be_swapped_or_rebound(configured, change):
    f = configured
    with principal_scope(f.who), operation_scope("discover"):
        access = grant(f)
        if change == "principal":
            with principal_scope(identity("bob")), pytest.raises(PermissionError):
                access()
            return
        if change == "account":
            f.policy([account(ref="BOB_VC")])
        elif change == "mode":
            f.ctx.settings.auth_mode = "dev"
        elif change in {"endpoint", "trust"}:
            f.target.options["vsphere"]["endpoint" if change == "endpoint" else "tls_trust"] = (
                "https://other.lab/sdk" if change == "endpoint" else "insecure")
            f.ctx.inventory.save()
        else:
            key, value = {"address": ("address", "10.20.0.3"), "port": ("port", 8443),
                          "generation": ("authorization_id", "b" * 32), "environment": ("environment", "B")}[change]
            setattr(f.target, key, value)
            f.ctx.inventory.save()
        with pytest.raises((PermissionError, wire.VsphereError)):
            access()
    assert not f.server.calls


@pytest.mark.parametrize("change", ["grant", "account", "target", "reuse-id", "scope", "wider-scope", "kill", "session"])
def test_revoked_response_cannot_continue_or_publish(configured, change):
    f = configured
    lease = {"valid": True}

    def validity():
        if not lease["valid"]:
            raise PermissionError("fixture session revoked")

    def after(method):
        if method != "RetrievePropertiesEx":
            return
        if change == "grant":
            f.policy([])
        elif change == "account":
            f.policy([account(ref="BOB_VC")])
        elif change == "target":
            f.target.in_scope = False
            f.ctx.inventory.save()
        elif change == "reuse-id":
            f.ctx.inventory.remove("vc")
            f.ctx.inventory.save()
            f.ctx.inventory.add_new(replace(f.target, authorization_id="f" * 32))
        elif change in {"scope", "wider-scope"}:
            f.svc.set_scopes([] if change == "scope" else ["10.20.0.0/23"], "Fixture revoker", "New grant")
        elif change == "kill":
            f.ctx.killswitch.sentinel.touch()
        else:
            lease["valid"] = False

    f.server.after = after
    with pytest.raises((PermissionError, RuntimeError)):
        sweep(f, validity=validity)
    assert f.server.methods[-1] == "RetrievePropertiesEx"
    assert_no_candidates(f)
    assert all(c.closed for c in f.server.connections)


@pytest.mark.parametrize("boundary", ["before-source", "conversion", "reconcile"])
def test_same_account_binding_is_retained_until_publication(configured, monkeypatch, boundary):
    f = configured
    owner, attribute = ((f.svc, "_passive") if boundary == "before-source" else
                        (vsphere, "observations") if boundary == "conversion" else (f.svc, "reconcile"))
    original = getattr(owner, attribute)

    def swap(*args, **kwargs):
        result = original(*args, **kwargs)
        f.policy([account(ref="BOB_VC")])
        return result

    monkeypatch.setattr(owner, attribute, swap)
    with pytest.raises(PermissionError):
        sweep(f)
    if boundary == "before-source":
        assert not f.server.calls
    assert_no_candidates(f)


@pytest.mark.parametrize("revoke", [False, True])
def test_background_worker_copies_requester_and_session_guard(configured, revoke):
    f = configured
    entered, release = threading.Event(), threading.Event()
    lease = {"valid": True}

    def validity():
        if not lease["valid"]:
            raise PermissionError("fixture session revoked")

    def after(method):
        if method == "RetrievePropertiesEx":
            entered.set()
            if not release.wait(10):
                raise AssertionError("fixture coordination timed out")

    f.server.after = after
    run = sweep(f, validity=validity, background=True)
    try:
        assert entered.wait(10)
        lease["valid"] = not revoke
    finally:
        release.set()
        done = f.svc.join(run.id, timeout=10)
    assert done.status == ("failed" if revoke else "finished")
    if revoke:
        assert f.server.methods[-1] == "RetrievePropertiesEx"
        assert_no_candidates(f)
    else:
        records = [r for r in f.ctx.audit.records() if r["action"] == "credential.use"]
        assert records[0]["principal"]["sub"] == "alice"
        assert len([a for a in f.svc.run_assets(run.id) if vsphere.is_observation(a)]) == 4


@pytest.mark.parametrize("secret", [PASSWORD, "session-fixture-only"])
@pytest.mark.parametrize("failure", ["name", "base64", "percent", "http", "transport"])
def test_credential_echo_is_sanitized_before_state_logs_and_candidate_responses(configured, caplog, secret, failure):
    f = configured
    caplog.set_level(logging.DEBUG)
    if failure in {"name", "base64", "percent"}:
        echo = (base64.b64encode(json.dumps({"echo": secret}).encode()).decode() if failure == "base64"
                else quote(secret, safe="") if failure == "percent" else secret)
        f.server.pages[0] = f.server.pages[0].replace(b"build-box", escape(echo).encode())
    else:
        f.server.overrides["RetrievePropertiesEx"] = (Response(secret.encode(), status=500) if failure == "http"
                                                     else OSError(secret))
    with pytest.raises(wire.VsphereError) as caught:
        sweep(f)
    assert_no_candidates(f)
    probe = CanaryProbe(secret)
    probe.add("public error", str(caught.value))
    probe.add("logs", caplog.text)
    probe.add("candidate response", [a.to_dict() for a in f.svc.list_assets()])
    probe.add("run response", [r.to_dict() for r in f.svc.runs()])
    probe.tree(f.ctx.store.root)
    probe.assert_clean()


def test_binding_stamp_cannot_be_transferred_to_new_endpoint_or_reused_target_id(configured):
    f = configured
    binding = f.ctx.access.credential(f.who, "discover", f.target)
    assert bind_target(f.target, binding).options["vsphere"] == {"endpoint": "https://vc.lab/sdk", "tls_trust": "system"}
    for changed in (replace(f.target, authorization_id="a" * 32), f.other,
                    replace(f.target, options={"hypervisor": "vsphere", "vsphere": {
                        "endpoint": "https://different.lab/sdk", "tls_trust": "system"}})):
        with pytest.raises(CredentialError):
            bind_target(changed, binding)
    with pytest.raises(TypeError):
        binding.options["transport"] = "ssh"


def test_vsphere_marker_does_not_authorize_other_transports_or_operations(configured):
    f = configured
    for transport in ("ssh", "winrm", "kubeconfig", "simulated"):
        with pytest.raises(PermissionError):
            f.ctx.access.credential(f.who, "discover", replace(f.target, transport=transport))
    row = account()
    row["grants"][0]["actions"] = ["scan", "apply", "rollback", "verify", "plan"]
    f.policy([row])
    for action in row["grants"][0]["actions"]:
        with pytest.raises(PermissionError):
            f.ctx.access.credential(f.who, action, f.target)


def test_second_requester_uses_own_endpoint_and_credential(configured):
    f = configured
    assert sweep(f, who=identity("bob")).status == "finished"
    assert {c.endpoint.url for c in f.server.connections} == {"https://other.lab:443/sdk"}
    login = next(xml for method, xml, _, _ in f.server.calls if method == "Login")
    assert login.findtext(f"{{{wire.VIM}}}userName") == "bob@lab"
    assert login.findtext(f"{{{wire.VIM}}}password") == "different-fixture-password"
    assert all(r["details"]["target"]["id"] == "vc-b" for r in f.ctx.audit.records()
               if r["action"] == "credential.use")


def test_missing_selected_secret_cannot_fall_back_to_shared_or_bare_environment(configured, monkeypatch):
    f = configured
    monkeypatch.delenv("CT_CRED_ALICE_VC")
    monkeypatch.setenv("ALICE_VC", PASSWORD)
    with pytest.raises(wire.VsphereError, match="credential_unavailable"):
        sweep(f)
    assert f.server.methods == ["RetrieveServiceContent"]
    assert_no_candidates(f)


def test_supplied_source_access_cannot_authorize_another_resource(configured):
    f = configured
    with principal_scope(f.who), operation_scope("discover"):
        access = grant(f)
        with pytest.raises(PermissionError, match="source_request_changed"):
            vsphere.collect(f.ctx, f.other, f.svc.scopes(), f.who.actor, lambda _: None, access=access)
    assert not f.server.calls


@pytest.mark.parametrize("when", ["setup", "response"])
def test_custom_ca_is_loaded_from_captured_bytes_and_replacement_revokes_access(configured, monkeypatch, cert_material, when):
    f = configured
    ca = f.ctx.store.root / "fixture-public-ca.pem"
    ca.write_bytes(cert_material["ca"])
    f.target.options["vsphere"].update(tls_trust="ca_file", ca_file=str(ca))
    f.ctx.inventory.save()
    original = wire.Endpoint.tls_context
    loaded = []

    def context(endpoint, *, ca_data=None):
        loaded.append(ca_data)
        if when == "setup":
            ca.write_bytes(cert_material["client"])
        return original(endpoint, ca_data=ca_data)

    monkeypatch.setattr(wire.Endpoint, "tls_context", context)
    if when == "response":
        f.server.after = lambda method: ca.write_bytes(cert_material["client"]) if method == "RetrievePropertiesEx" else None
    with pytest.raises(PermissionError, match="tls_trust_changed"):
        sweep(f)
    assert loaded == [cert_material["ca"]]
    assert f.server.methods == ([] if when == "setup" else
                                ["RetrieveServiceContent", "Login", "CreateContainerView", "RetrievePropertiesEx"])
    assert_no_candidates(f)


def test_custom_ca_size_is_bounded_before_client_creation(configured):
    f = configured
    ca = f.ctx.store.root / "oversized-public-ca.pem"
    ca.write_bytes(b"x" * (vsphere_access.MAX_CA_BYTES + 1))
    f.target.options["vsphere"].update(tls_trust="ca_file", ca_file=str(ca))
    f.ctx.inventory.save()
    with pytest.raises(wire.VsphereError, match="invalid_tls_trust"):
        sweep(f)
    assert not f.server.calls


@pytest.mark.parametrize("field,value", [("username", "line\nbreak"), ("username", "\ud800"),
                                         ("credential_ref", "../unscoped"), ("credential_ref", "账户")])
def test_invalid_account_text_never_reaches_network_or_diagnostics(configured, field, value):
    f = configured
    row = account()
    row["grants"][0]["credential"][field] = value
    f.policy([row])
    with principal_scope(f.who), operation_scope("discover"), pytest.raises(PermissionError) as caught:
        grant(f)
    assert value not in str(caught.value) and not f.server.calls


def test_credential_echo_never_reaches_authenticated_discovery_and_audit_api(configured, monkeypatch):
    from fastapi.testclient import TestClient
    from cyberthunder.api.app import create_app

    f = configured
    f.server.pages[0] = f.server.pages[0].replace(b"build-box", escape(PASSWORD).encode())
    with pytest.raises(wire.VsphereError, match="sensitive_response"):
        sweep(f)

    class Validator:
        def validate(self, token):
            assert token == "fixture-access-token"
            return {"iss": f.who.issuer, "sub": f.who.subject, "name": f.who.display_name,
                    "ct_kind": f.who.kind, "ct_roles": list(f.who.roles), "exp": f.who.expires_at}

    monkeypatch.setattr("cyberthunder.api.auth.make_validator", lambda *_: Validator())
    probe = CanaryProbe(PASSWORD)
    blocked_connect = socket.socket.connect
    # Windows TestClient creates an internal event-loop socket pair. Permit that
    # bootstrap only, then deny all sockets before exercising application routes.
    with monkeypatch.context() as bootstrap:
        bootstrap.setattr(socket.socket, "connect", f.original_connect)
        with TestClient(create_app(f.ctx)) as client:
            bootstrap.setattr(socket.socket, "connect", blocked_connect)
            headers = {"Authorization": "Bearer fixture-access-token"}
            before = len(f.server.calls)
            denied = client.get("/api/v1/discovery", headers=headers)
            assert denied.status_code == 403
            probe.add("limited discovery API refusal", denied.content)
            denied_sweep = client.post("/api/v1/discovery/sweep", headers=headers, json={"mode": "passive"})
            assert denied_sweep.status_code == 403 and len(f.server.calls) == before
            probe.add("limited sweep API refusal", denied_sweep.content)
            # Global history needs separate read grants; the vSphere credential
            # grant must not imply them. Add them explicitly for serialization.
            reader = account()
            reader["node_actions"].append("read")
            reader["grants"].append({"target_ids": ["vc-b"], "environments": ["B"], "actions": ["read"]})
            f.policy([reader])
            for path in ("/discovery", "/discovery/assets", "/discovery/runs", "/audit"):
                response = client.get("/api/v1" + path, headers=headers)
                assert response.status_code == 200
                probe.add("API " + path, response.content)
                probe.add("API headers " + path, dict(response.headers))
    probe.assert_clean()


def test_session_revoked_during_reconciliation_prevents_publication(configured, monkeypatch):
    f = configured
    lease = {"valid": True}
    original = f.svc.reconcile

    def validity():
        if not lease["valid"]:
            raise PermissionError("fixture session revoked")

    def reconcile(*args, **kwargs):
        result = original(*args, **kwargs)
        lease["valid"] = False
        return result

    monkeypatch.setattr(f.svc, "reconcile", reconcile)
    with pytest.raises(PermissionError):
        sweep(f, validity=validity)
    assert_no_candidates(f)


def test_revocation_after_authorized_asset_write_prevents_next_publication(configured, monkeypatch):
    f = configured
    original = f.svc._save_assets

    def publish(assets):
        original(assets)  # Authorized at this commit boundary; retain historical evidence.
        f.policy([])

    monkeypatch.setattr(f.svc, "_save_assets", publish)
    with pytest.raises(PermissionError):
        sweep(f)
    assert len([a for a in f.svc.list_assets() if vsphere.is_observation(a)]) == 4
    failed = f.svc.runs()[0]
    assert failed.status == "failed" and not f.svc.run_assets(failed.id)
    assert failed.asset_ids == []


def test_unicode_account_name_is_sent_as_selected_without_affecting_identity(configured):
    f = configured
    row = account()
    row["grants"][0]["credential"]["username"] = "équipe_运维@lab"
    f.policy([row])
    assert sweep(f).status == "finished"
    login = next(xml for method, xml, _, _ in f.server.calls if method == "Login")
    assert login.findtext(f"{{{wire.VIM}}}userName") == "équipe_运维@lab"
    record = next(r for r in f.ctx.audit.records() if r["action"] == "credential.use")
    assert record["details"]["subject"] == "alice"
