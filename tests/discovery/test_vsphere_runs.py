"""Limited-account HTTP and persistence boundaries using real services and fixture SOAP I/O."""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from dataclasses import replace
import logging
import socket
import threading
from urllib.parse import quote
from uuid import uuid4
from xml.sax.saxutils import escape

import pytest
from fastapi.testclient import TestClient

from cyberthunder.api.app import create_app
from cyberthunder.control.principal import principal_scope
from cyberthunder.control.roles import route_action
from cyberthunder.discovery.sources import vsphere
from cyberthunder.discovery.vsphere_runs import VsphereRuns
from cyberthunder.security.resources import target_scope
from cyberthunder.store import StateStore
from tests.security.canary_helpers import CanaryProbe

from .test_vsphere_account_access import account, configured, identity
from .vsphere_support import FIX, PASSWORD, Response

BASE = "/api/v1/discovery/vsphere/"


def limited(subject="alice", **kwargs):
    row = account(subject, **kwargs)
    row["node_actions"] = []
    return row


@pytest.fixture
def source(configured, monkeypatch):
    f = configured
    f.policy([limited(), limited("bob", target="vc-b", environment="B", ref="BOB_VC")])
    f.runs = VsphereRuns(f.ctx)
    for name in ("_passive", "_nmap", "reconcile", "_inventory_sources", "sweep"):
        monkeypatch.setattr(f.svc, name, lambda *_a, **_k: pytest.fail("source collection cannot use global discovery"))
    return f


@pytest.fixture
def client(source, monkeypatch):
    f = source

    class Validator:
        def validate(self, token):
            assert token == "fixture-access-token"
            p = f.who
            return {"iss": p.issuer, "sub": p.subject, "name": p.display_name, "ct_kind": p.kind,
                    "ct_roles": list(p.roles), "exp": p.expires_at, "sid": p.session_id}

    monkeypatch.setattr("cyberthunder.api.auth.make_validator", lambda *_: Validator())
    blocked = socket.socket.connect
    # Permit only Windows' TestClient event-loop socket-pair bootstrap.
    with monkeypatch.context() as bootstrap:
        bootstrap.setattr(socket.socket, "connect", f.original_connect)
        with TestClient(create_app(f.ctx), headers={"Authorization": "Bearer fixture-access-token"}) as api:
            bootstrap.setattr(socket.socket, "connect", blocked)
            yield api


def collect(client, target="vc"):
    return client.post(BASE + target + "/collect")


def documents(f):
    return [f.ctx.store.read_json(p) for p in f.ctx.store.list_json(f.runs.directory, "*/*.json")]


def test_exact_role_map():
    for method, path, action in (
        ("POST", "/discovery/vsphere/{target_id}/collect", "discover"),
        ("GET", "/discovery/vsphere/{target_id}/runs", "read"),
        ("HEAD", "/discovery/vsphere/{target_id}/runs/{run_id}", "read"),
    ):
        assert route_action(method, "/api/v1" + path) == action
        assert route_action(method, path + "/unexpected") is None
    assert route_action("DELETE", "/discovery/vsphere/{target_id}/runs/{run_id}") is None


def test_limited_http_collect_persists_only_owned_source_without_global_reconciliation(source, client, monkeypatch):
    f = source
    inventory = [t.to_dict() for t in f.ctx.inventory.all()]
    f.ctx.store.write_json(f.svc.assets_file, {"beta-history": {"unrelated": "must remain unchanged"}})
    before = f.ctx.store.read_json(f.svc.assets_file)
    with monkeypatch.context() as local:
        local.setattr(f.ctx.inventory, "all", lambda: pytest.fail("cannot infer anything about unrelated inventory"))
        response = collect(client)
    assert response.status_code == 200, response.text
    run = response.json()
    assert run["status"] == "finished" and run["complete"] and run["collection_started"]
    assert run["observation_count"] == 4 and run["authorization_scope"] == target_scope(f.target)
    rows = {a["facts"]["vsphere_ref"]: a for a in run["observations"]}
    assert rows["vm-102"]["facts"]["offline"] and rows["vm-102"]["address"] is None
    assert rows["vm-101"]["id"] != rows["vm-102"]["id"] and rows["vm-103"]["address"] is None
    assert all(a["inventory_target_id"] is None and not a["changes"] for a in rows.values())
    assert all(a["facts"]["reported_by"] == "vc" for a in rows.values())
    assert {c.endpoint.address for c in f.server.connections} == {"10.20.0.2"}
    assert f.ctx.store.read_json(f.svc.assets_file) == before
    assert [t.to_dict() for t in f.ctx.inventory.all()] == inventory
    assert f.svc.runs() == []
    history = client.get(BASE + "vc/runs").json()
    assert [r["id"] for r in history] == [run["id"]] and "observations" not in history[0]
    assert "scope_grants" not in history[0] and "source_configuration_sha256" not in history[0]
    assert client.get(BASE + "vc/runs/" + run["id"]).json() == run
    # Reopen through the backend contract, not a cached service or a JSON fallback.
    reopened = StateStore(f.ctx.store.root, backend=f.ctx.store.backend_name)
    try:
        paths = reopened.list_json(f.runs.directory, "*/*.json")
        assert len(paths) == 1
        stored = reopened.read_json(paths[0])
        assert stored["observations"] == run["observations"]
        assert stored["authorization_scope"] == target_scope(f.target)
        if reopened.backend_name == "sqlite":
            assert reopened.docs.get(reopened.logical_path(paths[0])) == stored
            assert not paths[0].exists()
    finally:
        reopened.close()
    audit = [r for r in f.ctx.audit.records() if r["action"] == "discovery.vsphere.run"]
    assert audit[-1]["details"]["auto_accepted"] == 0 and f.ctx.audit.verify().ok


def test_beta_and_global_views_remain_denied_even_with_node_grants(source, client):
    f = source
    row = limited()
    row["node_actions"] = ["read", "read.all", "discover"]
    f.policy([row])
    for path in ("/discovery", "/discovery/assets", "/discovery/runs", "/discovery/vsphere/vc-b/runs"):
        assert client.get("/api/v1" + path).status_code == 403
    assert client.post("/api/v1/discovery/sweep", json={"mode": "passive"}).status_code == 403
    assert collect(client, "vc-b").status_code == 403
    assert not f.server.connections and documents(f) == []
    assert collect(client).status_code == 200


@pytest.mark.parametrize("binding", ["absent", "wrong-transport", "scan-only"])
def test_missing_discover_binding_refused_before_client_construction(source, client, monkeypatch, binding):
    f = source
    row = limited()
    credential = row["grants"][0].pop("credential")
    if binding == "wrong-transport":
        credential["options"] = {"transport": "ntlm"}
        row["grants"][0]["credential"] = credential
    elif binding == "scan-only":
        row["grants"].append({"target_ids": ["vc"], "environments": ["A"], "actions": ["scan"], "credential": credential})
    f.policy([row])
    monkeypatch.setattr(vsphere, "InventoryClient", lambda *_a, **_k: pytest.fail("must deny before client construction"))
    response = collect(client)
    assert response.status_code == 403 and not f.server.connections and documents(f) == []


@pytest.mark.parametrize("failure", ["no-credential", "transport", "later-page", "empty-inventory", "unexpected"])
def test_no_connect_failure_and_incomplete_inventory_are_truthful(source, client, monkeypatch, failure):
    f = source
    if failure == "no-credential":
        monkeypatch.delenv("CT_CRED_ALICE_VC")
        monkeypatch.setattr(vsphere, "InventoryClient", lambda *_a, **_k: pytest.fail("missing credential must not construct client"))
    elif failure == "empty-inventory":
        from .vsphere_support import envelope
        f.server.overrides["RetrievePropertiesEx"] = Response(envelope("RetrievePropertiesEx", ""))
    else:
        method = "ContinueRetrievePropertiesEx" if failure == "later-page" else "RetrieveServiceContent"
        f.server.overrides[method] = RuntimeError(PASSWORD) if failure == "unexpected" else OSError(PASSWORD)
    response = collect(client)
    assert response.status_code == 200, response.text
    run = response.json()
    if failure == "empty-inventory":
        assert run["status"] == "finished" and run["complete"] and run["error"] is None
    else:
        assert run["status"] == "failed" and run["complete"] is False
        assert run["error"] == ("vsphere:credential_unavailable" if failure == "no-credential" else
                                "vsphere:collection_failed" if failure == "unexpected" else "vsphere:transport_failure")
    assert run["collection_started"] == (failure != "no-credential")
    assert run["observations"] == [] and run["observation_count"] == 0
    assert client.get(BASE + "vc/runs/" + run["id"]).json() == run
    assert bool(f.server.connections) == (failure != "no-credential")
    if failure == "later-page":
        assert "RetrievePropertiesEx" in f.server.methods and "ContinueRetrievePropertiesEx" in f.server.methods
    probe = CanaryProbe(PASSWORD)
    probe.add("failure response", response.content)
    probe.tree(f.ctx.store.root)
    probe.assert_clean()


@pytest.mark.parametrize("encoding", ["plain", "base64", "percent"])
def test_credential_echo_does_not_escape_to_run_history_logs_or_audit(source, client, caplog, encoding):
    f = source
    caplog.set_level(logging.DEBUG)
    echo = {"plain": PASSWORD, "base64": base64.b64encode(PASSWORD.encode()).decode(), "percent": quote(PASSWORD, safe="")}[encoding]
    f.server.pages[0] = f.server.pages[0].replace(b"build-box", escape(echo).encode())
    f.who = replace(f.who, session_id="fixture-session-id-must-not-be-exported")
    response = collect(client)
    assert response.status_code == 200 and response.json()["error"] == "vsphere:sensitive_response"
    run = response.json()
    assert not run["complete"] and not run["observations"]
    for secret in (PASSWORD, "session-fixture-only", f.who.session_id):
        probe = CanaryProbe(secret)
        probe.add("collect response", response.content)
        probe.add("history", client.get(BASE + "vc/runs").content)
        probe.add("detail", client.get(BASE + "vc/runs/" + run["id"]).content)
        probe.add("logs", caplog.text)
        probe.tree(f.ctx.store.root)
        probe.assert_clean()


@pytest.mark.parametrize("change", ["account", "binding", "scope", "generation", "endpoint", "environment", "out-of-scope", "kill"])
def test_revocation_during_response_stops_network_and_publication(source, client, change):
    f = source

    def revoke(method):
        if method != "RetrievePropertiesEx":
            return
        if change == "account":
            f.policy([])
        elif change == "binding":
            f.policy([limited(ref="BOB_VC")])
        elif change == "scope":
            f.svc.set_scopes(["10.20.0.0/24"], "Fixture setup", "Replace grant at same CIDR")
        elif change == "kill":
            f.ctx.killswitch.sentinel.touch()
        else:
            if change == "generation":
                f.target.authorization_id = uuid4().hex
            elif change == "endpoint":
                f.target.options["vsphere"]["endpoint"] = "https://other.lab/sdk"
            elif change == "environment":
                f.target.environment = "B"
            else:
                f.target.in_scope = False
            f.ctx.inventory.save()

    f.server.after = revoke
    response = collect(client)
    assert response.status_code == (423 if change == "kill" else 403), response.text
    assert f.server.methods == ["RetrieveServiceContent", "Login", "CreateContainerView", "RetrievePropertiesEx"]
    stored = documents(f)
    assert len(stored) == 1 and stored[0]["status"] == "stopped"
    assert stored[0]["complete"] is False and stored[0]["observations"] == []
    closed = [r for r in f.ctx.audit.records() if r["action"] == "discovery.vsphere.run"]
    assert closed[-1]["details"]["status"] == "stopped" and f.ctx.audit.verify().ok


def test_old_target_generation_never_relabels_history_for_reused_id(source, client):
    f = source
    first = collect(client).json()
    original_owner = first["authorization_scope"]
    f.target.authorization_id = uuid4().hex
    f.ctx.inventory.save()
    assert client.get(BASE + "vc/runs").json() == []
    assert client.get(BASE + "vc/runs/" + first["id"]).status_code == 404
    assert documents(f)[0]["authorization_scope"] == original_owner
    # Even a misplaced old record cannot inherit the destination directory's owner.
    f.ctx.store.write_json(f.runs._directory(target_scope(f.target), documents(f)[0]["collector_scope"]) / (first["id"] + ".json"), documents(f)[0])
    assert client.get(BASE + "vc/runs").json() == []
    assert client.get(BASE + "vc/runs/" + first["id"]).status_code == 404


@pytest.mark.parametrize("change", ["read-grant", "scope", "endpoint", "out-of-scope"])
def test_history_rechecks_current_resource_and_original_scope(source, client, change):
    f = source
    run = collect(client).json()
    if change == "read-grant":
        row = limited()
        row["grants"][0]["actions"] = ["discover"]
        f.policy([row])
    elif change == "scope":
        f.svc.set_scopes(["10.20.0.0/23"], "Fixture setup", "Broader replacement is a new grant")
    else:
        if change == "endpoint":
            f.target.options["vsphere"]["endpoint"] = "https://replacement.lab/sdk"
        else:
            f.target.in_scope = False
        f.ctx.inventory.save()
    listing = client.get(BASE + "vc/runs")
    assert listing.status_code == (403 if change in {"read-grant", "out-of-scope"} else 200)
    if listing.status_code == 200:
        assert listing.json() == []
    assert client.get(BASE + "vc/runs/" + run["id"]).status_code == 403


@pytest.mark.parametrize("phase", ["response", "publication", "history"])
def test_session_lease_survives_copied_worker_and_is_rechecked(source, monkeypatch, phase):
    f = source
    lease = {"valid": True}

    def validity():
        if not lease["valid"]:
            raise PermissionError("fixture session revoked")

    if phase == "response":
        f.server.after = lambda m: lease.update(valid=False) if m == "RetrievePropertiesEx" else None
    elif phase == "publication":
        original = f.ctx.store.write_json

        def write(path, value):
            original(path, value)
            if isinstance(value, dict) and value.get("status") == "finished" and value.get("source") == "vsphere":
                lease["valid"] = False
        monkeypatch.setattr(f.ctx.store, "write_json", write)
    with principal_scope(f.who, validity=validity), ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(copy_context().run, f.runs.collect, "vc", f.who.actor)
        if phase != "history":
            with pytest.raises(PermissionError):
                future.result(timeout=20)
            assert documents(f)[0]["observations"] == []
        else:
            run = future.result(timeout=20)
            original = f.ctx.store.read_json

            def read(path, *args, **kwargs):
                value = original(path, *args, **kwargs)
                if str(path).endswith(run["id"] + ".json"):
                    lease["valid"] = False
                return value
            monkeypatch.setattr(f.ctx.store, "read_json", read)
            with pytest.raises(PermissionError):
                f.runs.get("vc", run["id"])
            with pytest.raises(PermissionError):
                f.runs.runs("vc")


def test_concurrent_collections_preserve_both_runs_and_bound_history(source, monkeypatch):
    f = source
    response = f.server.response

    def repeatable(method):
        if method in {"RetrievePropertiesEx", "ContinueRetrievePropertiesEx"}:
            return Response((FIX / ("page1.xml" if method == "RetrievePropertiesEx" else "page2.xml")).read_bytes())
        return response(method)

    monkeypatch.setattr(f.server, "response", repeatable)
    barrier = threading.Barrier(2)
    f.server.after = lambda m: barrier.wait(timeout=15) if m == "RetrieveServiceContent" else None
    with principal_scope(f.who), ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(copy_context().run, f.runs.collect, "vc", f.who.actor) for _ in range(2)]
        results = [f.result(timeout=30) for f in futures]
        assert len({r["id"] for r in results}) == 2 and all(r["complete"] for r in results)
        assert {r["id"] for r in f.runs.runs("vc")} == {r["id"] for r in results}
        assert len(f.runs.runs("vc", limit=1)) == 1
        with pytest.raises(ValueError):
            f.runs.runs("vc", limit=0)
    assert len(documents(f)) == 2 and f.ctx.audit.verify().ok


def test_source_run_cannot_be_read_through_another_authorized_target(source, client):
    f = source
    alpha = collect(client).json()
    f.who = identity("bob")
    assert client.get(BASE + "vc/runs").status_code == 403
    assert client.get(BASE + "vc-b/runs/" + alpha["id"]).status_code == 404
    assert client.get(BASE + "vc-b/runs").json() == []


@pytest.mark.parametrize("kind,roles,allowed", [("human", ("viewer",), False), ("workload", ("viewer",), False),
                                                ("workload", ("analyst",), True)])
def test_source_collection_uses_discover_role_including_workload_constraints(source, client, kind, roles, allowed):
    f = source
    f.who = replace(f.who, kind=kind, roles=roles)
    response = collect(client)
    assert response.status_code == (200 if allowed else 403)
    assert bool(f.server.connections) == allowed


def test_read_history_does_not_require_a_new_discover_credential(source, client):
    f = source
    run = collect(client).json()
    row = limited()
    row["grants"][0].pop("credential")
    row["grants"][0]["actions"] = ["read"]
    f.policy([row])
    f.who = replace(f.who, roles=("viewer",))
    assert client.get(BASE + "vc/runs/" + run["id"]).json() == run
    assert collect(client).status_code == 403


def test_publication_sink_errors_do_not_expose_exception_text(source, client, monkeypatch):
    f = source
    append = f.ctx.audit.append

    def failing(action, *args, **kwargs):
        if action == "discovery.vsphere.run":
            raise RuntimeError(PASSWORD)
        return append(action, *args, **kwargs)

    monkeypatch.setattr(f.ctx.audit, "append", failing)
    response = collect(client)
    assert response.status_code == 503 and response.json() == {"detail": "vsphere:publication_failed"}
    assert documents(f)[0]["status"] == "stopped" and documents(f)[0]["observations"] == []
    probe = CanaryProbe(PASSWORD)
    probe.add("publication error", response.content)
    probe.tree(f.ctx.store.root)
    probe.assert_clean()


def test_invalid_saved_scope_does_not_echo_global_configuration(source, client):
    f = source
    private_text = "invalid-global-range-text-not-for-source-api"
    f.ctx.store.write_json(f.svc.scopes_file, [{"cidr": private_text}])
    response = collect(client)
    assert response.status_code == 403
    assert response.json() == {"detail": "vsphere:saved_scope_unavailable"}
    assert private_text not in response.text and not f.server.connections and documents(f) == []
