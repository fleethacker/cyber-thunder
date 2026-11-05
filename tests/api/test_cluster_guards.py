"""Active cluster endpoints use actor, scope and kill guards; cached risk stays readable."""
from __future__ import annotations

import json
import subprocess
from unittest.mock import Mock

import pytest

from cyberthunder.cluster import service
from cyberthunder.inventory.targets import Target
from tests.api.conftest import ACTOR

API = "/api/v1/cluster"


@pytest.fixture(autouse=True)
def cluster_isolation(ctx, monkeypatch):
    ctx.settings.bootstrap_cluster_target = False
    ctx.settings.bootstrap_cluster_target_id = "range-cluster"
    ctx.settings.scan_interval_s = 0
    ctx.settings.content_check_interval_s = 0
    process = Mock(side_effect=AssertionError("unexpected subprocess"))
    network = Mock(side_effect=AssertionError("unexpected network call"))
    monkeypatch.setattr(service.subprocess, "run", process)
    monkeypatch.setattr(service.urllib.request, "urlopen", network)
    return process, network


@pytest.fixture
def cluster_target(ctx):
    target = Target(id="range-cluster", name="Test range", asset_type="kubernetes", transport="kubeconfig",
                    in_scope=True, options={"kubeconfig": str(ctx.store.root / "fixture-config"),
                                            "context": "test-range", "kubectl": "kubectl"})
    ctx.inventory.add(target)
    ctx.inventory.save()
    return target


def active_request(client, operation, *, headers=None, target_id=None):
    if operation == "baseline":
        return client.post(f"{API}/baseline", headers=headers, json={"target_id": target_id})
    return client.get(f"{API}/survey", headers=headers, params={} if target_id is None else {"target_id": target_id})


@pytest.mark.parametrize("operation", ["baseline", "survey"])
@pytest.mark.parametrize("actor", [None, " ", "agent", "system:timer", "policy:commander"])
def test_active_routes_require_human_actor(client, ctx, cluster_isolation, operation, actor):
    before = len(ctx.audit)
    response = active_request(client, operation, headers={} if actor is None else {"X-Actor": actor})
    assert response.status_code == 400, response.text
    assert len(ctx.audit) == before
    cluster_isolation[0].assert_not_called()
    cluster_isolation[1].assert_not_called()


@pytest.mark.parametrize("operation", ["baseline", "survey"])
@pytest.mark.parametrize("failure", ["absent", "out_of_scope", "kind", "context", "kill"])
def test_active_route_guard_status(client, ctx, cluster_target, cluster_isolation, operation, failure):
    if failure == "absent":
        ctx.inventory.remove(cluster_target.id)
    elif failure == "out_of_scope":
        cluster_target.in_scope = False
    elif failure == "kind":
        cluster_target.asset_type = "linux"
    elif failure == "context":
        cluster_target.options.pop("context")
    else:
        ctx.killswitch.engage(ACTOR["X-Actor"], "fixture stop")
    response = active_request(client, operation, headers=ACTOR)
    assert response.status_code == (423 if failure == "kill" else 403), response.text
    cluster_isolation[0].assert_not_called()
    cluster_isolation[1].assert_not_called()
    assert list(ctx.audit.records())[-1]["actor"] == ACTOR["X-Actor"]


@pytest.mark.parametrize("operation", ["baseline", "survey"])
def test_active_routes_forward_actor_and_selected_target(client, ctx, cluster_target, cluster_isolation, operation):
    ctx.settings.bootstrap_cluster_target_id = "unregistered-default"
    process = cluster_isolation[0]
    process.side_effect = lambda argv, **kwargs: subprocess.CompletedProcess(
        argv, 0, stdout=json.dumps({"items": []}), stderr="")
    response = active_request(client, operation, headers=ACTOR, target_id=cluster_target.id)
    assert response.status_code == 200, response.text
    assert response.json()["requested_by"] == ACTOR["X-Actor"]
    assert response.json()["target"]["target_id"] == cluster_target.id
    assert process.call_count == 7
    for call in process.call_args_list:
        assert call.args[0][:5] == ["kubectl", "--kubeconfig", cluster_target.options["kubeconfig"],
                                   "--context", "test-range"]
    event = list(ctx.audit.records())[-1]
    assert event["actor"] == ACTOR["X-Actor"]
    assert event["details"]["target_id"] == cluster_target.id
    assert event["outcome"] == "ok"


@pytest.mark.parametrize("operation", ["baseline", "survey"])
@pytest.mark.parametrize("failure", ["scope", "kill"])
def test_interrupted_routes_return_guard_error_instead_of_partial_success(
        client, ctx, cluster_target, cluster_isolation, operation, failure):
    process = cluster_isolation[0]

    def run(argv, **kwargs):
        if process.call_count == 2:
            if failure == "scope":
                cluster_target.in_scope = False
            else:
                ctx.killswitch.engage(ACTOR["X-Actor"], "fixture stop")
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps({"items": []}), stderr="")

    process.side_effect = run
    response = active_request(client, operation, headers=ACTOR)
    assert response.status_code == (423 if failure == "kill" else 403), response.text
    assert process.call_count == 2
    assert ctx.cluster.latest() is None
    assert list(ctx.audit.records())[-1]["outcome"] == "blocked"


def test_cached_risk_read_needs_no_actor_or_current_authorization(client, ctx, cluster_isolation):
    cached = {"id": "prior-run", "generated_at": "2026-11-05T00:00:00Z", "requested_by": ACTOR["X-Actor"],
              "target": {"target_id": "removed-cluster", "context": "test-range"},
              "namespaces": [{"namespace": "test", "risk_rating": "minimal"}], "errors": []}
    ctx.store.write_json(ctx.cluster.root / "latest.json", cached)
    ctx.killswitch.engage(ACTOR["X-Actor"], "fixture stop")
    before = len(ctx.audit)
    response = client.get(f"{API}/risk")
    assert response.status_code == 200
    assert response.json() == cached
    assert len(ctx.audit) == before
    cluster_isolation[0].assert_not_called()
    cluster_isolation[1].assert_not_called()


@pytest.mark.parametrize("operation", ["baseline", "survey"])
@pytest.mark.parametrize("failure", ["missing_inventory", "malformed_inventory", "guard_error"])
def test_guard_source_failures_return_safe_denial_and_keep_prior_risk(
        client, ctx, cluster_target, cluster_isolation, monkeypatch, operation, failure):
    process = cluster_isolation[0]
    cached = {"id": "prior-run", "namespaces": []}
    ctx.store.write_json(ctx.cluster.root / "latest.json", cached)
    original = ctx.inventory.assert_in_scope
    failed = False

    def assert_scope(*args, **kwargs):
        nonlocal failed
        if failure == "guard_error" and process.call_count == 2 and not failed:
            failed = True
            raise OSError("private-authorization-diagnostic")
        return original(*args, **kwargs)

    def run(argv, **kwargs):
        if process.call_count == 2:
            if failure == "missing_inventory":
                ctx.store.targets.unlink()
            elif failure == "malformed_inventory":
                ctx.store.targets.write_text("targets: [\nprivate-authorization-diagnostic", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps({"items": []}), stderr="")

    monkeypatch.setattr(ctx.inventory, "assert_in_scope", assert_scope)
    process.side_effect = run
    response = active_request(client, operation, headers=ACTOR)
    assert response.status_code == 403, response.text
    assert "private-authorization-diagnostic" not in response.text
    assert process.call_count == 2
    assert ctx.cluster.latest() == cached
    terminal = list(ctx.audit.records())[-1]
    assert (terminal["actor"], terminal["outcome"]) == (ACTOR["X-Actor"], "blocked")
    assert "private-authorization-diagnostic" not in json.dumps(terminal)
    cluster_isolation[1].assert_not_called()


def test_bootstrap_candidate_can_only_be_scanned_after_existing_scope_workflow(
        client, ctx, cluster_isolation):
    from cyberthunder.runtime import bootstrap_cluster_target

    ctx.settings.bootstrap_cluster_target = True
    bootstrap_cluster_target(ctx)
    target_id = ctx.settings.bootstrap_cluster_target_id
    assert active_request(client, "baseline", headers=ACTOR).status_code == 403
    cluster_isolation[0].assert_not_called()
    response = client.put(f"/api/v1/targets/{target_id}", headers=ACTOR, json={"in_scope": True})
    assert response.status_code == 200, response.text
    scope_event = list(ctx.audit.records())[-1]
    assert scope_event["action"] == "scope.change" and scope_event["actor"] == ACTOR["X-Actor"]
    cluster_isolation[0].side_effect = lambda argv, **kwargs: subprocess.CompletedProcess(
        argv, 0, stdout=json.dumps({"items": []}), stderr="")
    assert active_request(client, "baseline", headers=ACTOR).status_code == 200
    response = client.put(f"/api/v1/targets/{target_id}", headers=ACTOR, json={"in_scope": False})
    assert response.status_code == 200
    bootstrap_cluster_target(ctx)
    cluster_isolation[0].reset_mock()
    assert active_request(client, "baseline", headers=ACTOR).status_code == 403
    cluster_isolation[0].assert_not_called()
