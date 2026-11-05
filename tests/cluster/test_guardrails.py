"""Cluster access guardrails exercised only with temporary state and fake external calls."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from cyberthunder.cluster import service
from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.control.killswitch import KillSwitch, KillSwitchEngaged
from cyberthunder.inventory.targets import Inventory, ScopeViolation, Target
from cyberthunder.runtime import RuntimeTasks, bootstrap_cluster_target

ACTOR = "ITC Rivera"
APP_IMAGE = "registry.invalid/app:old"
HELPER_IMAGE = "registry.invalid/helper:old"


@pytest.fixture(autouse=True)
def external_calls(monkeypatch):
    process = Mock(side_effect=AssertionError("unexpected subprocess"))
    network = Mock(side_effect=AssertionError("unexpected network call"))
    monkeypatch.setattr(service.subprocess, "run", process)
    monkeypatch.setattr(service.urllib.request, "urlopen", network)
    return process, network


@pytest.fixture
def ctx(state_dir):
    ctx = AppContext(Settings(state_dir=state_dir, node="cluster-fixture", llm_backend="template", explain_precompute=False,
                              bootstrap_cluster_target=False, bootstrap_cluster_target_id="range-cluster",
                              bootstrap_cluster_kubeconfig=str(state_dir / "unapproved-config"),
                              scheduler_actor="system:scheduler", scan_interval_s=0,
                              content_check_interval_s=0, trivy_binary="trivy", trivy_skip_db_update=True))
    yield ctx
    assert ctx.audit.verify().ok


@pytest.fixture
def target(ctx):
    target = Target(id="range-cluster", name="Isolated test cluster", asset_type="kubernetes",
                    transport="kubeconfig", in_scope=True,
                    options={"kubeconfig": str(ctx.store.root / "approved-config"),
                             "context": "isolated-range", "kubectl": "range-kubectl"})
    ctx.inventory.add(target)
    ctx.inventory.save()
    return target


def completed(argv, doc):
    return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(doc), stderr="")


def fake_tools(argv, **kwargs):
    if argv[0] == "trivy":
        severe = argv[-1] == APP_IMAGE
        return completed(argv, {"Results": [{"Target": "fixture-image", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2026-12345" if severe else "CVE-2026-54321",
            "PkgName": "fixture-package", "InstalledVersion": "1", "FixedVersion": "2" if severe else "",
            "Severity": "CRITICAL" if severe else "LOW", "CVSS": {"fixture": {"V3Score": 9.8 if severe else 2}},
        }]}]})
    resource = argv[argv.index("get") + 1]
    if resource == "namespaces":
        return completed(argv, {"items": [{"metadata": {"name": ns}} for ns in ("mission", "ops", "empty")]})
    if resource == "deployments":
        return completed(argv, {"items": [{"metadata": {"namespace": "mission", "name": name},
                                          "spec": {"template": {"spec": {"containers": [{"image": APP_IMAGE}]}}}}
                                         for name in ("one", "two")]})
    if resource == "pods":
        return completed(argv, {"items": [{"metadata": {"namespace": "ops", "name": "helper"},
                                          "spec": {"containers": [{"image": HELPER_IMAGE}]}}]})
    return completed(argv, {"items": []})


@pytest.mark.parametrize("operation", ["survey", "scan"])
@pytest.mark.parametrize("actor", [None, "", "   ", "agent", "SYSTEM:timer", "policy:commander", "name\nother"])
def test_service_rejects_unnamed_and_machine_actors(ctx, target, external_calls, operation, actor):
    with pytest.raises(PermissionError):
        getattr(ctx.cluster, operation)(actor=actor)
    external_calls[0].assert_not_called()
    external_calls[1].assert_not_called()
    event = list(ctx.audit.records())[-1]
    assert event["outcome"] == "rejected"
    assert event["details"]["target_id"] == target.id
    assert ctx.cluster.latest() is None


@pytest.mark.parametrize("operation", ["survey", "scan"])
def test_actor_argument_is_required(ctx, external_calls, operation):
    with pytest.raises(TypeError, match="actor"):
        getattr(ctx.cluster, operation)()
    external_calls[0].assert_not_called()


@pytest.mark.parametrize("operation", ["survey", "scan"])
@pytest.mark.parametrize("invalid", ["absent", "out_of_scope", "kind", "transport", "simulated",
                                    "kubeconfig", "context", "kubectl"])
def test_invalid_inventory_never_executes(ctx, target, external_calls, operation, invalid):
    if invalid == "absent":
        ctx.inventory.remove(target.id)
    elif invalid == "out_of_scope":
        target.in_scope = False
    elif invalid == "kind":
        target.asset_type = "linux"
    elif invalid == "transport":
        target.transport = "simulated"
    elif invalid == "simulated":
        target.simulated = True
    else:
        target.options[invalid] = " "
    with pytest.raises(ScopeViolation):
        getattr(ctx.cluster, operation)(actor=ACTOR)
    external_calls[0].assert_not_called()
    external_calls[1].assert_not_called()
    assert list(ctx.audit.records())[-1]["actor"] == ACTOR
    assert list(ctx.audit.records())[-1]["outcome"] == "rejected"


@pytest.mark.parametrize("operation", ["survey", "scan"])
def test_kill_before_run_never_executes(ctx, target, external_calls, operation):
    ctx.killswitch.engage(ACTOR, "fixture stop")
    with pytest.raises(KillSwitchEngaged):
        getattr(ctx.cluster, operation)(actor=ACTOR)
    external_calls[0].assert_not_called()
    external_calls[1].assert_not_called()
    events = list(ctx.audit.records())
    assert events[-2]["action"] == "action.blocked"
    assert events[-2]["actor"] == events[-1]["actor"] == ACTOR
    assert events[-1]["outcome"] == "blocked"


def test_baseline_uses_inventory_binding_and_preserves_profiles(ctx, target, external_calls):
    process, network = external_calls
    process.side_effect = fake_tools
    result = ctx.cluster.scan(actor=f"  {ACTOR}  ")
    assert result["requested_by"] == ACTOR
    assert result["target"] == {"target_id": target.id, **target.options}
    profiles = {p["namespace"]: p for p in result["namespaces"]}
    assert profiles["mission"]["risk_rating"] == "critical"
    assert profiles["mission"]["summary"]["critical"] == 2
    assert profiles["mission"]["fixable_vulnerabilities"] == 2
    assert profiles["mission"]["images"] == 1
    assert profiles["mission"]["max_cvss"] == 9.8
    assert profiles["mission"]["top_vulnerabilities"][0]["id"] == "CVE-2026-12345"
    assert profiles["ops"]["risk_rating"] == "low"
    assert profiles["empty"]["risk_rating"] == "minimal"
    assert all(p["description_source"] == "template" and p["description"] for p in profiles.values())
    assert result["errors"] == []
    argv = [call.args[0] for call in process.call_args_list]
    assert len(argv) == 9
    expected_prefix = ["range-kubectl", "--kubeconfig", target.options["kubeconfig"], "--context", "isolated-range"]
    assert all(call[:5] == expected_prefix for call in argv[:7])
    assert [call[-1] for call in argv[7:]] == [APP_IMAGE, HELPER_IMAGE]
    assert all("--skip-db-update" in call for call in argv[7:])
    assert all(ctx.settings.bootstrap_cluster_kubeconfig not in call for call in argv)
    assert ctx.cluster.latest() == result
    assert ctx.store.read_json(ctx.cluster.root / "baselines" / result["id"] / "baseline.json") == result
    assert len(list((ctx.cluster.root / "baselines" / result["id"]).glob("trivy_*.json"))) == 2
    events = list(ctx.audit.records())
    assert [e["action"] for e in events] == ["cluster.baseline.start", "cluster.baseline"]
    for event in events:
        assert event["actor"] == ACTOR
        assert event["subject"] == result["id"]
        assert event["details"]["source"] == "inventory"
        assert all(event["details"][key] == value for key, value in result["target"].items())
    assert events[-1]["details"]["images"] == 2
    assert events[-1]["outcome"] == "ok"
    network.assert_not_called()


def test_explicit_target_selection_does_not_fall_back(ctx, target, external_calls):
    external_calls[0].side_effect = fake_tools
    ctx.settings.bootstrap_cluster_target_id = "missing-default"
    result = ctx.cluster.survey(actor=ACTOR, target_id=target.id)
    assert result["target"]["target_id"] == target.id
    assert result["requested_by"] == ACTOR
    assert len(result["workloads"]) == 3
    assert list(ctx.audit.records())[-1]["action"] == "cluster.survey"
    external_calls[0].reset_mock()
    with pytest.raises(ScopeViolation):
        ctx.cluster.survey(actor=ACTOR, target_id="")
    external_calls[0].assert_not_called()


def interrupt(ctx, target, change):
    if change == "kill":
        KillSwitch(ctx.store.root, ctx.audit).engage(ACTOR, "fixture interruption")
    else:
        # A separate inventory instance models revocation or edits made by another process.
        inventory = Inventory.load(ctx.store.targets)
        current = inventory.get(target.id)
        if change == "scope":
            current.in_scope = False
        elif change == "removed":
            inventory.remove(target.id)
        else:
            current.options[change] = "different-connection"
        inventory.save()


@pytest.mark.parametrize("change", ["kill", "scope", "removed", "kubeconfig", "context", "kubectl"])
@pytest.mark.parametrize("call_number", [1, 2, 7, 8, 9])
def test_run_stops_after_external_call_when_authorization_changes(ctx, target, external_calls, change, call_number):
    process, network = external_calls
    cached = {"id": "previous-good-baseline", "namespaces": []}
    ctx.store.write_json(ctx.cluster.root / "latest.json", cached)

    def run(argv, **kwargs):
        if process.call_count == call_number:
            interrupt(ctx, target, change)
        return fake_tools(argv, **kwargs)

    process.side_effect = run
    with pytest.raises(KillSwitchEngaged if change == "kill" else ScopeViolation):
        ctx.cluster.scan(actor=ACTOR)
    assert process.call_count == call_number
    network.assert_not_called()
    assert ctx.cluster.latest() == cached
    assert not list((ctx.cluster.root / "baselines").glob("*/baseline.json"))
    event = list(ctx.audit.records())[-1]
    assert (event["action"], event["actor"], event["outcome"]) == ("cluster.baseline", ACTOR, "blocked")
    assert event["details"]["context"] == "isolated-range"


@pytest.mark.parametrize("failure", ["missing", "malformed", "invalid_structure", "unreadable"])
@pytest.mark.parametrize("operation,call_number", [("scan", 0), ("survey", 2), ("scan", 2), ("scan", 8)])
def test_inventory_source_failure_stops_access_and_preserves_cache(
        ctx, target, external_calls, monkeypatch, failure, operation, call_number):
    process, network = external_calls
    cached = {"id": "prior-authorized-baseline", "namespaces": []}
    ctx.store.write_json(ctx.cluster.root / "latest.json", cached)
    writes = Mock(wraps=ctx.store.write_json)
    monkeypatch.setattr(ctx.store, "write_json", writes)
    read_text = Path.read_text

    def fail_source():
        if failure == "missing":
            ctx.store.targets.unlink()
        elif failure == "malformed":
            ctx.store.targets.write_text("targets: [\nprivate-inventory-fixture", encoding="utf-8")
        elif failure == "invalid_structure":
            ctx.store.targets.write_text("targets: [null]\n", encoding="utf-8")
        else:
            def unreadable(path, *args, **kwargs):
                if path == ctx.store.targets:
                    raise OSError("private-inventory-fixture")
                return read_text(path, *args, **kwargs)

            monkeypatch.setattr(Path, "read_text", unreadable)

    def run(argv, **kwargs):
        if process.call_count == call_number:
            fail_source()
        return fake_tools(argv, **kwargs)

    process.side_effect = run
    if call_number == 0:
        fail_source()
    with pytest.raises(ScopeViolation):
        getattr(ctx.cluster, operation)(actor=ACTOR)
    assert process.call_count == call_number
    writes.assert_not_called()
    network.assert_not_called()
    assert ctx.cluster.latest() == cached
    terminal = list(ctx.audit.records())[-1]
    assert terminal["actor"] == ACTOR
    assert terminal["action"] == ("cluster.survey" if operation == "survey" else "cluster.baseline")
    assert terminal["outcome"] == ("rejected" if call_number == 0 else "blocked")
    assert terminal["details"]["target_id"] == target.id
    assert "private-inventory-fixture" not in json.dumps(terminal)


@pytest.mark.parametrize("guard", ["inventory", "kill"])
@pytest.mark.parametrize("error_type", [OSError, FileNotFoundError, ValueError])
@pytest.mark.parametrize("call_number", [2, 8])
def test_transient_guard_error_is_fatal_even_if_next_check_would_recover(
        ctx, target, external_calls, monkeypatch, guard, error_type, call_number):
    process, network = external_calls
    cached = {"id": "prior-authorized-baseline", "namespaces": []}
    ctx.store.write_json(ctx.cluster.root / "latest.json", cached)
    writes = Mock(wraps=ctx.store.write_json)
    monkeypatch.setattr(ctx.store, "write_json", writes)
    owner, method = ((ctx.inventory, "assert_in_scope") if guard == "inventory" else (ctx.killswitch, "guard"))
    original = getattr(owner, method)
    failed = False

    def transient_failure(*args, **kwargs):
        nonlocal failed
        if process.call_count == call_number and not failed:
            failed = True
            raise error_type("private-guard-diagnostic")
        return original(*args, **kwargs)

    monkeypatch.setattr(owner, method, transient_failure)
    process.side_effect = fake_tools
    with pytest.raises(service.ClusterGuardError):
        ctx.cluster.scan(actor=ACTOR)
    assert failed
    assert process.call_count == call_number
    writes.assert_not_called()
    network.assert_not_called()
    assert ctx.cluster.latest() == cached
    terminal = list(ctx.audit.records())[-1]
    assert (terminal["action"], terminal["actor"], terminal["outcome"]) == ("cluster.baseline", ACTOR, "blocked")
    assert terminal["details"]["target_id"] == target.id
    assert terminal["details"]["context"] == "isolated-range"
    assert "private-guard-diagnostic" not in json.dumps(terminal)


@pytest.mark.parametrize("operation,call_number", [("survey", 2), ("scan", 8)])
@pytest.mark.parametrize("change", ["kill", "scope"])
def test_interruption_wins_over_tool_failure(ctx, target, external_calls, operation, call_number, change):
    process = external_calls[0]

    def run(argv, **kwargs):
        if process.call_count == call_number:
            interrupt(ctx, target, change)
            raise subprocess.TimeoutExpired(argv, 1)
        return fake_tools(argv, **kwargs)

    process.side_effect = run
    with pytest.raises(KillSwitchEngaged if change == "kill" else ScopeViolation):
        getattr(ctx.cluster, operation)(actor=ACTOR)
    assert process.call_count == call_number
    assert list(ctx.audit.records())[-1]["outcome"] == "blocked"


def test_guard_rechecks_before_image_process_and_publication(ctx, target, external_calls, monkeypatch):
    external_calls[0].side_effect = fake_tools
    original = ctx.cluster._scan_image

    def revoke_before_image(*args, **kwargs):
        interrupt(ctx, target, "scope")
        return original(*args, **kwargs)

    monkeypatch.setattr(ctx.cluster, "_scan_image", revoke_before_image)
    with pytest.raises(ScopeViolation):
        ctx.cluster.scan(actor=ACTOR)
    assert external_calls[0].call_count == 7
    assert ctx.cluster.latest() is None


def test_guard_blocks_publication_after_profile_generation(ctx, target, external_calls, monkeypatch):
    external_calls[0].side_effect = fake_tools
    original = ctx.cluster._profiles

    def stop_after_profiles(*args):
        profiles = original(*args)
        interrupt(ctx, target, "kill")
        return profiles

    monkeypatch.setattr(ctx.cluster, "_profiles", stop_after_profiles)
    with pytest.raises(KillSwitchEngaged):
        ctx.cluster.scan(actor=ACTOR)
    assert external_calls[0].call_count == 9
    assert ctx.cluster.latest() is None


@pytest.mark.parametrize("collection_error", [None, OSError, PermissionError])
def test_ordinary_tool_errors_still_produce_audited_partial_baseline(ctx, target, external_calls, collection_error):
    def run(argv, **kwargs):
        if "deployments" in argv:
            if collection_error is not None:
                raise collection_error("fixture RBAC denial")
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="fixture RBAC denial")
        if argv[0] == "trivy":
            raise FileNotFoundError("fixture binary missing")
        return fake_tools(argv, **kwargs)

    external_calls[0].side_effect = run
    result = ctx.cluster.scan(actor=ACTOR)
    assert len(result["errors"]) == 2
    assert "fixture RBAC denial" in result["errors"][0]
    assert "not found" in result["errors"][1]
    assert list(ctx.audit.records())[-1]["outcome"] == "partial"
    assert ctx.cluster.latest() == result


def test_fatal_initial_collection_error_is_audited(ctx, target, external_calls):
    external_calls[0].side_effect = FileNotFoundError("fixture tool missing")
    with pytest.raises(FileNotFoundError):
        ctx.cluster.scan(actor=ACTOR)
    assert list(ctx.audit.records())[-1]["outcome"] == "error"
    assert ctx.cluster.latest() is None


def test_bootstrap_is_opt_in(ctx, external_calls):
    bootstrap_cluster_target(ctx)
    assert ctx.inventory.all() == []
    assert list(ctx.audit.records()) == []
    external_calls[0].assert_not_called()


def test_bootstrap_registers_only_an_unauthorized_candidate(ctx, external_calls):
    ctx.settings.bootstrap_cluster_target = True
    bootstrap_cluster_target(ctx)
    proposed = Inventory.load(ctx.store.targets).get(ctx.settings.bootstrap_cluster_target_id)
    assert not proposed.in_scope
    assert proposed.sudo is False
    assert proposed.asset_type == "kubernetes" and proposed.transport == "kubeconfig"
    assert proposed.options == {"kubeconfig": ctx.settings.bootstrap_cluster_kubeconfig,
                                "context": "in-cluster", "kubectl": "kubectl"}
    event = list(ctx.audit.records())[-1]
    assert event["actor"] == "system:scheduler"
    assert event["action"] == "inventory.bootstrap"
    assert event["details"]["in_scope"] is False
    assert event["details"]["authorization_required"] is True
    with pytest.raises(ScopeViolation):
        ctx.cluster.scan(actor=ACTOR)
    external_calls[0].assert_not_called()


@pytest.mark.parametrize("in_scope", [True, False])
def test_bootstrap_preserves_existing_and_revoked_targets(ctx, target, in_scope, external_calls):
    ctx.settings.bootstrap_cluster_target = True
    target.in_scope = in_scope
    target.notes = "Operator-owned connection"
    ctx.inventory.save()
    before = target.to_dict()
    bootstrap_cluster_target(ctx)
    bootstrap_cluster_target(ctx)
    assert ctx.inventory.get(target.id).to_dict() == before
    assert Inventory.load(ctx.store.targets).get(target.id).to_dict() == before
    assert list(ctx.audit.records()) == []
    external_calls[0].assert_not_called()


def test_bootstrap_notices_revocation_from_another_process(ctx, target):
    ctx.settings.bootstrap_cluster_target = True
    interrupt(ctx, target, "scope")
    bootstrap_cluster_target(ctx)
    assert not ctx.inventory.get(target.id).in_scope
    assert not Inventory.load(ctx.store.targets).get(target.id).in_scope


def test_bootstrap_kill_keeps_api_startup_available_without_registration(ctx, external_calls):
    ctx.settings.bootstrap_cluster_target = True
    ctx.killswitch.engage(ACTOR, "startup stop")
    tasks = RuntimeTasks(ctx)
    tasks.start()
    tasks.stop()
    assert ctx.inventory.all() == []
    assert list(ctx.audit.records())[-1]["action"] == "action.blocked"
    assert list(ctx.audit.records())[-1]["actor"] == "system:scheduler"
    external_calls[0].assert_not_called()
    external_calls[1].assert_not_called()


def test_bootstrap_rechecks_kill_before_inventory_write(ctx, monkeypatch):
    ctx.settings.bootstrap_cluster_target = True
    original = ctx.killswitch.guard
    calls = []

    def guard(action, actor):
        calls.append(action)
        if len(calls) == 2:
            ctx.killswitch.engage(ACTOR, "stop before registration")
        original(action, actor)

    monkeypatch.setattr(ctx.killswitch, "guard", guard)
    bootstrap_cluster_target(ctx)
    assert ctx.inventory.all() == []
    assert list(ctx.audit.records())[-1]["action"] == "action.blocked"


@pytest.mark.parametrize("actor", ["", " ", "scheduler\nother"])
def test_bootstrap_requires_a_traceable_scheduler_actor(ctx, actor):
    ctx.settings.bootstrap_cluster_target = True
    ctx.settings.scheduler_actor = actor
    with pytest.raises(PermissionError):
        bootstrap_cluster_target(ctx)
    assert ctx.inventory.all() == []
    assert list(ctx.audit.records())[-1]["outcome"] == "rejected"
