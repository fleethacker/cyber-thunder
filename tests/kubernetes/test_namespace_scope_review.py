"""Independent negative calibration for bounded namespace collection; no cluster access."""
import json
from concurrent.futures import CancelledError
from dataclasses import replace
from types import SimpleNamespace

import pytest

from cyberthunder.adapters.kubernetes import KubernetesAdapter, scope
from cyberthunder.adapters.kubernetes.kubectl import KIND_INFO
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.control.principal import operation_scope, principal_scope
from cyberthunder.findings.schema import Finding
from cyberthunder.inventory.targets import ScopeViolation, Target
from cyberthunder.remediation.models import BeforeState
from cyberthunder.transport.base import CommandResult
from tests.security.test_kube_credentials import cert_material, write, TOKEN  # noqa: F401
from tests.security.test_kubernetes_account_integration import selected_cluster, assert_selected  # noqa: F401


def target():
    return Target("cluster-a", "Fixture cluster", "kubernetes", "kubeconfig", sudo=False,
                  options={"namespaces": ["work"], "kubeconfig": "fixture-config", "context": "fixture-context"})


def response(resource, items=()):
    _, kind, api = KIND_INFO[resource]
    return {"kind": kind + "List", "apiVersion": api, "metadata": {}, "items": list(items)}


class Lists:
    def __init__(self, overrides=None):
        self.calls = []
        self.overrides = overrides or {}

    def run(self, command, **kwargs):
        self.calls.append(command)
        words = command.split()
        scope.guard_command(words, None, ("work",))
        value = self.overrides.get(words[2], response(words[2]))
        if isinstance(value, BaseException):
            raise value
        return value if isinstance(value, CommandResult) else CommandResult(command, 0, json.dumps(value))


@pytest.mark.parametrize("owner", ["ReplicaSet", "Job"])
def test_observed_owned_pod_is_checked_without_readable_owner(tmp_path, owner):
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": "observed", "namespace": "work", "ownerReferences": [
               {"apiVersion": "apps/v1" if owner == "ReplicaSet" else "batch/v1", "kind": owner,
                "name": "owner", "uid": "fixture-owner"}]},
           "spec": {"containers": [{"name": "app", "image": "registry.local/app:1",
                                    "securityContext": {"privileged": True}}]}}
    adapter, selected = KubernetesAdapter(), target()
    transport = Lists({"pods": response("pods", [pod]), "deployments": CommandResult("", 403),
                       "cronjobs": CommandResult("", 403)})
    collected = adapter.collect(selected, transport, tmp_path)
    findings = adapter.run_detection(selected, collected)
    assert any(f.rule_version == "k8s:cis:5.2.2" and f.is_open
               and "k8s-object:work/pod/observed/app" in f.tags for f in findings)
    assert not any(f.status == "not_a_finding" for f in findings)
    assert collected.raw[scope.SCOPE_KEY]["namespace_lists_complete"] is False


@pytest.mark.parametrize("field,value", [("name", []), ("kind", {}), ("namespace", 7)])
def test_malformed_binding_subject_is_unavailable_not_complete(tmp_path, field, value):
    binding = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
               "metadata": {"name": "binding", "namespace": "work"},
               "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
               "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "work"}]}
    binding["subjects"][0][field] = value
    adapter, selected = KubernetesAdapter(), target()
    collected = adapter.collect(selected, Lists({"rolebindings": response("rolebindings", [binding])}), tmp_path)
    assert collected.raw[scope.SCOPE_KEY]["resources"]["rolebindings"]["work"]["status"] == "unavailable"
    assert "rolebindings" not in collected.artifacts
    assert all(f.status == "not_reviewed" for f in adapter.run_detection(selected, collected))


@pytest.mark.parametrize("drift", ["namespace", "context", "kubeconfig", "executable"])
def test_direct_transport_rejects_drift_during_final_read(tmp_path, monkeypatch, drift):
    adapter, selected = KubernetesAdapter(), target()
    transport = adapter.make_transport(selected)
    calls = []

    def process(argv, **kwargs):
        resource = argv[argv.index("get") + 1]
        calls.append(resource)
        if resource == "services":
            key = {"namespace": "namespaces", "executable": "kubectl"}.get(drift, drift)
            selected.options[key] = ["outside"] if drift == "namespace" else "changed"
        return SimpleNamespace(returncode=0, stdout=json.dumps(response(resource)), stderr="")

    monkeypatch.setattr("subprocess.run", process)
    with pytest.raises(PermissionError):
        adapter.collect(selected, transport, tmp_path)
    assert calls == list(scope.NAMESPACED_RESOURCES)
    assert not (tmp_path / "services.json").exists()


def test_closed_grammar_rejects_alternate_spellings_and_connection_flags(monkeypatch):
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: pytest.fail("unexpected process"))
    transport = KubernetesAdapter().make_transport(target())
    commands = [
        "kubectl get po -n work -o json", "kubectl get pods.v1 -n work -o json",
        "kubectl get pods --namespace=work -o json", "kubectl get pods -nwork -o json",
        "kubectl get pods -n work --output=json", "kubectl get pods -n work -ojson",
        "kubectl get pods -n work -o json --raw=/api/v1/secrets",
        "kubectl get pods -n work -o json --server=https://outside.invalid",
        "kubectl get pods -n work -o json --token=fixture",
        "kubectl get pods -n work -o json --as-group=system:masters",
        "kubectl get pods -n work -o json --cluster=outside",
        "kubectl get pods -n work -o json --kuberc=fixture",
        "kubectl get pods -n work -o json --profile-output=fixture",
        "kubectl get pods -n work -o json\rkubectl get secrets -A",
    ]
    for command in commands:
        with pytest.raises(PermissionError):
            transport.run(command)


def test_namespace_collection_rejects_backends_that_bypass_kubectl_guard(tmp_path):
    adapter = KubernetesAdapter()
    for backend in ("local", "ssh", "simulated"):
        selected = target()
        selected.transport = backend
        transport = SimpleNamespace(run=lambda *a, **kw: pytest.fail("unguarded backend reached"))
        for call in (lambda: adapter.discover(selected, transport),
                     lambda: adapter.collect(selected, transport, tmp_path / backend),
                     lambda: adapter.health_check(selected, transport)):
            with pytest.raises(ValueError, match="kubeconfig or fixture"):
                call()
        assert not (tmp_path / backend).exists()


@pytest.mark.parametrize("failure", [CancelledError, PermissionError, KillSwitchEngaged])
def test_stop_exceptions_escape_collection_without_later_reads(tmp_path, failure):
    transport = Lists({"pods": failure("stopped fixture")})
    with pytest.raises(failure):
        KubernetesAdapter().collect(target(), transport, tmp_path)
    assert transport.calls == [scope.list_command("pods", "work")]
    assert not list(tmp_path.glob("*.json"))


def test_roundtripped_read_only_evidence_blocks_fresh_cluster_transport(tmp_path, monkeypatch):
    adapter, selected = KubernetesAdapter(), target()
    collected = adapter.collect(selected, Lists(), tmp_path / "raw")
    evidence = Finding.from_dict(adapter.run_detection(selected, collected)[0].to_dict())
    selected.options.pop("namespaces")
    transport = adapter.make_transport(selected)
    monkeypatch.setattr(transport, "run", lambda *a, **kw: pytest.fail("unexpected cluster operation"))
    fix = next(f for f in adapter.fixes() if f.kind == "manifest")
    before = BeforeState(selected.id, fix.fix_ref, str(tmp_path / "unread"))
    for proof in (replace(evidence, tags=[]), replace(evidence, collection_provenance={})):
        for call in (lambda: adapter.capture_before_state(selected, transport, fix, proof, tmp_path / "before"),
                     lambda: adapter.apply(selected, transport, fix, proof, before),
                     lambda: adapter.verify(selected, transport, fix, proof)):
            with pytest.raises(PermissionError, match="read-only"):
                call()
    assert not (tmp_path / "before").exists()


@pytest.mark.parametrize("drift", ["inventory_replacement", "account", "credential", "kill"])
def test_verified_final_response_rechecks_current_inventory_and_account(selected_cluster, tmp_path, monkeypatch, drift):
    ctx, selected, person, config, policy_path, calls = selected_cluster
    selected.options["namespaces"] = ["work"]
    ctx.inventory.save()

    def process(argv, **kwargs):
        calls.append((argv, kwargs))
        resource = argv[argv.index("get") + 1]
        if resource == "services":
            if drift == "inventory_replacement":
                # Replace only the persisted row; the caller's cached Target stays unchanged.
                from cyberthunder.inventory.targets import Inventory
                fresh = Inventory.load(ctx.inventory.path)
                fresh.get(selected.id).options["namespaces"] = ["outside"]
                fresh.save()
            elif drift == "account":
                policy = json.loads(policy_path.read_text())
                policy["entries"][0]["grants"][0]["credential"]["options"]["context"] = "other-account"
                write(policy_path, json.dumps(policy).encode())
            elif drift == "credential":
                config.write_text("changed fixture credential")
            else:
                monkeypatch.setenv("CT_KILL", "1")
        return SimpleNamespace(returncode=0, stdout=json.dumps(response(resource)), stderr="")

    monkeypatch.setattr("subprocess.run", process)
    with principal_scope(person), operation_scope("scan"):
        transport = ctx.transport_for(selected)
        with pytest.raises((PermissionError, ScopeViolation, KillSwitchEngaged)):
            ctx.adapters.get("kubernetes").collect(selected, transport, tmp_path / "raw")
    assert len(calls) == len(scope.NAMESPACED_RESOURCES)
    assert_selected(calls, config)
    assert not (tmp_path / "raw" / "services.json").exists()
    assert TOKEN not in ctx.audit.path.read_text()
