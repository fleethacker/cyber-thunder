"""Live subprocess entry points select one user's protected Kubernetes config."""
import json
import time
from types import SimpleNamespace

import pytest

from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.control.principal import Principal, principal_scope, operation_scope
from cyberthunder.inventory.targets import Target
from tests.security.test_kube_credentials import cert_material, document, write, TOKEN


@pytest.fixture
def selected_cluster(state_dir, cert_material, monkeypatch):
    ctx = AppContext(Settings(state_dir=state_dir, auth_mode="oidc", security_mode="range",
                              llm_backend="template", auto_propose=False, explain_precompute=False))
    target = Target("cluster-a", "Cluster A", "kubernetes", "kubeconfig", sudo=False,
                    options={"kubeconfig": "shared-administrator-config", "context": "admin"})
    ctx.inventory.add(target)
    ctx.inventory.save()
    person = Principal("https://identity.example.test", "alice", "Alice", kind="human",
                       roles=("analyst", "approver"), expires_at=time.time() + 300)
    folder = state_dir / "auth"
    folder.mkdir(mode=0o700)
    config = write(folder / "alice.yaml", document(cert_material))
    policy = {"version": 1, "entries": [{"issuer": person.issuer, "subject": person.subject,
        "node_actions": [], "grants": [{"target_ids": ["cluster-a"],
            "actions": ["read", "scan", "discover", "apply"],
            "credential": {"username": None, "credential_ref": None, "sudo": False,
                "options": {"kubeconfig": str(config), "context": "alice-A"}}}]}]}
    path = write(folder / "access.json", json.dumps(policy).encode())
    calls = []
    def process(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout='{"items":[]}', stderr="")
    monkeypatch.setattr("subprocess.run", process)
    monkeypatch.setenv("KUBECONFIG", "ambient-administrator")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "fixture-unused-secret")
    return ctx, target, person, config, path, calls


def assert_selected(calls, config):
    assert calls
    for argv, kwargs in calls:
        assert argv[0] == "kubectl"
        assert argv[argv.index("--kubeconfig") + 1] == str(config)
        assert argv[argv.index("--context") + 1] == "alice-A"
        assert argv[argv.index("--user") + 1] == "alice"
        assert "KUBECONFIG" not in kwargs["env"]
        assert "AWS_SECRET_ACCESS_KEY" not in kwargs["env"]
        assert TOKEN not in json.dumps(argv) + json.dumps(kwargs["env"])


def test_adapter_and_cluster_survey_use_the_same_selected_account(selected_cluster):
    ctx, target, person, config, _, calls = selected_cluster
    with principal_scope(person):
        with operation_scope("scan"):
            transport = ctx.transport_for(target)
            transport.run("kubectl get nodes -o json")
        result = ctx.cluster.survey(actor=person.actor, target_id=target.id)
    assert result["namespaces"] == []
    assert_selected(calls, config)
    assert ctx.inventory.get(target.id).options["context"] == "admin"
    assert TOKEN not in ctx.audit.path.read_text()


def test_kubectl_override_and_changed_config_stop_before_subprocess(selected_cluster):
    ctx, target, person, config, _, calls = selected_cluster
    with principal_scope(person), operation_scope("scan"):
        transport = ctx.transport_for(target)
        with pytest.raises(PermissionError):
            transport.run("kubectl get nodes --context admin")
        config.write_text("invalid changed config")
        with pytest.raises(PermissionError):
            transport.run("kubectl get nodes")
    assert calls == []


def test_survey_revocation_stops_before_next_collection(selected_cluster, monkeypatch):
    ctx, target, person, _, path, calls = selected_cluster
    def revoke(argv, **kwargs):
        calls.append((argv, kwargs))
        path.write_text('{"version":1,"entries":[]}')
        return SimpleNamespace(returncode=0, stdout='{"items":[]}', stderr="")
    monkeypatch.setattr("subprocess.run", revoke)
    with principal_scope(person):
        with pytest.raises(PermissionError):
            ctx.cluster.survey(actor=person.actor, target_id=target.id)
    assert len(calls) == 1


def test_cluster_direct_calls_cannot_replace_verified_actor(selected_cluster):
    ctx, target, person, _, _, calls = selected_cluster
    with principal_scope(person):
        with pytest.raises(PermissionError):
            ctx.cluster.survey(actor="different operator", target_id=target.id)
    assert calls == []
