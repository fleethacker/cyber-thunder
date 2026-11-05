"""The packaged app exposes its host cluster in Assets without manual registration."""
import json
from pathlib import Path
import subprocess
from unittest.mock import Mock

from fastapi.testclient import TestClient
import pytest
import yaml

from cyberthunder.api.app import create_app
from cyberthunder.config import Settings
from cyberthunder.context import AppContext


@pytest.fixture(autouse=True)
def offline_tools(monkeypatch):
    monkeypatch.setattr("cyberthunder.config.platform.node", lambda: "cluster-bootstrap-test")
    monkeypatch.setattr(subprocess, "run", Mock(side_effect=AssertionError("unexpected subprocess")))
    monkeypatch.setattr("urllib.request.urlopen", Mock(side_effect=AssertionError("unexpected network call")))


@pytest.fixture
def packaged_settings(state_dir, monkeypatch):
    manifest = Path(__file__).resolve().parents[1] / "deploy/kubernetes/cyberthunder.yaml"
    documents = list(yaml.safe_load_all(manifest.read_text(encoding="utf-8")))
    deployment = next(d for d in documents if d["kind"] == "Deployment")
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    for variable in container["env"]:
        monkeypatch.setenv(variable["name"], variable["value"])
    return Settings.from_env(state_dir=state_dir, explain_precompute=False,
                             scan_interval_s=0, content_check_interval_s=0)


def test_packaged_startup_registers_host_cluster(packaged_settings):
    ctx = AppContext(packaged_settings)
    with TestClient(create_app(ctx)) as client:
        targets = client.get("/api/v1/targets").json()["targets"]
        assert len(targets) == 1
        target = targets[0]
        assert target["id"] == "local-cluster"
        assert target["name"] == "Local Kubernetes cluster"
        assert target["asset_type"] == "kubernetes"
        assert target["transport"] == "kubeconfig"
        expected_kubeconfig = target["options"]["kubeconfig"]
        assert Path(expected_kubeconfig) == Path("/etc/cyberthunder/kubeconfig")
        assert target["options"] == {"kubeconfig": expected_kubeconfig,
                                     "context": "in-cluster", "kubectl": "kubectl"}
        assert target["in_scope"] is False
        assert target["sudo"] is False
        assert "discovery-source" in target["tags"]
    events = [r for r in ctx.audit.records() if r["action"] == "inventory.bootstrap"]
    assert len(events) == 1
    assert events[0]["details"]["authorization_required"] is True
    assert events[0]["details"]["in_scope"] is False
    assert ctx.audit.verify().ok


def test_restart_preserves_operator_scope_edits_and_external_assets(packaged_settings):
    ctx = AppContext(packaged_settings)
    headers = {"X-Actor": "ITC Rivera"}
    with TestClient(create_app(ctx)) as client:
        authorized = client.put("/api/v1/targets/local-cluster", headers=headers, json={"in_scope": True})
        assert authorized.status_code == 200
        changed = client.put("/api/v1/targets/local-cluster", headers=headers,
                             json={"name": "Shipboard cluster", "in_scope": False})
        assert changed.status_code == 200
        external = client.post("/api/v1/targets", headers=headers, json={
            "id": "external-cluster", "asset_type": "kubernetes", "transport": "kubeconfig",
            "in_scope": False, "options": {"kubeconfig": "/etc/external/kubeconfig"},
        })
        assert external.status_code == 201
        before = client.get("/api/v1/targets").json()
    restarted = AppContext(packaged_settings)
    with TestClient(create_app(restarted)) as client:
        assert client.get("/api/v1/targets").json() == before
    assert len([r for r in restarted.audit.records() if r["action"] == "inventory.bootstrap"]) == 1
    assert restarted.audit.verify().ok


def test_host_cluster_discovery_uses_packaged_context_and_node_permissions(packaged_settings, monkeypatch):
    manifest = Path(__file__).resolve().parents[1] / "deploy/kubernetes/cyberthunder.yaml"
    documents = list(yaml.safe_load_all(manifest.read_text(encoding="utf-8")))
    role = next(d for d in documents if d["kind"] == "ClusterRole")
    calls = []

    def run(argv, **kwargs):
        assert argv[:2] == ["kubectl", "--kubeconfig"]
        assert Path(argv[2]) == Path("/etc/cyberthunder/kubeconfig")
        assert argv[3:5] == ["--context", "in-cluster"]
        calls.append(argv[5:])
        if argv[5:] == ["version", "-o", "json"]:
            assert any("/version" in r.get("nonResourceURLs", []) and "get" in r["verbs"]
                       for r in role["rules"])
            data = {"serverVersion": {"gitVersion": "v1.36.4"}}
        else:
            assert argv[5:] == ["get", "nodes", "-o", "json"]
            assert any("nodes" in r.get("resources", []) and "list" in r["verbs"]
                       for r in role["rules"])
            data = {"items": [{"metadata": {"name": "node-01"}, "status": {
                "nodeInfo": {"osImage": "Test Linux"},
                "conditions": [{"type": "Ready", "status": "True"}],
            }}]}
        return subprocess.CompletedProcess(argv, 0, json.dumps(data), "")

    monkeypatch.setattr("cyberthunder.adapters.kubernetes.kubectl.subprocess.run", run)
    ctx = AppContext(packaged_settings)
    headers = {"X-Actor": "ITC Rivera"}
    with TestClient(create_app(ctx)) as client:
        refused = client.post("/api/v1/targets/local-cluster/discover", headers=headers)
        assert refused.status_code == 403
        assert calls == []
        authorized = client.put("/api/v1/targets/local-cluster", headers=headers, json={"in_scope": True})
        assert authorized.status_code == 200
        scope = [r for r in ctx.audit.records() if r["action"] == "scope.change"]
        assert len(scope) == 1 and scope[0]["actor"] == headers["X-Actor"]
        response = client.post("/api/v1/targets/local-cluster/discover", headers=headers)
        assert response.status_code == 200, response.text
        facts = response.json()
        assert facts["os_name"] == "Kubernetes"
        assert facts["os_version"] == "v1.36.4"
        assert facts["extra"]["nodes"] == ["node-01"]
        assert facts["extra"]["nodes_ready"] == 1
    assert len(calls) == 2


def test_bootstrap_can_be_disabled(packaged_settings):
    packaged_settings.bootstrap_cluster_target = False
    with TestClient(create_app(AppContext(packaged_settings))) as client:
        assert client.get("/api/v1/targets").json()["targets"] == []
