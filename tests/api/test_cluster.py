"""A requested cluster baseline persists risk profiles and the requesting actor."""
from unittest.mock import Mock
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from cyberthunder.cluster import service
from cyberthunder.inventory.targets import Target
from tests.api.conftest import ACTOR


@pytest.fixture(autouse=True)
def isolated_cluster_runtime(ctx, monkeypatch):
    ctx.settings.bootstrap_cluster_target = False
    ctx.settings.scan_interval_s = 0
    ctx.settings.content_check_interval_s = 0
    process = Mock(side_effect=AssertionError("unexpected subprocess"))
    network = Mock(side_effect=AssertionError("unexpected network call"))
    monkeypatch.setattr(service.subprocess, "run", process)
    monkeypatch.setattr(service.urllib.request, "urlopen", network)
    return process, network


def test_baseline_records_operator_and_persists_risk(client, ctx, monkeypatch, isolated_cluster_runtime):
    @contextmanager
    def scan_context():
        yield {"cache_dir": ctx.store.root / "managed-cache", "generation": "fixture-generation",
               "state": "ready", "provenance": "offline_import", "integrity_verified": True,
               "engine": {"available": True, "version": "0.71.1", "supported": True},
               "databases": [{"kind": "main", "present": True, "stale": False}]}

    ctx.vulnerabilities = SimpleNamespace(scan_context=scan_context, due_update=lambda: False)
    target = Target(id="explicit-range", name="Isolated test range", asset_type="kubernetes",
                    transport="kubeconfig", in_scope=True,
                    options={"kubeconfig": str(ctx.store.root / "fixture-config"), "context": "fixture-range"})
    ctx.inventory.add(target)
    ctx.inventory.save()

    def survey(binding, actor):
        assert binding.target_id == target.id and actor == ACTOR["X-Actor"]
        assert binding.kubeconfig == target.options["kubeconfig"]
        assert binding.context == target.options["context"]
        return {"namespaces": [{"name": "demo"}],
                "workloads": [{"namespace": "demo", "kind": "Deployment", "name": "web",
                               "images": ["example.test/web:1"]}], "errors": []}

    def scan_image(image, run_dir, binding, actor, *, snapshot):
        assert binding.target_id == target.id and actor == ACTOR["X-Actor"]
        assert run_dir.parent == ctx.cluster.root / "baselines"
        assert snapshot["generation"] == "fixture-generation"
        section = {"target": image, "class": "os-pkgs", "type": "debian"}
        return {"image": image, "complete": True, "sections": [section],
                "vulnerabilities": [{"id": "CVE-2026-12345", "package": "fixture-package", "installed_version": "1",
                                     "severity": "HIGH", "cvss": 8.0, "fixed_version": "2", "section": section}]}, None

    monkeypatch.setattr(ctx.cluster, "_survey", survey)
    monkeypatch.setattr(ctx.cluster, "_scan_image", scan_image)

    response = client.post("/api/v1/cluster/baseline", json={"target_id": target.id, "use_openai": False}, headers=ACTOR)
    assert response.status_code == 200, response.text
    baseline = response.json()
    assert baseline["errors"] == []
    profile = baseline["namespaces"][0]
    assert profile["namespace"] == "demo"
    assert profile["summary"]["high"] == 1
    assert profile["fixable_vulnerabilities"] == 1
    assert profile["description_source"] == "template"
    saved = client.get("/api/v1/cluster/risk").json()
    assert saved["id"] == baseline["id"]
    assert saved["namespaces"] == baseline["namespaces"]
    assert saved["target"]["target_id"] == target.id
    assert saved["requested_by"] == baseline["requested_by"] == ACTOR["X-Actor"]
    assert ctx.cluster.latest() == baseline
    audit = [r for r in ctx.audit.records() if r["action"] == "cluster.baseline"]
    assert len(audit) == 1
    assert audit[0]["actor"] == ACTOR["X-Actor"]
    assert audit[0]["subject"] == baseline["id"]
    assert audit[0]["details"]["target_id"] == target.id
    isolated_cluster_runtime[0].assert_not_called()
    isolated_cluster_runtime[1].assert_not_called()
