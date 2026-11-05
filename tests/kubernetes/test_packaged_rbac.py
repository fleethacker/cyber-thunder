"""Exercise the Kubernetes checks using the packaged role and recorded cluster data."""
from pathlib import Path
import shlex

import pytest
import yaml

from cyberthunder.adapters.kubernetes import KubernetesAdapter, checks
from cyberthunder.inventory.targets import Target
from cyberthunder.transport.base import CommandResult
from cyberthunder.transport.fixture import FixtureTransport

ROOT = Path(__file__).resolve().parents[2]
RESOURCE_GROUPS = {
    "nodes": "", "namespaces": "", "pods": "", "serviceaccounts": "", "services": "",
    "deployments": "apps", "statefulsets": "apps", "daemonsets": "apps",
    "cronjobs": "batch", "jobs": "batch",
    "clusterrolebindings": "rbac.authorization.k8s.io", "rolebindings": "rbac.authorization.k8s.io",
    "networkpolicies": "networking.k8s.io",
}


@pytest.fixture
def role():
    documents = yaml.safe_load_all((ROOT / "deploy/kubernetes/cyberthunder.yaml").read_text(encoding="utf-8"))
    return next(document for document in documents if document["kind"] == "ClusterRole")


def permits(role, group, resource, verb):
    return any(group in rule.get("apiGroups", []) and resource in rule.get("resources", [])
               and verb in rule["verbs"] for rule in role["rules"])


class PackagedRoleTransport(FixtureTransport):
    def __init__(self, role):
        super().__init__(ROOT / "tests/fixtures/kubernetes/sim_session", strict=True)
        self.role = role

    def run(self, command, *, timeout=120, sudo=False):
        argv = shlex.split(command)
        if argv[1] == "version":
            allowed = any("/version" in rule.get("nonResourceURLs", []) and "get" in rule["verbs"]
                          for rule in self.role["rules"])
        elif argv[2] == "--raw":
            allowed = permits(self.role, "", "nodes/proxy", "get")
        else:
            resource = argv[2]
            allowed = permits(self.role, RESOURCE_GROUPS[resource], resource, "list")
        if not allowed:
            self.calls.append(command)
            return CommandResult(command, 1, stderr=f"Forbidden by packaged role: {command}")
        return super().run(command, timeout=timeout, sudo=sudo)


def test_packaged_role_collects_all_configuration_scan_artifacts(role, tmp_path):
    adapter = KubernetesAdapter()
    target = Target(id="local-cluster", name="Local Kubernetes cluster", asset_type="kubernetes",
                    transport="kubeconfig", options={"kubeconfig": "/etc/cyberthunder/kubeconfig"})
    transport = PackagedRoleTransport(role)
    collected = adapter.collect(target, transport, tmp_path)
    assert not collected.errors, collected.errors
    assert set(checks.ARTIFACTS) <= set(collected.artifacts)
    findings = adapter.run_detection(target, collected)
    assert any(finding.rule_version == "k8s:hunt:admin-to-default" for finding in findings)
    assert any(finding.rule_version == "k8s:cis:5.1.5" for finding in findings)
    assert not collected.errors, collected.errors


def test_packaged_role_remains_limited_to_scan_reads(role):
    for rule in role["rules"]:
        assert set(rule["verbs"]) <= {"get", "list"}
        assert "*" not in rule.get("apiGroups", [])
        for resource in rule.get("resources", []):
            assert resource in RESOURCE_GROUPS
            assert rule["apiGroups"] == [RESOURCE_GROUPS[resource]]
        assert set(rule.get("nonResourceURLs", [])) <= {"/version"}
