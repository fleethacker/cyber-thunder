"""k3s control-plane collection, envFrom secrets, kube-system escape pods and kind-aware fix selection."""
import json

import pytest

from cyberthunder.adapters.base import Collected
from cyberthunder.adapters.kubernetes import KubernetesAdapter, k3s
from cyberthunder.adapters.kubernetes import checks as k8s_checks
from cyberthunder.adapters.kubernetes import hunt as k8s_hunt
from cyberthunder.adapters.kubernetes.kubectl import OBJ_TAG
from cyberthunder.config import Settings
from cyberthunder.inventory.targets import Target
from cyberthunder.remediation.library import FixLibrary
from cyberthunder.transport.base import CommandResult

K3S_CONFIG = """\
write-kubeconfig-mode: "0600"
token: K10-super-secret-join-token
# cyber-thunder seed
kube-apiserver-arg:
  - "anonymous-auth=true"
kubelet-arg:
  - "read-only-port=10255"
"""
EXECSTART = ("{ path=/usr/local/bin/k3s ; argv[]=/usr/local/bin/k3s server --token K10-other-secret "
             "--kube-controller-manager-arg=profiling=true ; ignore_errors=no ; start_time=[n/a] ; status=0/0 }")


def _collected(tmp_path, target, pods=None, **raw):
    p = tmp_path / "pods.json"
    p.write_text(json.dumps({"items": pods or []}), encoding="utf-8")
    return Collected(target_id=target.id, asset_type="kubernetes", workdir=str(tmp_path),
                     artifacts={"pods": str(p)}, raw=dict(raw))


@pytest.fixture
def k8s_target():
    return Target(id="k3s-01", name="k3s-01", asset_type="kubernetes", transport="kubeconfig",
                  options={"kubeconfig": "unused"})


def _by_rule(findings):
    return {(f.rule_version, f.status): f for f in findings}


# -- detection-2: API-server flags on k3s ------------------------------------------------------------------
def test_k3s_effective_flags_layers_defaults_config_and_cli():
    flags = k3s.effective_flags(K3S_CONFIG, EXECSTART)
    assert flags["role"] == "server"
    assert flags["kube-apiserver"]["anonymous-auth"] == "true"
    assert "audit-log-path" not in flags["kube-apiserver"]
    assert flags["kube-apiserver"]["authorization-mode"] == "Node,RBAC"     # k3s default kept
    assert flags["kube-controller-manager"]["profiling"] == "true"          # command line wins
    assert flags["kubelet"]["read-only-port"] == "10255"
    assert "K10" not in json.dumps(flags)                                   # the join token is never kept


def test_k3s_agent_has_no_api_server():
    flags = k3s.effective_flags(None, "/usr/local/bin/k3s agent --server https://10.0.0.1:6443")
    assert flags["role"] == "agent" and "kube-apiserver" not in flags and "kubelet" in flags


def test_k3s_flags_detect_anonymous_auth_and_missing_audit_log(tmp_path, k8s_target):
    flags = dict(k3s.effective_flags(K3S_CONFIG, EXECSTART), node="k3s-01")
    col = _collected(tmp_path, k8s_target, **{k8s_checks.K3S_FLAGS: flags})
    found = _by_rule(k8s_checks.run_checks(k8s_target, col))
    for sid in ("CNTR-K8-000360", "CNTR-K8-000610", "CNTR-K8-000910", "CNTR-K8-000330"):
        f = found[(sid, "open")]
        assert OBJ_TAG + "-/node/k3s-01" in f.tags
    assert ("CNTR-K8-000270", "open") not in found


def test_api_server_rules_not_reviewed_without_a_source(tmp_path, k8s_target):
    col = _collected(tmp_path, k8s_target)
    found = _by_rule(k8s_checks.run_checks(k8s_target, col))
    assert ("CNTR-K8-000360", "not_reviewed") in found
    assert ("CNTR-K8-000610", "not_reviewed") in found
    assert not any(st == "open" and sid.startswith("CNTR-K8-000") for sid, st in found)


class _NodeTransport:
    def __init__(self):
        self.commands = []

    def run(self, cmd, timeout=None, sudo=False):
        self.commands.append((cmd, sudo))
        out = {k3s.READ_CONFIG: K3S_CONFIG, k3s.READ_EXECSTART: EXECSTART}.get(cmd)
        return CommandResult(cmd, 0 if out is not None else 127, out or "")


def test_collect_reads_k3s_node_when_node_target_is_set(state_dir, tmp_path, monkeypatch):
    adapter = KubernetesAdapter()
    settings = Settings.from_env(state_dir=state_dir)
    target = adapter.demo_targets()[0]
    target.options = dict(target.options, node_target="k3s-01-node")
    adapter.reset_simulated(target, settings)
    kt = adapter.make_transport(target, settings)
    node = Target(id="k3s-01-node", name="k3s-01", asset_type="linux", address="10.0.0.1")
    nt = _NodeTransport()
    monkeypatch.setattr(adapter, "node_transport", lambda node_id: (node, nt))
    col = adapter.collect(target, kt, tmp_path / "scan")
    assert not col.errors, col.errors
    assert (k3s.READ_CONFIG, True) in nt.commands
    stored = json.dumps(col.to_dict())
    assert "K10" not in stored
    found = adapter.run_detection(target, col)
    hits = [f for f in found if f.rule_version == "CNTR-K8-000360" and OBJ_TAG + "-/node/k3s-01" in f.tags]
    assert hits and "anonymous-auth=true" in hits[0].evidence


def test_node_target_out_of_scope_is_refused(state_dir, tmp_path, monkeypatch):
    from cyberthunder.inventory.targets import Inventory
    from cyberthunder.store import StateStore
    monkeypatch.setenv("CT_STATE_DIR", str(state_dir))
    inv = Inventory(targets=[Target(id="k3s-01-node", name="k3s-01", asset_type="linux", address="10.0.0.1",
                                    in_scope=False)])
    inv.save(StateStore(Settings.from_env().state_dir).targets)
    adapter = KubernetesAdapter()
    settings = Settings.from_env()
    target = adapter.demo_targets()[0]
    target.options = dict(target.options, node_target="k3s-01-node")
    adapter.reset_simulated(target, settings)
    col = adapter.collect(target, adapter.make_transport(target, settings), tmp_path / "scan")
    assert any("node_target k3s-01-node" in e for e in col.errors)
    assert k8s_checks.K3S_FLAGS not in col.raw


# -- detection-5: envFrom secretRef ----------------------------------------------------------------------
def test_envfrom_secret_is_flagged(tmp_path, k8s_target):
    pod = {"metadata": {"name": "db-client", "namespace": "apps"},
           "spec": {"containers": [{"name": "app", "image": "registry.local/app:1.0",
                                    "envFrom": [{"secretRef": {"name": "db-creds"}}]}]}}
    col = _collected(tmp_path, k8s_target, pods=[pod])
    hits = [f for f in k8s_checks.run_checks(k8s_target, col) if f.rule_version == "CNTR-K8-001160"]
    assert hits and "envFrom secret db-creds" in hits[0].evidence


# -- detection-6: escape pod hidden in kube-system -----------------------------------------------------------
ESCAPE_POD = {"metadata": {"name": "kube-proxy-helper", "namespace": "kube-system"},
              "spec": {"hostPID": True, "containers": [{
                  "name": "helper", "image": "ghcr.io/x0rcist/node-tools:latest",
                  "securityContext": {"privileged": True}}],
                  "volumes": [{"name": "host-root", "hostPath": {"path": "/"}}]}}


def test_privileged_host_root_pod_in_kube_system_is_found(tmp_path, k8s_target):
    col = _collected(tmp_path, k8s_target, pods=[ESCAPE_POD])
    rules = {f.rule_version for f in k8s_hunt.run_hunt(k8s_target, col)}
    assert {"k8s:hunt:host-escape", "k8s:hunt:unexpected-system-pod"} <= rules


def test_controller_owned_system_pods_stay_quiet(tmp_path, k8s_target):
    pods = [{"metadata": {"name": "coredns-6799fbcd5-x7k2p", "namespace": "kube-system",
                          "ownerReferences": [{"kind": "ReplicaSet", "name": "coredns-6799fbcd5"}]},
             "spec": {"containers": [{"name": "coredns", "image": "registry.local/k8s/coredns:1.11.1"}]}},
            {"metadata": {"name": "kube-apiserver-node1", "namespace": "kube-system",
                          "annotations": {"kubernetes.io/config.mirror": "abc", "kubernetes.io/config.source": "file"}},
             "spec": {"containers": [{"name": "kube-apiserver", "image": "registry.local/k8s/kube-apiserver:v1.30.6",
                                      "securityContext": {"privileged": True}}],
                      "volumes": [{"name": "etc", "hostPath": {"path": "/etc"}}]}}]
    col = _collected(tmp_path, k8s_target, pods=pods)
    assert k8s_hunt.run_hunt(k8s_target, col) == []


# -- remediation-9: fixes must fit the object kind ---------------------------------------------------------
def test_bare_pod_findings_resolve_to_runbooks(state_dir, tmp_path):
    adapter = KubernetesAdapter()
    settings = Settings.from_env(state_dir=state_dir)
    target = adapter.demo_targets()[0]
    adapter.reset_simulated(target, settings)
    col = adapter.collect(target, adapter.make_transport(target, settings), tmp_path / "scan")
    findings = adapter.run_detection(target, col)
    lib = FixLibrary(adapter.fixes())
    for rule in ("k8s:cis:5.2.2", "k8s:cis:5.2.3", "k8s:cis:5.2.6"):
        f = next(x for x in findings if x.rule_version == rule and "apps/pod/kube-proxy-helper" in x.rule_id)
        assert lib.resolve(f).kind == "runbook", rule
    dep = next(x for x in findings if x.rule_version == "k8s:cis:5.2.2" and "apps/deployment/web-frontend" in x.rule_id)
    assert lib.resolve(dep).fix_ref == "k8s:fix:deployment-drop-privileged"
    escape = next(x for x in findings if x.rule_version == "k8s:hunt:host-escape")
    assert lib.resolve(escape).fix_ref == "k8s:fix:delete-pod"
