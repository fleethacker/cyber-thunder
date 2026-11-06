"""k3s drop-in precedence and guarded k3d collection, including failure coverage."""
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from cyberthunder.adapters.base import Collected
from cyberthunder.adapters.kubernetes import KubernetesAdapter, checks, k3d, k3s
from cyberthunder.inventory.targets import Inventory, Target


def bundle(files=()):
    return "\0".join(["CT_K3S_CONFIG_V1", *(p for file in files for p in file), "CT_END", ""])


def test_dropins_sorted_replace_append_and_cli_replaces_entire_list():
    files = [(k3s.CONFIG_PATH + ".d/20-last.yaml", "kube-apiserver-arg+: [profiling=true]"),
             (k3s.CONFIG_PATH, "kube-apiserver-arg: [anonymous-auth=true, audit-log-path=/old]"),
             (k3s.CONFIG_PATH + ".d/10-first.yaml", "kube-apiserver-arg: [audit-log-path=/new]"),
             (k3s.CONFIG_PATH + ".d/15-more.yaml", "kube-apiserver-arg+: [audit-policy-file=/policy]")]
    merged = k3s.effective_flags(None, "k3s server", files=files)["kube-apiserver"]
    assert merged["anonymous-auth"] == "false"  # previous whole list replaced
    assert merged["audit-log-path"] == "/new"
    assert merged["audit-policy-file"] == "/policy"
    assert merged["profiling"] == "true"
    cli = k3s.effective_flags(None, "k3s server --kube-apiserver-arg=anonymous-auth=true", files=files)
    assert cli["kube-apiserver"]["anonymous-auth"] == "true"
    assert "audit-log-path" not in cli["kube-apiserver"]
    assert "audit-policy-file" not in cli["kube-apiserver"]
    assert cli["kube-apiserver"]["profiling"] == "false"


@pytest.mark.parametrize("text", ["", "CT_K3S_CONFIG_V1\0", bundle([(k3s.CONFIG_PATH, "")])[:-7],
                                  bundle([("/etc/shadow", "secret")]),
                                  bundle([(k3s.CONFIG_PATH, ""), (k3s.CONFIG_PATH, "")])])
def test_incomplete_or_unexpected_bundles_rejected(text):
    with pytest.raises(ValueError):
        k3s.config_bundle(text)


@pytest.mark.parametrize("config", ["token: SECRET\nkube-apiserver-arg: [", "[]", "false", "kubelet-arg: true",
                                    "kubelet-arg: [x]\nkubelet-arg: [y]", "config: /elsewhere",
                                    "kubelet-arg: [x]\nkubelet-arg+: [y]"])
def test_malformed_yaml_never_leaks_tokens(config):
    with pytest.raises(ValueError) as exc:
        k3s.effective_flags(config, "k3s server")
    assert "SECRET" not in str(exc.value)


@pytest.mark.parametrize("cmd", ["", "k3s", "unrelated server", "k3s server -c /elsewhere",
                                 "k3s server --config=/elsewhere", "k3s server --kubelet-arg", "k3s server '"])
def test_uncollected_or_unsupported_commandline_rejected(cmd):
    with pytest.raises(ValueError):
        k3s.effective_flags("", cmd)


def test_fixed_script_reads_real_files_sorted_and_fails_unreadable_type(tmp_path):
    bash = Path("C:/Program Files/Git/bin/bash.exe")
    if not bash.exists():
        import shutil
        found = shutil.which("bash")
        if not found:
            pytest.skip("bash unavailable for isolated file collection")
        bash = Path(found)
    root = tmp_path / "config"
    root.mkdir()
    config = root / "config.yaml"
    drops = root / "config.yaml.d"
    drops.mkdir()
    config.write_text("token: SECRET\nkube-apiserver-arg: [anonymous-auth=true]\n")
    (drops / "20.yaml").write_text("kube-apiserver-arg+: [audit-log-path=/audit]\n")
    (drops / "10.yaml").write_text("kube-apiserver-arg: [anonymous-auth=false]\n")
    (drops / ".05.yaml").write_text("kube-controller-manager-arg: [profiling=true]\n")
    (drops / ".yaml").write_text("kubelet-arg: [read-only-port=10255]\n")
    # Only the test redirects the fixed /etc tree to an isolated directory.
    path = root.as_posix()
    script = k3s.READ_CONFIG.replace("/etc/rancher/k3s", path).replace("/etc /etc/rancher ", "")
    result = subprocess.run([str(bash), "-c", script], capture_output=True)
    assert result.returncode == 0, result.stderr
    collected = result.stdout.decode().replace(path, "/etc/rancher/k3s")
    flags = k3s.effective_flags(None, "k3s server", files=k3s.config_bundle(collected))
    assert flags["kube-apiserver"]["anonymous-auth"] == "false"
    assert flags["kube-apiserver"]["audit-log-path"] == "/audit"
    assert flags["kube-controller-manager"]["profiling"] == "true"
    assert flags["kubelet"]["read-only-port"] == "10255"
    assert "SECRET" not in json.dumps(flags)
    (drops / "30-invalid.yaml").mkdir()
    failed = subprocess.run([str(bash), "-c", script], capture_output=True)
    assert failed.returncode != 0
    with pytest.raises(ValueError):
        k3s.config_bundle(failed.stdout.decode().replace(path, "/etc/rancher/k3s"))


@pytest.fixture
def range_target(state_dir, monkeypatch):
    monkeypatch.setenv("CT_STATE_DIR", str(state_dir))
    target = Target(id="range-cluster", name="range", asset_type="kubernetes", transport="kubeconfig",
                    options={"kubeconfig": "unused", "k3d_cluster": "range"})
    Inventory(targets=[target]).save(state_dir / "targets.yaml")
    return target


def data_for(tmp_path, names=("k3d-range-server-0",)):
    col = Collected("range-cluster", "kubernetes", str(tmp_path))
    col.raw.update(version={"serverVersion": {"gitVersion": "v1.30.6+k3s1"}}, nodes={"items": [
        {"metadata": {"name": name, "labels": {"node-role.kubernetes.io/control-plane": "true"}}} for name in names]},
        pods={"items": []})
    return col, checks.KubeData(col)


def docker_stub(monkeypatch, *, labels=None, cmdline=None, config=None, fail_at=None):
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        assert argv[:3] == ["docker", "--context", "default"]
        assert not kwargs.get("shell")
        assert not any(k.startswith("DOCKER_") for k in kwargs["env"])
        if fail_at and len(calls) == fail_at:
            return SimpleNamespace(returncode=1, stdout="", stderr="SECRET")
        args = argv[3:]
        if args[0] == "inspect":
            out = json.dumps([{"Name": "/" + args[-1], "Id": "a" * 64, "State": {"Running": True},
                               "Config": {"Labels": labels or {"k3d.cluster": "range", "k3d.role": "server"},
                                          "Env": ["K3S_TOKEN=SECRET"]}}])
        elif args[-1] == "/proc/1/cmdline":
            out = cmdline or "k3s\0server\0--token\0SECRET\0"
        elif args[-1] == "/proc/1/environ":
            out = "K3S_TOKEN=SECRET\0"
        else:
            assert args == ["exec", "a" * 64, "sh", "-c", k3s.READ_CONFIG]
            out = config if config is not None else bundle()
        return SimpleNamespace(returncode=0, stdout=out, stderr="")
    monkeypatch.setattr(k3d.subprocess, "run", run)
    return calls


def test_k3d_collects_all_servers_with_explicit_pass_fail(range_target, tmp_path, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://unrelated:2375")
    calls = docker_stub(monkeypatch)
    col, data = data_for(tmp_path, ("k3d-range-server-0", "k3d-range-server-1"))
    col.raw[checks.K3S_FLAGS] = {"servers": k3d.collect(range_target, data)}
    found = checks.check_apiserver(range_target, checks.KubeData(col))
    assert len(found) == 12
    assert {f.status for f in found} == {"open", "not_a_finding"}
    assert "SECRET" not in json.dumps(col.to_dict())
    assert len(calls) >= 6
    assert all("runtime activation is not verified" in f.evidence for f in found)


@pytest.mark.parametrize("cluster", ["--help", "range;id", "$(id)", "../range", ["range"], "", "a" * 41])
def test_k3d_options_cannot_select_arbitrary_container_or_inject(cluster, range_target, tmp_path, monkeypatch):
    calls = docker_stub(monkeypatch)
    range_target.options["k3d_cluster"] = cluster
    with pytest.raises(ValueError):
        k3d.collect(range_target, data_for(tmp_path)[1])
    assert calls == []


@pytest.mark.parametrize("names", [("unrelated",), ("k3d-other-server-0",), (), ("k3d-range-server-0",) * 2])
def test_k3d_api_node_mismatch_refuses_docker(names, range_target, tmp_path, monkeypatch):
    calls = docker_stub(monkeypatch)
    with pytest.raises(ValueError):
        k3d.collect(range_target, data_for(tmp_path, names)[1])
    assert calls == []


def test_k3d_wrong_docker_labels_never_exec(range_target, tmp_path, monkeypatch):
    calls = docker_stub(monkeypatch, labels={"k3d.cluster": "other", "k3d.role": "server"})
    with pytest.raises(ValueError):
        k3d.collect(range_target, data_for(tmp_path)[1])
    assert len(calls) == 1


@pytest.mark.parametrize("failure", ["kill", "scope", "changed"])
def test_k3d_scope_and_kill_checked_before_docker(failure, range_target, state_dir, tmp_path, monkeypatch):
    calls = docker_stub(monkeypatch)
    if failure == "kill":
        monkeypatch.setenv("CT_KILL", "1")
    else:
        inv = Inventory.load(state_dir / "targets.yaml")
        inv.update(range_target.id, **({"in_scope": False} if failure == "scope" else {"address": "other"}))
        inv.save()
    with pytest.raises((RuntimeError, PermissionError, ValueError)):
        k3d.collect(range_target, data_for(tmp_path)[1])
    assert not calls


def test_failure_cannot_leave_partial_server_defaults(range_target, tmp_path, monkeypatch):
    docker_stub(monkeypatch, fail_at=3)
    col, data = data_for(tmp_path)
    with pytest.raises(ValueError) as exc:
        k3d.collect(range_target, data)
    assert "SECRET" not in str(exc.value)
    assert {f.status for f in checks.check_apiserver(range_target, data)} == {"not_reviewed"}


def test_adapter_records_collection_failure_without_passes(range_target, tmp_path, monkeypatch):
    from cyberthunder.transport.base import CommandResult
    class Unavailable:
        def run(self, command):
            return CommandResult(command, 1)
    col = KubernetesAdapter().collect(range_target, Unavailable(), tmp_path)
    assert any("k3d" in error for error in col.errors)
    found = checks.check_apiserver(range_target, checks.KubeData(col))
    assert len(found) == 6 and all(f.status == "not_reviewed" for f in found)


@pytest.mark.parametrize("args", ["--disable-apiserver", "--disable-agent=true", "--disable-controller-manager",
                                  "--kube-apiserver-arg=anonymous-auth=garbage", "--kubelet-arg=read-only-port=bad"])
def test_unsupported_or_malformed_component_state_never_passes(args):
    with pytest.raises(ValueError):
        k3s.effective_flags("", "k3s server " + args)


def test_mid_collection_scope_change_stops_next_docker_command(range_target, state_dir, tmp_path, monkeypatch):
    calls = docker_stub(monkeypatch)
    original = k3d.subprocess.run
    def revoke(argv, **kwargs):
        result = original(argv, **kwargs)
        inv = Inventory.load(state_dir / "targets.yaml")
        inv.update(range_target.id, in_scope=False)
        inv.save()
        return result
    monkeypatch.setattr(k3d.subprocess, "run", revoke)
    with pytest.raises(PermissionError):
        k3d.collect(range_target, data_for(tmp_path)[1])
    assert len(calls) == 1


def test_paginated_nodes_cannot_establish_all_server_coverage(range_target, tmp_path, monkeypatch):
    calls = docker_stub(monkeypatch)
    col, data = data_for(tmp_path)
    col.raw["nodes"]["metadata"] = {"continue": "next-page"}
    with pytest.raises(ValueError):
        k3d.collect(range_target, data)
    assert not calls


@pytest.mark.parametrize("flags", [
    {"node": "k3d-range-server-0", "kube-apiserver": {}},
    {"node": "k3d-range-server-0", "complete": True, "kube-apiserver": {}},
    {"servers": "malformed"},
])
def test_partial_or_old_flag_records_cannot_be_passes(flags, tmp_path):
    col, _ = data_for(tmp_path)
    col.raw[checks.K3S_FLAGS] = flags
    target = Target(id="cluster", name="cluster", asset_type="kubernetes")
    results = checks.check_apiserver(target, checks.KubeData(col))
    assert len(results) == 6 and all(f.status == "not_reviewed" for f in results)
