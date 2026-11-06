"""Secondary-node collection cannot leave the initiating account's authorization path."""
import json
import sys
from types import ModuleType, SimpleNamespace

import pytest

from cyberthunder.adapters.base import Collected
from cyberthunder.adapters.kubernetes import KubernetesAdapter, checks, k3s
from cyberthunder.config import Settings
from cyberthunder.inventory.targets import Inventory, Target
from cyberthunder.transport.base import CommandResult


@pytest.fixture
def identity(monkeypatch):
    # Keep these tests independent of the parent's principal implementation.
    module = ModuleType("cyberthunder.control.principal")
    state = SimpleNamespace(principal=SimpleNamespace(verified=True))
    module.current_principal = lambda: state.principal
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return state


@pytest.fixture
def no_legacy_io(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("verified secondary collection reached legacy settings or transport I/O")
    monkeypatch.setattr(Settings, "from_env", forbidden)
    monkeypatch.setattr(Inventory, "load", forbidden)
    monkeypatch.setattr("cyberthunder.transport.base.make_transport", forbidden)


def objects(tmp_path, *, sudo=False):
    cluster = Target("cluster", "Cluster", "kubernetes", transport="kubeconfig", sudo=False,
                     options={"node_target": "node-a", "node_name": "k3s-node"})
    node = Target("node-a", "Node", "linux", transport="ssh", sudo=sudo)
    col = Collected("cluster", "kubernetes", str(tmp_path))
    return cluster, node, col, checks.KubeData(col)


class NodeTransport:
    def __init__(self, *, failure=None):
        self.failure = failure
        self.commands = []
        self.closed = 0

    def run(self, command, *, sudo=False, **kwargs):
        self.commands.append((command, sudo))
        if self.failure is not None:
            raise self.failure
        if command == k3s.READ_CONFIG:
            text = 'kube-apiserver-arg:\n  - anonymous-auth=false\ntoken: test-only-join-token\n'
            if hasattr(k3s, "config_bundle"):
                text = "\0".join(["CT_K3S_CONFIG_V1", k3s.CONFIG_PATH, text, "CT_END", ""])
        elif command == k3s.READ_EXECSTART:
            text = '/usr/local/bin/k3s server --token test-only-join-token'
        else:
            text = ""
        return CommandResult(command, 0, text)

    def close(self):
        self.closed += 1


@pytest.mark.parametrize("via_collect", [False, True])
def test_verified_missing_factory_fails_before_legacy_settings_or_io(tmp_path, identity, no_legacy_io, via_collect):
    adapter = KubernetesAdapter()
    cluster, _, col, data = objects(tmp_path)
    with pytest.raises(PermissionError, match="guarded secondary"):
        if via_collect:
            adapter._collect_k3s_node(cluster, "node-a", data, col)
        else:
            adapter.node_transport("node-a")
    assert not col.raw and not col.errors


def test_noncallable_factory_never_uses_legacy_fallback(identity, no_legacy_io):
    with pytest.raises(PermissionError):
        KubernetesAdapter().node_transport("node-a", factory=object())


def test_supplied_factory_receives_exact_node_id_without_settings_reload(tmp_path, identity, no_legacy_io):
    _, node, _, _ = objects(tmp_path)
    transport = NodeTransport()
    calls = []

    def factory(node_id):
        calls.append(node_id)
        return node, transport

    assert KubernetesAdapter().node_transport("node-a", factory) == (node, transport)
    assert calls == ["node-a"] and transport.commands == []


def test_collect_forwards_the_factory_attached_to_the_cluster_transport(tmp_path, identity, no_legacy_io):
    cluster, node, _, _ = objects(tmp_path)
    secondary = NodeTransport()
    calls = []

    class ClusterTransport:
        def secondary_transport(self, node_id):
            calls.append(node_id)
            return node, secondary

        def run(self, command):
            return CommandResult(command, 0, json.dumps({"items": []}))

    col = KubernetesAdapter().collect(cluster, ClusterTransport(), tmp_path / "collected")
    assert calls == ["node-a"] and secondary.closed == 1
    assert secondary.commands[0] == (k3s.READ_CONFIG, False)
    assert col.raw[checks.K3S_FLAGS]["node_target"] == "node-a"
    assert "test-only-join-token" not in json.dumps(col.to_dict())


def test_factory_permission_denial_propagates_without_a_partial_result(tmp_path, identity, no_legacy_io):
    cluster, _, col, data = objects(tmp_path)

    def denied(node_id):
        raise PermissionError("secondary target is not authorized")

    with pytest.raises(PermissionError, match="not authorized"):
        KubernetesAdapter()._collect_k3s_node(cluster, "node-a", data, col, factory=denied)
    assert not col.raw and not col.errors


@pytest.mark.parametrize("failure", [PermissionError("revoked"), RuntimeError("connection failed")])
def test_io_failure_closes_secondary_and_propagates(tmp_path, identity, no_legacy_io, failure):
    cluster, node, col, data = objects(tmp_path)
    transport = NodeTransport(failure=failure)
    with pytest.raises(type(failure)):
        KubernetesAdapter()._collect_k3s_node(cluster, "node-a", data, col, factory=lambda _: (node, transport))
    assert transport.closed == 1 and checks.K3S_FLAGS not in col.raw


@pytest.mark.parametrize("change", [{"id": "node-b"}, {"asset_type": "windows"}, {"in_scope": False}])
def test_wrong_or_out_of_scope_factory_target_is_closed_before_commands(tmp_path, identity, no_legacy_io, change):
    cluster, node, col, data = objects(tmp_path)
    for key, value in change.items():
        setattr(node, key, value)
    transport = NodeTransport()
    with pytest.raises(PermissionError):
        KubernetesAdapter()._collect_k3s_node(cluster, "node-a", data, col, factory=lambda _: (node, transport))
    assert transport.closed == 1 and not transport.commands and not col.raw


@pytest.mark.parametrize("outcome", ["success", "read_exit", "parse_failure", "permission_during_parse"])
def test_secondary_closed_after_reader_return_or_exception(tmp_path, identity, no_legacy_io, monkeypatch, outcome):
    adapter = KubernetesAdapter()
    cluster, node, col, data = objects(tmp_path)
    transport = NodeTransport()

    def reader(*args):
        if outcome == "permission_during_parse":
            raise PermissionError("revoked during collection")
        if outcome in {"read_exit", "parse_failure"}:
            col.errors.append("node collection incomplete")

    monkeypatch.setattr(adapter, "_read_k3s_node", reader)
    if outcome == "permission_during_parse":
        with pytest.raises(PermissionError):
            adapter._collect_k3s_node(cluster, "node-a", data, col, factory=lambda _: (node, transport))
    else:
        adapter._collect_k3s_node(cluster, "node-a", data, col, factory=lambda _: (node, transport))
    assert transport.closed == 1


@pytest.mark.parametrize("principal", [None, SimpleNamespace(verified=False)])
def test_legacy_development_still_uses_settings_inventory_and_default_factory(tmp_path, identity, monkeypatch, principal):
    identity.principal = principal
    _, node, _, _ = objects(tmp_path)
    transport = NodeTransport()
    calls = []
    settings = SimpleNamespace(state_dir=tmp_path)
    monkeypatch.setattr(Settings, "from_env", lambda: settings)

    def load(path):
        calls.append(("inventory", path))
        return Inventory(targets=[node])

    def make(selected, supplied_settings):
        calls.append(("transport", selected.id, supplied_settings is settings))
        return transport

    monkeypatch.setattr(Inventory, "load", load)
    monkeypatch.setattr("cyberthunder.transport.base.make_transport", make)
    assert KubernetesAdapter().node_transport("node-a") == (node, transport)
    assert calls[-1] == ("transport", "node-a", True)


def test_permission_denied_on_second_command_never_retains_flags(tmp_path, identity, no_legacy_io):
    cluster, node, col, data = objects(tmp_path)
    transport = NodeTransport()
    run = transport.run

    def revoke(command, **kwargs):
        if transport.commands:
            raise PermissionError("access revoked after configuration read")
        return run(command, **kwargs)

    transport.run = revoke
    with pytest.raises(PermissionError):
        KubernetesAdapter()._collect_k3s_node(cluster, "node-a", data, col, factory=lambda _: (node, transport))
    assert transport.closed == 1 and checks.K3S_FLAGS not in col.raw


def test_close_failure_cannot_replace_an_authorization_denial(tmp_path, identity, no_legacy_io):
    cluster, node, col, data = objects(tmp_path)
    transport = NodeTransport(failure=PermissionError("authorization revoked"))

    def close():
        transport.closed += 1
        raise RuntimeError("cleanup failure")

    transport.close = close
    with pytest.raises(PermissionError, match="authorization revoked"):
        KubernetesAdapter()._collect_k3s_node(cluster, "node-a", data, col, factory=lambda _: (node, transport))
    assert transport.closed == 1 and not col.raw
