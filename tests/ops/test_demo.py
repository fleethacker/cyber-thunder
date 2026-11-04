"""Demo loader with a tiny fake adapter (the real adapters are built elsewhere)."""
import json

import pytest

from cyberthunder import demo
from cyberthunder.adapters import registry
from cyberthunder.adapters.base import Adapter, AssetFacts, Collected
from cyberthunder.audit.chain import verify_file
from cyberthunder.cli import main
from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.inventory.targets import Target


class FakeAdapter(Adapter):
    asset_type = "linux"
    resets: list = []

    def discover(self, target, transport): return AssetFacts(hostname=target.name)
    def collect(self, target, transport, workdir, *, modules=(), rule_filter=None):
        return Collected(target_id=target.id, asset_type=self.asset_type, workdir=str(workdir))
    def check(self, target, collected): return []
    def capture_before_state(self, target, transport, fix, finding, dest): raise NotImplementedError
    def apply(self, target, transport, fix, finding, before): raise NotImplementedError
    def verify(self, target, transport, fix, finding): raise NotImplementedError
    def health_check(self, target, transport): raise NotImplementedError
    def rollback(self, target, transport, fix, before): raise NotImplementedError

    def demo_targets(self):
        return [Target(id="demo-linux", name="Demo Linux", asset_type="linux", transport="simulated",
                       simulated=True, tags=["demo"])]

    def reset_simulated(self, target, settings=None):
        FakeAdapter.resets.append(target.id)
        return True


@pytest.fixture
def ctx(state_dir):
    FakeAdapter.resets = []
    saved = dict(registry._adapters)
    registry._adapters.clear()
    registry.register(FakeAdapter)
    try:
        yield AppContext(Settings.from_env(state_dir=state_dir))
    finally:
        registry._adapters.clear()
        registry._adapters.update(saved)


def test_status_before_and_after_load(ctx):
    st = demo.status(ctx)
    assert st == {"available": True, "loaded": False, "targets": ["demo-linux"], "simulate_verify_fail_next": False}
    targets = demo.load(ctx, "sailor1")
    assert [t.id for t in targets] == ["demo-linux"]
    assert demo.status(ctx)["loaded"] is True
    # load is idempotent and persisted
    demo.load(ctx, "sailor1")
    assert len(ctx.inventory.all()) == 1
    fresh = AppContext(Settings.from_env(state_dir=ctx.settings.state_dir))
    assert fresh.inventory.get("demo-linux").simulated


def test_load_and_reset_are_audited(ctx):
    demo.load(ctx, "sailor1")
    assert demo.reset(ctx, "sailor1") == {"reset": {"demo-linux": True}}
    assert FakeAdapter.resets == ["demo-linux"]
    actions = [r["action"] for r in ctx.audit.records()]
    assert "demo.load" in actions and "demo.reset" in actions
    assert verify_file(ctx.store.audit_log).ok


def test_verify_fail_flag_round_trips(ctx):
    assert demo.consume_simulate_verify_fail(ctx) is False
    demo.set_simulate_verify_fail_next(ctx, True, "sailor1")
    assert demo.status(ctx)["simulate_verify_fail_next"] is True
    on_disk = json.loads((ctx.store.root / "demo.json").read_text(encoding="utf-8"))
    assert on_disk["simulate_verify_fail_next"] is True
    assert demo.consume_simulate_verify_fail(ctx) is True     # read and clear
    assert demo.consume_simulate_verify_fail(ctx) is False
    assert demo.status(ctx)["simulate_verify_fail_next"] is False
    assert [r for r in ctx.audit.records() if r["action"] == "demo.simulate_verify_fail"]
    assert verify_file(ctx.store.audit_log).ok


def test_no_adapters_means_unavailable(state_dir):
    saved = dict(registry._adapters)
    registry._adapters.clear()
    try:
        c = AppContext(Settings.from_env(state_dir=state_dir))
        assert demo.status(c)["available"] is False and demo.load(c, "x") == []
    finally:
        registry._adapters.update(saved)


def test_cli_load_status_reset_run(ctx, state_dir, capsys):
    base = ["--state-dir", str(state_dir), "--actor", "sailor1", "demo"]
    assert main([*base, "load"]) == 0
    assert "demo-linux" in capsys.readouterr().out
    assert main([*base, "status"]) == 0
    assert json.loads(capsys.readouterr().out)["loaded"] is True
    assert main([*base, "reset"]) == 0
    assert json.loads(capsys.readouterr().out)["reset"] == {"demo-linux": True}
    rc = main([*base, "run"])
    captured = capsys.readouterr()
    # the scanner may still be a stub in this checkout: that must produce a clear message, not a traceback
    if rc != 0:
        assert "scanner is not built" in captured.err
