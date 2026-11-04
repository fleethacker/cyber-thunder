"""Engine test fixtures: a fake Linux adapter registered only for the duration of a test, a fake host,
and an AppContext over a temp state dir with an inventory built in the test."""
from __future__ import annotations

import pytest

from cyberthunder.adapters import load_all, registry
from cyberthunder.config import Settings
from cyberthunder.inventory.targets import Target

from . import fakes

HOST = "rhel-01"
OUT_OF_SCOPE = "rhel-oos"
NO_ADAPTER = "core-sw-01"


@pytest.fixture
def fake_adapter(monkeypatch):
    load_all()                       # import real adapters first so they cannot re-register over the fake
    saved = dict(registry._adapters)
    adapter = fakes.FakeLinuxAdapter()
    registry.register(adapter)
    registry._adapters.pop("cisco_ios", None)      # a type with no adapter loaded, for the skip path
    fakes.reset_hosts(HOST, OUT_OF_SCOPE)
    yield adapter
    registry._adapters.clear()
    registry._adapters.update(saved)
    fakes.HOSTS.clear()


@pytest.fixture
def make_ctx(state_dir, fake_adapter, monkeypatch):
    monkeypatch.setenv("CT_STATE_DIR", str(state_dir))
    monkeypatch.setenv("CT_LLM_BACKEND", "template")
    made = []

    def _make(**overrides):
        from cyberthunder.context import AppContext
        opts = {"state_dir": state_dir, "explain_precompute": False, "llm_backend": "template", "node": "test-node"}
        opts.update(overrides)
        ctx = AppContext(Settings.from_env(**opts))
        if not ctx.inventory.all():
            # the fake host stands in for a real one (simulated=False) so scanner-content fixes are offered for it
            ctx.inventory.add(Target(id=HOST, name="RHEL 9 web", asset_type="linux", transport="simulated",
                                     simulated=False))
            ctx.inventory.add(Target(id=OUT_OF_SCOPE, name="RHEL 9 not ours", asset_type="linux",
                                     transport="simulated", simulated=True, in_scope=False))
            ctx.inventory.add(Target(id=NO_ADAPTER, name="Core switch", asset_type="cisco_ios",
                                     transport="simulated", simulated=True))
            ctx.inventory.save()
        made.append(ctx)
        return ctx

    yield _make
    for ctx in made:
        v = ctx.audit.verify()
        assert v.ok, f"audit chain broken: {v}"


@pytest.fixture
def ctx(make_ctx):
    return make_ctx()
