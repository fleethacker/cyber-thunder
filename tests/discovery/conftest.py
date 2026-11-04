"""Discovery test fixtures: an AppContext on a temp state dir and copies of the recorded tool outputs."""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import pytest

# Nothing in these tests may touch a real state directory, even at import time.
os.environ["CT_STATE_DIR"] = tempfile.mkdtemp(prefix="ct-discovery-")

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "discovery"


@pytest.fixture
def fix() -> Path:
    return FIX


@pytest.fixture
def ctx(state_dir, monkeypatch):
    monkeypatch.setenv("CT_STATE_DIR", str(state_dir))
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext
    return AppContext(Settings.from_env(state_dir=str(state_dir)))


@pytest.fixture
def fixture_copy(tmp_path):
    """Copy a fixture directory (FixtureTransport writes missing.log next to commands.json)."""
    def make(name: str) -> Path:
        dest = tmp_path / "fx"
        if not dest.exists():
            shutil.copytree(FIX, dest)
        return dest / name
    return make


def add_targets(ctx, *targets):
    for t in targets:
        ctx.inventory.add(t)
    ctx.save_inventory("tester")
