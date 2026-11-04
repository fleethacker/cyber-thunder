"""Fixtures for the Linux adapter tests. Everything runs against the simulated host or static fixtures;
no network, no live host. State goes under the per-test state_dir (see the top-level conftest)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberthunder.adapters.linux import LinuxAdapter
from cyberthunder.config import Settings

ROOT = Path(__file__).resolve().parent.parent.parent
ANSWER_KEY = ROOT / "range" / "answer_key" / "linux.json"
FIXTURES = ROOT / "tests" / "fixtures" / "linux"


@pytest.fixture
def adapter() -> LinuxAdapter:
    return LinuxAdapter()


@pytest.fixture
def settings(state_dir) -> Settings:
    return Settings.from_env(state_dir=str(state_dir))


@pytest.fixture
def sim_target(adapter):
    return adapter.demo_targets()[0]


@pytest.fixture
def sim_transport(adapter, sim_target, settings):
    t = adapter.make_transport(sim_target, settings)
    yield t
    t.close()


@pytest.fixture
def answer_key() -> dict:
    return json.loads(ANSWER_KEY.read_text(encoding="utf-8"))


@pytest.fixture
def fixtures_linux() -> Path:
    return FIXTURES


def collect_and_detect(adapter, target, transport, tmp_path):
    """Full read-only pass: collect, then check + hunt + cve. Returns (collected, findings)."""
    collected = adapter.collect(target, transport, tmp_path / "collect")
    findings = adapter.check(target, collected) + adapter.hunt(target, collected) + adapter.cve(target, collected)
    return collected, findings
