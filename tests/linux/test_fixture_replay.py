"""Collect + detect against a recorded FixtureTransport, so detection is exercised against static
command output and not only the live simulated host. The fixture under tests/fixtures/linux/sim_recorded
is produced by tools/record_sim_fixture.py from the simulated host.
"""
from __future__ import annotations

from cyberthunder.transport.fixture import FixtureTransport

from .conftest import collect_and_detect
from .test_detect import _open_ids


def test_replay_detects_answer_key(adapter, sim_target, answer_key, fixtures_linux, tmp_path):
    transport = FixtureTransport(fixtures_linux / "sim_recorded")
    collected = adapter.collect(sim_target, transport, tmp_path / "collect")
    findings = adapter.check(sim_target, collected) + adapter.hunt(sim_target, collected)
    found = _open_ids(findings)
    missing = [item["id"] for item in answer_key["items"] if item["check_id"] not in found]
    assert not missing, f"undetected over fixture replay: {missing}"


def test_replay_reports_missing_scap_without_native_collection_errors(adapter, sim_target, fixtures_linux, tmp_path):
    transport = FixtureTransport(fixtures_linux / "sim_recorded")
    collected = adapter.collect(sim_target, transport, tmp_path / "collect")
    # This recording has no scanner or dpkg; native collection must still succeed.
    missing_scap = "oscap: scanner not found on the host; SCAP coverage is unavailable"
    assert missing_scap in collected.errors
    assert collected.raw["scanner_coverage"]["status"] == "unavailable"
    real = [e for e in collected.errors if "dpkg" not in e and e != missing_scap]
    assert not real, real


def test_replay_matches_live_simhost(adapter, sim_target, sim_transport, fixtures_linux, tmp_path):
    live = {f.id for f in collect_and_detect(adapter, sim_target, sim_transport, tmp_path / "live")[1]
            if f.is_open}
    transport = FixtureTransport(fixtures_linux / "sim_recorded")
    collected = adapter.collect(sim_target, transport, tmp_path / "fix")
    replay = {f.id for f in adapter.check(sim_target, collected) + adapter.hunt(sim_target, collected)
              if f.is_open}
    assert replay == live
