"""Container host adapter: detection on the seeded simulated docker host, stop-and-disable with exact
rollback, runbook output, fixture replay with a Trivy report, podman fallback."""
import json
from datetime import datetime
from pathlib import Path

import pytest

from cyberthunder.adapters.containers import ContainersAdapter
from cyberthunder.adapters.containers import hunt as c_hunt
from cyberthunder.adapters.containers.checks import NAME_TAG
from cyberthunder.adapters.containers.images import (image_registry, image_repository, registry_allowed,
                                                     uses_latest_or_untagged)
from cyberthunder.adapters.containers.simulated import cid
from cyberthunder.adapters.containers.trivy_min import parse_trivy
from cyberthunder.config import Settings
from cyberthunder.inventory.targets import Target
from cyberthunder.remediation.library import FixLibrary
from cyberthunder.transport.base import CommandResult, Transport, make_transport

ROOT = Path(__file__).resolve().parents[2]
ANSWER_KEY = json.loads((ROOT / "range" / "answer_key" / "containers.json").read_text(encoding="utf-8"))
ITEMS = {i["id"]: i for i in ANSWER_KEY["items"]}
CITABLE = {"stig_id", "group", "cci", "attack", "cve", "iavm"}


@pytest.fixture
def adapter():
    return ContainersAdapter()


@pytest.fixture
def settings(state_dir):
    return Settings.from_env(state_dir=state_dir)


@pytest.fixture
def target(adapter):
    return adapter.demo_targets()[0]


@pytest.fixture
def transport(adapter, target, settings):
    adapter.reset_simulated(target, settings)
    return adapter.make_transport(target, settings)


def detect(adapter, target, transport, tmp_path, sub="scan"):
    col = adapter.collect(target, transport, tmp_path / sub)
    assert not col.errors, col.errors
    return adapter.run_detection(target, col)


def find_item(findings, item):
    for f in findings:
        if f.rule_version == item["rule"] and NAME_TAG + item["container"] in f.tags:
            return f
    return None


def inspect(transport, name):
    return json.loads(transport.run(f"docker inspect {cid(name)}").stdout)[0]


def test_every_answer_key_item_is_found(adapter, target, transport, tmp_path):
    findings = detect(adapter, target, transport, tmp_path)
    missing = [i["id"] for i in ANSWER_KEY["items"] if find_item(findings, i) is None]
    assert not missing
    assert len(ANSWER_KEY["items"]) == 6


def test_every_finding_cites(adapter, target, transport, tmp_path):
    for f in detect(adapter, target, transport, tmp_path):
        ids = [r.id for r in f.references]
        assert any(r.system in CITABLE for r in f.references) or any(i.startswith("CIS-Docker-") for i in ids), f.rule_id
        if f.source == "hunt":
            assert f.ref_ids("attack")


def test_fix_library_resolves(adapter, target, transport, tmp_path):
    findings = detect(adapter, target, transport, tmp_path)
    lib = FixLibrary(adapter.fixes())
    for item in ANSWER_KEY["items"]:
        fix = lib.resolve(find_item(findings, item))
        assert fix is not None and fix.fix_ref == item["fix_ref"], item["id"]


@pytest.mark.parametrize("item_id", ["I1", "I2"])
def test_stop_and_disable_then_rollback(adapter, target, transport, tmp_path, item_id):
    item = ITEMS[item_id]
    finding = find_item(detect(adapter, target, transport, tmp_path, "before"), item)
    fix = FixLibrary(adapter.fixes()).resolve(finding)
    orig = inspect(transport, item["container"])

    before = adapter.capture_before_state(target, transport, fix, finding, tmp_path / "snap")
    assert before.extra["running"] is True
    res = adapter.apply(target, transport, fix, finding, before)
    assert res.ok, res.output
    now = inspect(transport, item["container"])
    assert now["State"]["Running"] is False and now["HostConfig"]["RestartPolicy"]["Name"] == "no"

    v = adapter.verify(target, transport, fix, finding)
    assert v.ok and v.rule_passed, v.evidence

    rb = adapter.rollback(target, transport, fix, before)
    assert rb.ok, rb.output
    back = inspect(transport, item["container"])
    for key in ("HostConfig", "Config", "Mounts", "Name", "Image", "Path", "Args"):
        assert back[key] == orig[key], key
    assert back["State"]["Running"] is True and back["State"]["Status"] == orig["State"]["Status"]
    assert find_item(detect(adapter, target, transport, tmp_path, "after"), item) is not None


def test_runbook_prints_corrected_command_and_changes_nothing(adapter, target, transport, settings, tmp_path):
    item = ITEMS["M1"]
    finding = find_item(detect(adapter, target, transport, tmp_path), item)
    fix = FixLibrary(adapter.fixes()).resolve(finding)
    state = adapter.simulated_state_path(target, settings).read_text(encoding="utf-8")
    before = adapter.capture_before_state(target, transport, fix, finding, tmp_path / "snap")
    res = adapter.apply(target, transport, fix, finding, before)
    assert not res.ok and not res.changed
    run = res.details["corrected_run"]
    assert run.startswith("docker run -d --name ops-agent") and "--privileged" not in run
    assert "registry.local/ops/agent:3.2" in run
    assert "ops-agent" in res.output and "<name>" not in res.output
    assert adapter.simulated_state_path(target, settings).read_text(encoding="utf-8") == state


def test_socket_runbook_drops_only_the_socket(adapter, target, transport, tmp_path):
    from cyberthunder.adapters.containers.fixes import corrected_run
    d = inspect(transport, "ops-dashboard")
    run = corrected_run(d, "engine-socket")
    assert "docker.sock" not in run and "--read-only" in run and "--memory 268435456" in run


def test_apply_refuses_finding_without_container_ref(adapter, target, transport):
    from cyberthunder.adapters.base import make_finding
    f = make_finding(target=target, source="hunt", rule_id="containers:hunt:miner:x", title="x", severity="high",
                     references=["T1496"], rule_version="containers:hunt:miner", tags=["container:x; rm -rf /"])
    fix = FixLibrary(adapter.fixes()).get("containers:fix:stop-and-disable")
    assert not adapter.apply(target, transport, fix, f, None).ok


def test_fixture_replay_with_trivy(adapter, fixtures_dir, tmp_path):
    root = fixtures_dir / "containers" / "sim_session"
    opts = dict(adapter.demo_targets()[0].options, fixture_dir=str(root))
    t = Target(id="sim-docker-01", name="replay", asset_type="containers", transport="fixture", sudo=False, options=opts)
    tr = make_transport(t)
    col = adapter.collect(t, tr, tmp_path)
    assert not col.errors, col.errors
    findings = adapter.check(t, col) + adapter.cve(t, col)
    recorded = datetime.fromisoformat((root / "recorded_at.txt").read_text(encoding="utf-8").strip())
    findings += c_hunt.run_hunt(t, col, now=recorded)
    missing = [i["id"] for i in ANSWER_KEY["items"] if find_item(findings, i) is None]
    assert not missing
    cves = [f for f in findings if f.source == "trivy"]
    assert any("CVE-2024-6387" in f.citations for f in cves)
    assert all(f.ref_ids("cve") for f in cves)


def test_trivy_min_parser(target, fixtures_dir):
    fs = parse_trivy(fixtures_dir / "containers" / "sim_session" / "trivy_image.json", target)
    assert {f.rule_version for f in fs} == {"CVE-2024-6387", "CVE-2023-44487"}
    assert all(f.severity.value == "high" and "fixed in" in f.evidence for f in fs)


class _PodmanOnly(Transport):
    kind = "fake"

    def __init__(self):
        self.calls = []

    def run(self, command, *, timeout=120, sudo=False):
        self.calls.append(command)
        if command.startswith("podman version"):
            return CommandResult(command, 0, '{\n  "Client": {"Version": "4.9.4"}\n}\n')
        if command.startswith("podman info"):
            return CommandResult(command, 0, '{"ServerVersion": "4.9.4"}')
        if command.startswith("podman ps"):
            return CommandResult(command, 0, "")
        if command.startswith("podman images"):
            return CommandResult(command, 0, "")
        return CommandResult(command, 127, "", "not found")

    def read_file(self, path):
        raise NotImplementedError

    def write_file(self, path, data, *, mode=None, sudo=False):
        raise NotImplementedError


def test_podman_fallback(adapter, tmp_path):
    t = Target(id="pod-01", name="pod-01", asset_type="containers", transport="local", sudo=False)
    tr = _PodmanOnly()
    col = adapter.collect(t, tr, tmp_path)
    assert col.raw["engine"] == "podman" and not col.errors
    assert any(c.startswith("podman ps -a") for c in tr.calls)


def test_image_helpers():
    assert image_repository("nginx:1.25") == "docker.io/library/nginx"
    assert image_repository("xmrig/xmrig:6.21.0") == "docker.io/xmrig/xmrig"
    assert image_registry("203.0.113.50:5000/cache-sync:0.3") == "203.0.113.50:5000"
    assert registry_allowed("registry.local/ops/agent:3.2", ["registry.local"])
    assert not registry_allowed("docker.io/xmrig/xmrig:6.21.0", ["registry.local", "docker.io/library"])
    assert uses_latest_or_untagged("ghcr.io/x/y") and uses_latest_or_untagged("a/b:latest")
    assert not uses_latest_or_untagged("localhost:5000/a@sha256:" + "0" * 64)


def test_health_and_unknown_command(adapter, target, transport):
    assert adapter.health_check(target, transport).ok
    assert transport.run("docker rm -f web").exit_code == 127
