import json
import shutil

import pytest

from cyberthunder.adapters import registry
from cyberthunder.adapters.cisco import CiscoIOSAdapter, validate_payload
from cyberthunder.adapters.cisco.parser import parse_config
from cyberthunder.adapters.cisco.transports import ConfigFileTransport, SimulatedTransport
from cyberthunder.config import Settings
from cyberthunder.findings.schema import Status
from cyberthunder.inventory.targets import Target
from cyberthunder.remediation.library import FixLibrary
from cyberthunder.transport.base import make_transport
from cyberthunder.transport.fixture import FixtureTransport

from .helpers import (ANSWER_KEY, CLEAN_SWITCH, FIXTURES, ROUTER_OPTS, SEEDED_ROUTER, SEEDED_SWITCH, FakeIOSDevice,
                      FakeSSHTransport, read)


@pytest.fixture
def settings(state_dir, monkeypatch):
    monkeypatch.setenv("CT_STATE_DIR", str(state_dir))
    return Settings.from_env(state_dir=str(state_dir))


@pytest.fixture
def adapter():
    return CiscoIOSAdapter()


@pytest.fixture
def sim(adapter, settings):
    target = adapter.demo_targets()[0]
    return target, make_transport(target, settings)


def scan(adapter, target, transport, workdir):
    c = adapter.collect(target, transport, workdir)
    return c, adapter.run_detection(target, c)


def test_registered_and_demo_target(adapter):
    assert registry.get("cisco_ios").asset_type == "cisco_ios"
    t = adapter.demo_targets()[0]
    assert (t.id, t.name, t.transport, t.simulated) == ("sim-switch-01", "swi-01 (simulated)", "simulated", True)
    assert t.options["known_users"] == ["admin"] and t.options["known_syslog"] == ["10.1.1.5"]
    assert t.options["allow_push"] is False


def test_simulated_transport_seeds_state_dir_and_resets(adapter, sim, settings):
    target, tr = sim
    assert isinstance(tr, SimulatedTransport)
    path = settings.state_dir / "simulated" / "sim-switch-01.cfg"
    assert path.exists() and read(path) == read(SEEDED_SWITCH)
    tr.write_config("hostname changed\n")
    assert adapter.reset_simulated(target, settings) and read(path) == read(SEEDED_SWITCH)


def test_collect_check_hunt_on_simulated(adapter, sim, tmp_path):
    target, tr = sim
    c, findings = scan(adapter, target, tr, tmp_path / "w")
    assert c.facts.hostname == "swi-01" and c.facts.extra["role"] == "switch"
    assert c.path("running_config").exists()
    open_ = [f for f in findings if f.status == Status.OPEN]
    assert len([f for f in open_ if f.source == "cisco_ios"]) >= 12
    assert len([f for f in open_ if f.source == "hunt"]) >= 5
    for f in findings:
        assert f.citations and f.asset_type == "cisco_ios"
    for f in open_:
        assert f.fix_ref, f.rule_id
        if f.source == "hunt":
            assert any(r.system == "attack" for r in f.references)
        else:
            assert any(r.system == "cci" for r in f.references) and f.group_id.startswith("V-")


def test_answer_key_complete_through_adapter(adapter, sim, tmp_path):
    target, tr = sim
    _, findings = scan(adapter, target, tr, tmp_path / "w")
    key = json.loads(ANSWER_KEY.read_text(encoding="utf-8"))
    open_ = [f for f in findings if f.status == Status.OPEN]
    lib = FixLibrary(adapter.fixes())
    for item in key["items"]:
        match = [f for f in open_ if item["check_id"] in (f.rule_version, f.rule_id)]
        assert match, f"answer-key item {item['id']} ({item['what']}) not detected"
        assert match[0].fix_ref == item["fix_ref"] and lib.get(item["fix_ref"]) is not None
        assert (match[0].source == "hunt") == (item["kind"] == "intrusion")
    assert len([i for i in key["items"] if i["kind"] == "intrusion"]) >= 5


def test_router_answer_key_through_file_transport(adapter, tmp_path):
    cfg = tmp_path / "rtr.cfg"
    shutil.copyfile(SEEDED_ROUTER, cfg)
    t = Target(id="rtr-01", name="rtr", asset_type="cisco_ios", transport="file", sudo=False,
               options={**ROUTER_OPTS, "config_path": str(cfg)})
    _, findings = scan(adapter, t, adapter.make_transport(t), tmp_path / "w")
    key = json.loads(ANSWER_KEY.read_text(encoding="utf-8"))["router"]["items"]
    ids = {f.rule_version for f in findings if f.status == Status.OPEN} | {f.rule_id for f in findings}
    assert all(i["check_id"] in ids for i in key)


def test_every_fix_entry_is_valid(adapter):
    entries = adapter.fixes()
    refs = [e.fix_ref for e in entries]
    assert len(refs) == len(set(refs))
    rule_entries = [e for e in entries if e.fix_ref.startswith("cisco:rule:")]
    assert len(rule_entries) == 30
    for e in entries:
        assert e.asset_type == "cisco_ios" and e.rollback_kind in ("config_replace", "manual")
        assert e.before_state["commands"]["running_config"] == "show running-config"
        assert e.verify["rule_ids"]
        if e.kind == "config_snippet":
            validate_payload(e.payload)
            assert "allow_push" in e.notes
    demo = [e for e in entries if e.fix_ref.startswith("cisco:sim-switch-01:")]
    assert len(demo) >= 20


def _apply_verify(adapter, target, tr, finding, tmp_path):
    lib = FixLibrary(adapter.fixes())
    fix = lib.get(finding.fix_ref)
    assert fix is not None and fix.kind == "config_snippet", finding.fix_ref
    before = adapter.capture_before_state(target, tr, fix, finding, tmp_path / "snap" / finding.id)
    res = adapter.apply(target, tr, fix, finding, before)
    assert res.ok and res.changed, res.output
    v = adapter.verify(target, tr, fix, finding)
    return fix, before, res, v


VERIFY_RULES = ["CISC-ND-000720",   # line blocks
                "CISC-L2-000100",   # interface blocks
                "CISC-ND-000010", "CISC-ND-000150", "CISC-ND-000160", "CISC-ND-000210", "CISC-ND-000470",
                "CISC-ND-000550", "CISC-ND-001200", "CISC-ND-001450", "CISC-L2-000260", "CISC-ND-001140"]


@pytest.mark.parametrize("stig", VERIFY_RULES)
def test_apply_verify_rollback_per_rule(adapter, sim, tmp_path, stig):
    target, tr = sim
    original = tr.path.read_bytes()
    _, findings = scan(adapter, target, tr, tmp_path / "w")
    f = next(x for x in findings if x.rule_version == stig)
    assert f.status == Status.OPEN
    fix, before, res, v = _apply_verify(adapter, target, tr, f, tmp_path)
    assert v.ok and v.rule_passed and v.health.ok, v.evidence
    assert res.details["diff"].startswith("---")
    # applying again changes nothing
    again = adapter.apply(target, tr, fix, f, before)
    assert again.ok and not again.changed
    rb = adapter.rollback(target, tr, fix, before)
    assert rb.ok and tr.path.read_bytes() == original
    assert adapter.verify(target, tr, fix, f).rule_passed is False


@pytest.mark.parametrize("rid", ["hunt:cisco:unknown_user:netops2", "hunt:cisco:eem_applet:CFG-BACKUP",
                                 "hunt:cisco:static_route:10.10.10.0/24", "hunt:cisco:telnet_vty:vty_0_4"])
def test_hunt_remediation_and_rollback(adapter, sim, tmp_path, rid):
    target, tr = sim
    original = tr.path.read_bytes()
    _, findings = scan(adapter, target, tr, tmp_path / "w")
    f = next(x for x in findings if x.rule_id == rid)
    fix, before, res, v = _apply_verify(adapter, target, tr, f, tmp_path)
    assert v.ok, v.evidence
    assert adapter.rollback(target, tr, fix, before).ok and tr.path.read_bytes() == original


def test_rescan_after_fix_closes_finding(adapter, sim, tmp_path):
    target, tr = sim
    _, findings = scan(adapter, target, tr, tmp_path / "w")
    f = next(x for x in findings if x.rule_version == "CISC-ND-000720")
    _apply_verify(adapter, target, tr, f, tmp_path)
    c = adapter.collect(target, tr, tmp_path / "w2", rule_filter=["CISC-ND-000720"])
    again = adapter.check(target, c)
    assert len(again) == 1 and again[0].status == Status.NOT_A_FINDING and again[0].id == f.id


def test_runbook_and_refused_payloads(adapter, sim, tmp_path):
    target, tr = sim
    _, findings = scan(adapter, target, tr, tmp_path / "w")
    f = next(x for x in findings if x.rule_version == "CISC-ND-000150")
    lib = FixLibrary(adapter.fixes())
    runbook = lib.get("hunt:cisco:unknown_user")
    before = adapter.capture_before_state(target, tr, runbook, f, tmp_path / "s")
    r = adapter.apply(target, tr, runbook, f, before)
    assert not r.ok and not r.changed and r.details["steps"]
    bad = lib.get(f.fix_ref)
    from dataclasses import replace
    evil = replace(bad, payload="do reload")
    r2 = adapter.apply(target, tr, evil, f, before)
    assert not r2.ok and "refused" in r2.output
    with pytest.raises(ValueError):
        validate_payload("copy running-config tftp://10.0.0.1/x")


def test_fixture_transport(adapter, tmp_path):
    root = tmp_path / "fx"
    root.mkdir()
    shutil.copyfile(SEEDED_SWITCH, root / "running.txt")
    (root / "commands.json").write_text(json.dumps([
        {"match": "show running-config", "stdout": {"file": "running.txt"}},
        {"match": "show version", "stdout": {"file": "show_version.txt"}},
    ]), encoding="utf-8")
    shutil.copyfile(FIXTURES / "show_version.txt", root / "show_version.txt")
    t = Target(id="fx-sw", name="fx", asset_type="cisco_ios", transport="fixture", sudo=False,
               options={"fixture_dir": str(root), "known_users": ["admin"], "known_syslog": ["10.1.1.5"]})
    tr = make_transport(t)
    assert isinstance(tr, FixtureTransport)
    c, findings = scan(adapter, t, tr, tmp_path / "w")
    assert c.facts.model == "C9300-48P" and c.facts.os_version == "17.09.04a"
    f = next(x for x in findings if x.rule_id == "hunt:cisco:http_server")
    fix = FixLibrary(adapter.fixes()).get(f.fix_ref)
    before = adapter.capture_before_state(t, tr, fix, f, tmp_path / "s")
    assert adapter.apply(t, tr, fix, f, before).ok
    assert adapter.verify(t, tr, fix, f).ok
    assert adapter.rollback(t, tr, fix, before).ok
    assert parse_config(adapter.read_config(t, tr)).http_server


def test_file_transport_requires_path_and_unknown_command(adapter, tmp_path):
    t = Target(id="f", name="f", asset_type="cisco_ios", transport="file", options={})
    with pytest.raises(Exception):
        adapter.make_transport(t)
    tr = ConfigFileTransport(CLEAN_SWITCH)
    assert tr.run("show interfaces").exit_code == 127
    assert tr.run("show running-config").stdout == read(CLEAN_SWITCH)


def _live_target(**opts):
    return Target(id="lab-sw", name="lab", asset_type="cisco_ios", transport="ssh", address="192.0.2.10", sudo=False,
                  options={"known_users": ["admin"], "known_syslog": ["10.1.1.5"], **opts})


def test_live_without_push_produces_steps_and_changes_nothing(adapter, tmp_path):
    dev = FakeIOSDevice(read(SEEDED_SWITCH))
    tr = FakeSSHTransport(dev)
    t = _live_target(allow_push=False)
    c, findings = scan(adapter, t, tr, tmp_path / "w")
    assert c.facts.model == "C9300-48P"
    f = next(x for x in findings if x.rule_version == "CISC-ND-000720")
    fix = FixLibrary(adapter.fixes_for(t, c)).get(f.fix_ref)
    before = adapter.capture_before_state(t, tr, fix, f, tmp_path / "s")
    r = adapter.apply(t, tr, fix, f, before)
    assert not r.ok and not r.changed and r.details["steps"][0] == "configure terminal"
    assert dev.config == read(SEEDED_SWITCH) and "configure terminal" not in dev.typed
    assert all(ch.closed for ch in dev.channels)


def test_live_push_verify_and_inverse_rollback(adapter, tmp_path):
    dev = FakeIOSDevice(read(SEEDED_SWITCH))
    tr = FakeSSHTransport(dev)
    t = _live_target(allow_push=True)
    c, findings = scan(adapter, t, tr, tmp_path / "w")
    lib = FixLibrary(adapter.fixes_for(t, c) + adapter.fixes())
    for stig in ("CISC-ND-000720", "CISC-ND-000160"):          # line blocks, then a multi-line banner
        f = next(x for x in findings if x.rule_version == stig)
        fix = lib.get(f.fix_ref)
        before = adapter.capture_before_state(t, tr, fix, f, tmp_path / "s" / stig)
        r = adapter.apply(t, tr, fix, f, before)
        assert r.ok, r.output
        assert dev.saved == dev.config
        v = adapter.verify(t, tr, fix, f)
        assert v.ok, v.evidence
        assert any(ch.name == "cli_responds" and ch.ok for ch in v.health.checks)
        rb = adapter.rollback(t, tr, fix, before)
        assert rb.ok and rb.details["mode"] == "ssh_inverse"
        assert adapter.verify(t, tr, fix, f).rule_passed is False
    assert all(ch.closed for ch in dev.channels)


def test_live_configure_replace_rollback_and_rejected_line(adapter, tmp_path):
    dev = FakeIOSDevice(read(SEEDED_SWITCH))
    tr = FakeSSHTransport(dev)
    t = _live_target(allow_push=True, archive=True, archive_path="flash:ct-pre.cfg")
    c, findings = scan(adapter, t, tr, tmp_path / "w")
    f = next(x for x in findings if x.rule_version == "CISC-ND-000150")
    fix = FixLibrary(adapter.fixes()).get(f.fix_ref)
    before = adapter.capture_before_state(t, tr, fix, f, tmp_path / "s")
    assert dev.archive == read(SEEDED_SWITCH)
    assert adapter.apply(t, tr, fix, f, before).ok and "login block-for" in dev.config
    rb = adapter.rollback(t, tr, fix, before)
    assert rb.ok and rb.details["mode"] == "configure_replace" and dev.config == read(SEEDED_SWITCH)
    from dataclasses import replace
    bogus = replace(fix, payload="bogus command")
    saved = dev.saved
    r = adapter.apply(t, tr, bogus, f, before)
    assert not r.ok and "rejected" in r.output and dev.saved == saved     # no write memory after an error
