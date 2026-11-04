import json


def test_cklb_merge(state_dir, monkeypatch, tmp_path, fixtures_dir):
    monkeypatch.setenv("CT_STATE_DIR", str(state_dir))
    from cyberthunder.adapters.windows.adapter import WindowsAdapter
    from cyberthunder.adapters.windows.simhost import SimulatedWindowsHost

    a = WindowsAdapter()
    target = a.demo_targets()[0]
    target.options["cklb_path"] = str(fixtures_dir / "windows" / "ws01-evaluate-stig.cklb")
    sim = SimulatedWindowsHost(tmp_path / "sim.json")
    sim.reset()
    col = a.collect(target, sim, tmp_path / "w", modules=["check"])
    assert "cklb" in col.artifacts and not col.errors
    out = a.run_detection(target, col)
    wd = [f for f in out if f.rule_version == "WN11-CC-000038"]
    assert len(wd) == 1
    f = wd[0]
    assert f.is_open                                         # live state wins over the stale checklist
    assert "checklist status was not_a_finding" in f.evidence
    assert f.description == "Checklist discussion text for WDigest."
    assert f.fix_ref == "windows:wdigest_off"
    extra = [f for f in out if f.rule_version == "WN11-00-000040"]
    assert extra and extra[0].source == "evaluate-stig" and extra[0].host == target.id and extra[0].citations


def test_fixture_transport_replay(state_dir, monkeypatch, tmp_path):
    """A recorded live session (FixtureTransport) drives the same detection as the simulated host."""
    monkeypatch.setenv("CT_STATE_DIR", str(state_dir))
    from cyberthunder.adapters.windows.adapter import WindowsAdapter
    from cyberthunder.adapters.windows.scripts import command_for, load
    from cyberthunder.adapters.windows.simhost import SimulatedWindowsHost
    from cyberthunder.transport.fixture import FixtureTransport

    sim = SimulatedWindowsHost(tmp_path / "sim.json")
    sim.reset()
    entries = []
    for name in ("facts", "checks", "hunt"):
        cmd = command_for(load(name))
        entries.append({"match": cmd, "stdout": sim.run(cmd).stdout, "exit": 0})
    fx = tmp_path / "fx"
    fx.mkdir()
    (fx / "commands.json").write_text(json.dumps(entries), encoding="utf-8")

    a = WindowsAdapter()
    target = a.demo_targets()[0]
    col = a.collect(target, FixtureTransport(fx, strict=True), tmp_path / "w")
    assert not col.errors
    out = a.run_detection(target, col)
    assert {f.rule_version for f in out if f.is_open and f.rule_version} >= {"WN11-SO-000010", "WN11-CC-000326"}
    assert any("T1053.005" in f.citations for f in out)


def test_hunt_rules_on_crafted_state():
    from cyberthunder.adapters.windows import hunt
    now = "2026-11-04T12:00:00Z"
    state = {
        "now": now,
        "admins": {"name": "WS\\itadmin", "sid": "S-1-5-21-1-1001"},           # single object, not a list
        "listeners": [{"address": "0.0.0.0", "port": 4444, "pid": 9, "process": "nc"},
                      {"address": "0.0.0.0", "port": 49666, "pid": 8, "process": "svchost"}],
        "wmi": [{"filter": "f", "query": "SELECT * FROM __InstanceModificationEvent", "consumer": "c",
                 "consumer_class": "CommandLineEventConsumer", "command": "cmd /c x"}],
        "hidden_accounts": [{"name": "support$", "value": "0"}],
        "rdp": {"enabled": True, "key_last_write": "2026-11-01T00:00:00Z", "nla": 1},
        "failed_logons": [{"time": f"2026-11-04T11:00:{i:02d}Z", "user": "itadmin", "ip": "10.1.1.9"} for i in range(12)],
        "defender_exclusions": {"paths": ["C:\\Users\\Public"], "processes": None, "extensions": []},
        "services": [{"name": "Svc", "display": "Svc", "path": "C:\\Program Files\\Vendor App\\svc.exe -k",
                      "start_type": "Auto", "status": "Running"}],
    }
    got = {h.technique for h in hunt.hits(state, {"known_admins": ["itadmin"], "expected_ports": [3389]})}
    assert got == {"T1571", "T1546.003", "T1564.002", "T1021.001", "T1110", "T1562.001", "T1543.003"}
