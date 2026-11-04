import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ANSWER_KEY = ROOT / "range" / "answer_key" / "windows.json"


@pytest.fixture
def env(state_dir, monkeypatch, tmp_path):
    monkeypatch.setenv("CT_STATE_DIR", str(state_dir))
    from cyberthunder.adapters.windows.adapter import WindowsAdapter
    from cyberthunder.adapters.windows.simhost import SimulatedWindowsHost
    from cyberthunder.config import Settings
    settings = Settings.from_env(state_dir=str(state_dir))
    adapter = WindowsAdapter()
    target = adapter.demo_targets()[0]
    transport = adapter.make_transport(target, settings)
    assert isinstance(transport, SimulatedWindowsHost)
    transport.reset()
    return adapter, target, transport, tmp_path


def scan(adapter, target, transport, workdir):
    col = adapter.collect(target, transport, workdir)
    assert not col.errors, col.errors
    return adapter.run_detection(target, col)


def test_subset_benchmark_parses(fixtures_dir):
    from cyberthunder.parsers.xccdf import parse_xccdf
    p = parse_xccdf(fixtures_dir / "windows" / "w11_subset-xccdf.xml")
    assert len(p.rules) >= 15
    assert all(m.rule_version.startswith("WN11-") for m in p.rules.values())
    assert p.benchmark_id == "Microsoft_Windows_11_STIG"


def test_catalog_matches_benchmark_subset(fixtures_dir):
    from cyberthunder.adapters.windows import checks
    from cyberthunder.parsers.xccdf import parse_xccdf
    p = parse_xccdf(fixtures_dir / "windows" / "w11_subset-xccdf.xml")
    by_version = {m.rule_version: m for m in p.rules.values()}
    for c in checks.CHECKS:
        if c.stig_id:
            assert c.stig_id in by_version, c.stig_id
            assert c.rule_id == by_version[c.stig_id].rule_id
            assert checks.rule_meta(c.stig_id)["severity"] == by_version[c.stig_id].severity.value


def test_checks_script_reads_every_registry_value():
    from cyberthunder.adapters.windows import checks
    from cyberthunder.adapters.windows.scripts import load
    text = load("checks")
    for path in checks.REG_VALUES:
        assert f"'{path}'" in text, path


def test_every_answer_key_item_found(env):
    adapter, target, transport, tmp = env
    findings = scan(adapter, target, transport, tmp / "scan")
    open_ = [f for f in findings if f.is_open]
    key = json.loads(ANSWER_KEY.read_text(encoding="utf-8"))
    for item in key["items"]:
        if item["kind"] == "misconfig":
            hits = [f for f in open_ if f.rule_version == item["stig_id"]]
        else:
            hits = [f for f in open_ if item["attack"] in f.citations and item["indicator"].lower() in (f.evidence or "").lower()]
        assert hits, f"{item['id']} not found"
        assert hits[0].fix_ref == item["fix_ref"], item["id"]
    # Seeded host is otherwise compliant: misconfigs are exactly the answer key's.
    stig_open = {f.rule_version for f in open_ if f.source == "windows-stig"}
    assert stig_open == {i["stig_id"] for i in key["items"] if i["kind"] == "misconfig"}


def test_all_findings_cite(env):
    adapter, target, transport, tmp = env
    findings = scan(adapter, target, transport, tmp / "scan")
    assert findings
    for f in findings:
        assert f.citations, f.rule_id
        assert f.asset_type == "windows"
        if f.source == "hunt":
            assert any(r.system == "attack" or r.id.startswith("T1") for r in f.references), f.rule_id


def _by_version(findings, v):
    return next(f for f in findings if f.rule_version == v)


def _run_fix(adapter, target, transport, finding, tmp):
    lib = {e.fix_ref: e for e in adapter.fixes()}
    fix = lib[finding.fix_ref]
    before = adapter.capture_before_state(target, transport, fix, finding, tmp / f"snap-{finding.id}")
    res = adapter.apply(target, transport, fix, finding, before)
    assert res.ok, res.output
    ver = adapter.verify(target, transport, fix, finding)
    return fix, before, ver


@pytest.mark.parametrize("stig_id", ["WN11-00-000165", "WN11-CC-000038", "WN11-AC-000035"])
def test_apply_verify_rollback_check_fix(env, stig_id):
    adapter, target, transport, tmp = env
    finding = _by_version(scan(adapter, target, transport, tmp / "s1"), stig_id)
    assert finding.is_open
    fix, before, ver = _run_fix(adapter, target, transport, finding, tmp)
    assert ver.ok and ver.rule_passed and ver.health.ok
    assert _by_version(scan(adapter, target, transport, tmp / "s2"), stig_id).status.value == "not_a_finding"
    rb = adapter.rollback(target, transport, fix, before)
    assert rb.ok, rb.output
    assert _by_version(scan(adapter, target, transport, tmp / "s3"), stig_id).is_open


@pytest.mark.parametrize("attack,indicator", [("T1053.005", "OneDriveSync2"), ("T1078.003", "svc_backup"),
                                              ("T1547.001", "upd.exe"), ("T1543.003", "WinDefendSvc2"),
                                              ("T1136.001", "svc_backup")])
def test_apply_verify_rollback_hunt_fix(env, attack, indicator):
    adapter, target, transport, tmp = env
    findings = scan(adapter, target, transport, tmp / "s1")
    finding = next(f for f in findings if attack in f.citations and indicator.lower() in f.evidence.lower())
    state_before = transport.load()
    fix, before, ver = _run_fix(adapter, target, transport, finding, tmp)
    assert ver.ok and ver.rule_passed, ver.evidence
    assert not [f for f in scan(adapter, target, transport, tmp / "s2") if f.rule_id == finding.rule_id]
    rb = adapter.rollback(target, transport, fix, before)
    assert rb.ok, rb.output
    after = transport.load()
    for k in ("registry", "groups", "services", "tasks", "users"):
        assert after[k] == state_before[k], k
    assert [f for f in scan(adapter, target, transport, tmp / "s3") if f.rule_id == finding.rule_id]


def test_verify_fails_when_fix_did_not_take(env):
    adapter, target, transport, tmp = env
    finding = _by_version(scan(adapter, target, transport, tmp / "s1"), "WN11-SO-000205")
    fix = {e.fix_ref: e for e in adapter.fixes()}[finding.fix_ref]
    ver = adapter.verify(target, transport, fix, finding)      # nothing applied
    assert ver.rule_passed is False and not ver.ok


def test_reset_restores_seed(env):
    adapter, target, transport, tmp = env
    finding = _by_version(scan(adapter, target, transport, tmp / "s1"), "WN11-SO-000010")
    _run_fix(adapter, target, transport, finding, tmp)
    assert adapter.reset_simulated(target)
    assert _by_version(scan(adapter, target, transport, tmp / "s2"), "WN11-SO-000010").is_open


def test_simulated_host_refuses_unknown_commands(env):
    adapter, target, transport, tmp = env
    from cyberthunder.adapters.windows.scripts import command_for
    assert transport.run("Remove-Item C:\\ -Recurse").exit_code != 0
    assert transport.run(command_for("Get-Process")).exit_code != 0
    assert transport.run(command_for("# cyberthunder-fix: windows:not_a_fix\n")).exit_code != 0


def test_fix_library_entries_are_complete(env):
    adapter = env[0]
    from cyberthunder.remediation.library import FixLibrary
    lib = FixLibrary(adapter.fixes())
    for e in lib.all():
        assert e.rollback_kind in ("command", "manual")
        assert e.before_state.get("commands"), e.fix_ref
        if e.kind == "powershell":
            assert e.payload.splitlines()[0] == f"# cyberthunder-fix: {e.fix_ref}"
        assert e.citations


def test_rule_filter_limits_checks(env):
    adapter, target, transport, tmp = env
    col = adapter.collect(target, transport, tmp / "s", modules=["check"], rule_filter=["WN11-CC-000038"])
    out = adapter.run_detection(target, col)
    assert [f.rule_version for f in out] == ["WN11-CC-000038"]


def test_hunt_param_values_are_validated():
    from cyberthunder.adapters.windows.scripts import safe_values
    assert safe_values({"name": "OneDriveSync2", "path": "\\"})
    with pytest.raises(ValueError):
        safe_values({"name": "x'; Remove-Item C:\\ -Recurse; '"})


def test_long_scripts_are_staged_as_files(env, monkeypatch):
    adapter, target, transport, tmp = env
    from cyberthunder.adapters.windows import adapter as mod
    monkeypatch.setattr(mod, "MAX_INLINE", 100)
    findings = scan(adapter, target, transport, tmp / "s")
    assert any(f.rule_version == "WN11-SO-000010" and f.is_open for f in findings)
    assert any(" -File " in c for c in transport.calls)
