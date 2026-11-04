"""The Windows adapter running the trimmed DISA Windows 11 benchmark against the simulated host, merged with
the native checks; fix, verify and rollback through the benchmark."""
import pytest

FIXTURE_NAME = "w11_subset-ds.xml"

# Expected results per seeded state (range/answer_key/windows.json): the benchmark finds the same six
# misconfigurations the native checks do, and everything else in the subset passes.
EXPECTED_OPEN = {"WN11-00-000165", "WN11-SO-000010", "WN11-CC-000038", "WN11-SO-000205", "WN11-AC-000035",
                 "WN11-CC-000326"}
EXPECTED_PASS = {"WN11-SO-000195", "WN11-SO-000270", "WN11-CC-000190", "WN11-AC-000010", "WN11-AC-000020",
                 "WN11-AC-000005", "WN11-AC-000045", "WN11-AC-000040", "WN11-SO-000140", "WN11-AU-000070",
                 "WN11-AU-000075", "WN11-AU-000005", "WN11-SO-000020", "WN11-UR-000005", "WN11-UR-000015",
                 "WN11-UR-000010", "WN11-00-000010"}


@pytest.fixture
def env(state_dir, monkeypatch, tmp_path, fixtures_dir):
    monkeypatch.setenv("CT_STATE_DIR", str(state_dir))
    from cyberthunder.adapters.windows.adapter import WindowsAdapter
    from cyberthunder.config import Settings
    settings = Settings.from_env(state_dir=str(state_dir))
    adapter = WindowsAdapter()
    target = adapter.demo_targets()[0]
    target.options = {**target.options, "scap_datastream": str(fixtures_dir / "scap" / FIXTURE_NAME)}
    transport = adapter.make_transport(target, settings)
    transport.reset()
    return adapter, target, transport, tmp_path


def _scan(adapter, target, transport, workdir):
    col = adapter.collect(target, transport, workdir)
    assert not col.errors, col.errors
    return col, adapter.run_detection(target, col)


def _stig(findings):
    out = {}
    for f in findings:
        if f.source in ("windows-stig", "windows-scap") and f.rule_version:
            assert f.rule_version not in out, f"duplicate finding for {f.rule_version}"
            out[f.rule_version] = f
    return out


def test_benchmark_on_simulated_host(env):
    adapter, target, transport, tmp = env
    col, findings = _scan(adapter, target, transport, tmp / "scan")
    assert col.raw["scap_source"]["rounds"][0]["registry_keys"] >= 7
    by = _stig(findings)
    scap = {k: f for k, f in by.items() if "scap" in f.tags}
    assert len(scap) >= 15
    assert {k for k, f in scap.items() if f.status.value == "open"} == EXPECTED_OPEN
    assert EXPECTED_PASS <= {k for k, f in scap.items() if f.status.value == "not_a_finding"}
    assert by["WN11-AU-000515"].status.value == "not_reviewed"
    assert "fileeffectiverights53_test" in by["WN11-AU-000515"].evidence
    assert by["WN11-UR-000075"].status.value == "not_applicable"
    for f in findings:
        assert f.references, f"{f.rule_id} has no citation"
    lm = by["WN11-SO-000205"]
    assert "LmCompatibilityLevel = 2" in lm.evidence


def test_merge_keeps_native_ids_and_native_only_rules(env):
    adapter, target, transport, tmp = env
    _, findings = _scan(adapter, target, transport, tmp / "scan")
    by = _stig(findings)
    # covered by both: one finding, the native id and fix, the benchmark's evidence
    lm = by["WN11-SO-000205"]
    assert lm.source == "windows-stig" and lm.fix_ref == "windows:lm_compat"
    assert lm.evidence.startswith("SCAP benchmark (OVAL):") and "scap" in lm.tags
    # only in the benchmark: its own finding
    assert by["WN11-UR-000010"].source == "windows-scap"
    # only native (firewall, defender are not in the subset): unchanged
    assert by["WN11-00-000135"].source == "windows-stig" and "scap" not in by["WN11-00-000135"].tags
    # without the datastream the same host gives the native findings only
    target.options = {k: v for k, v in target.options.items() if k != "scap_datastream"}
    _, native = _scan(adapter, target, transport, tmp / "native")
    nby = _stig(native)
    assert "WN11-UR-000010" not in nby
    assert nby["WN11-SO-000205"].id == lm.id


def test_benchmark_result_wins_over_native(monkeypatch, env):
    """Make the native check disagree: the benchmark's status is the one reported, both are in the evidence."""
    adapter, target, transport, tmp = env
    from cyberthunder.adapters.windows import checks
    real = checks.evaluate

    def lying(*a, **kw):
        out = real(*a, **kw)
        for f in out:
            if f.rule_version == "WN11-SO-000205":
                f.status = type(f.status)("not_a_finding")
        return out
    monkeypatch.setattr(checks, "evaluate", lying)
    _, findings = _scan(adapter, target, transport, tmp / "scan")
    lm = _stig(findings)["WN11-SO-000205"]
    assert lm.status.value == "open"
    assert "native check said not_a_finding" in lm.evidence


def test_rule_filter_rescan(env):
    adapter, target, transport, tmp = env
    col = adapter.collect(target, transport, tmp / "one", rule_filter=["WN11-UR-000010"])
    findings = adapter.check(target, col)
    assert [f.rule_version for f in findings if "scap" in f.tags] == ["WN11-UR-000010"]


def test_fix_verify_rollback_through_benchmark(env):
    from cyberthunder.remediation.library import FixLibrary
    adapter, target, transport, tmp = env
    _, findings = _scan(adapter, target, transport, tmp / "scan")
    finding = _stig(findings)["WN11-SO-000205"]
    lib = FixLibrary()
    lib.extend(adapter.fixes())
    fix = lib.resolve(finding)
    assert fix is not None and fix.fix_ref == "windows:lm_compat"
    before = adapter.capture_before_state(target, transport, fix, finding, tmp / "before")
    assert adapter.apply(target, transport, fix, finding, before).ok
    v = adapter.verify(target, transport, fix, finding)
    assert v.rule_passed is True and v.evidence.startswith("SCAP benchmark (OVAL):")
    assert adapter.rollback(target, transport, fix, before).ok
    v2 = adapter.verify(target, transport, fix, finding)
    assert v2.rule_passed is False


def test_benchmark_only_rule_verifies_from_benchmark(env):
    adapter, target, transport, tmp = env
    _, findings = _scan(adapter, target, transport, tmp / "scan")
    f = _stig(findings)["WN11-UR-000010"]
    fix = next(iter(adapter.fixes()))
    v = adapter.verify(target, transport, fix, f)
    assert v.rule_passed is True and "SE_NETWORK_LOGON_NAME" in v.evidence


def test_missing_datastream_is_an_error_not_a_crash(env):
    adapter, target, transport, tmp = env
    target.options = {**target.options, "scap_datastream": str(tmp / "absent.xml")}
    col = adapter.collect(target, transport, tmp / "scan")
    assert any("scap datastream" in e for e in col.errors)
    assert adapter.run_detection(target, col)          # native checks still run


def test_scap_merge_unit():
    from cyberthunder.adapters.base import make_finding
    from cyberthunder.adapters.windows.scap_merge import merge
    from cyberthunder.inventory.targets import Target
    t = Target(id="w", name="w", asset_type="windows", transport="simulated")
    native = [make_finding(target=t, source="windows-stig", rule_id="SV-1r1_rule", title="n", severity="medium",
                           status="open", rule_version="WN11-AA-000001", evidence="native says open",
                           fix_ref="windows:x"),
              make_finding(target=t, source="windows-stig", rule_id="SV-2r1_rule", title="n2", severity="medium",
                           status="open", rule_version="WN11-AA-000002", evidence="native open")]
    bench = [make_finding(target=t, source="windows-scap", rule_id="SV-1r2_rule", title="b", severity="high",
                          status="not_a_finding", rule_version="WN11-AA-000001", evidence="oval true",
                          references=["CCI-000366"], tags=["scap"]),
             make_finding(target=t, source="windows-scap", rule_id="SV-2r2_rule", title="b2", severity="medium",
                          status="not_reviewed", rule_version="WN11-AA-000002", evidence="unknown"),
             make_finding(target=t, source="windows-scap", rule_id="SV-3r1_rule", title="b3", severity="low",
                          status="open", rule_version="WN11-AA-000003", evidence="oval false")]
    out = {f.rule_version: f for f in merge(t, native, bench)}
    assert len(out) == 3
    a = out["WN11-AA-000001"]
    assert (a.status.value, a.id, a.fix_ref, a.severity.value, a.title) == ("not_a_finding", native[0].id, "windows:x",
                                                                           "high", "b")
    assert "native check said open" in a.evidence and "CCI-000366" in {r.id for r in a.references}
    b = out["WN11-AA-000002"]
    assert b.status.value == "open" and "could not decide" in b.evidence
    assert out["WN11-AA-000003"].source == "windows-scap"
