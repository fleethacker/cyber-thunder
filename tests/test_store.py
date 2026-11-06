"""The store's view of 'current findings': latest full scan plus newer partial runs overlaid."""
from cyberthunder.findings.schema import Finding
from cyberthunder.store import StateStore, is_partial_run


def _f(host, rule, status="open", severity="medium"):
    return Finding(host=host, source="native", rule_id=rule, title=rule, severity=severity, status=status)


def _run(store, scan_id, started_at, findings, trigger="manual", rule_filter=None):
    store.save_scan_run({"id": scan_id, "started_at": started_at, "status": "done", "trigger": trigger,
                         "rule_filter": rule_filter, "targets": sorted({f.host for f in findings})})
    store.save_findings(scan_id, findings)


def test_partial_runs_do_not_become_the_default_scan(state_dir):
    store = StateStore(state_dir)
    _run(store, "scan-1", "2026-11-04T10:00:00+00:00", [_f("h1", "RHEL-09-255045"), _f("h1", "RHEL-09-255040")])
    _run(store, "scan-2", "2026-11-04T11:00:00+00:00", [_f("h1", "iavm:2026-A-0001:openssh")], trigger="bulletin")
    assert is_partial_run(store.load_scan_run("scan-2"))
    assert store.latest_scan_id() == "scan-1"
    assert store.latest_scan_id(full_only=False) == "scan-2"


def test_current_findings_overlay_newer_partial_runs(state_dir):
    store = StateStore(state_dir)
    _run(store, "scan-1", "2026-11-04T10:00:00+00:00",
         [_f("h1", "RHEL-09-255045"), _f("h1", "RHEL-09-255040"), _f("h2", "RHEL-09-255045")])
    # a bulletin adds findings
    _run(store, "scan-2", "2026-11-04T11:00:00+00:00", [_f("h1", "iavm:2026-A-0001:openssh", severity="high")], trigger="bulletin")
    # a targeted rescan after a STIG delta re-evaluates one rule on h1: it now passes
    _run(store, "scan-3", "2026-11-04T12:00:00+00:00", [_f("h1", "RHEL-09-255045", status="not_a_finding")],
         trigger="stig_delta", rule_filter=["RHEL-09-255045"])
    current = {(f.host, f.rule_id): f for f in store.load_findings()}
    assert len(current) == 4
    assert current[("h1", "RHEL-09-255045")].status.value == "not_a_finding"     # replaced by the rescan
    assert current[("h1", "RHEL-09-255040")].status.value == "open"              # untouched from the full scan
    assert current[("h2", "RHEL-09-255045")].status.value == "open"
    assert current[("h1", "iavm:2026-A-0001:openssh")].severity.value == "high"  # added by the bulletin
    # explicit scan ids still return exactly that run
    assert len(store.load_findings("scan-2")) == 1
    assert store.get_finding(current[("h1", "iavm:2026-A-0001:openssh")].id) is not None


def test_new_full_scan_resets_the_overlay(state_dir):
    store = StateStore(state_dir)
    _run(store, "scan-1", "2026-11-04T10:00:00+00:00", [_f("h1", "a")])
    _run(store, "scan-2", "2026-11-04T11:00:00+00:00", [_f("h1", "iavm:x:y")], trigger="bulletin")
    _run(store, "scan-3", "2026-11-04T12:00:00+00:00", [_f("h1", "a", status="not_a_finding")])
    assert store.latest_scan_id() == "scan-3"
    assert [f.rule_id for f in store.load_findings()] == ["a"]


def test_full_scan_does_not_erase_targets_it_did_not_scan(state_dir):
    store = StateStore(state_dir)
    _run(store, "both", "2026-11-04T10:00:00+00:00", [_f("h1", "a"), _f("h2", "b")])
    _run(store, "one", "2026-11-04T11:00:00+00:00", [_f("h1", "a", status="not_a_finding")])
    current = {f.host: f for f in store.load_findings()}
    assert current["h1"].status.value == "not_a_finding"
    assert current["h2"].status.value == "open"
    store.save_scan_run({"id": "empty", "started_at": "2026-11-04T12:00:00+00:00",
                         "status": "done", "targets": ["h1"]})
    store.save_findings("empty", [])
    assert [(f.host, f.rule_id) for f in store.load_findings()] == [("h2", "b")]
