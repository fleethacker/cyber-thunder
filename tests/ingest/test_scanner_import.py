"""Passive scanner imports use temporary state and the existing export fixture."""
from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock

import pytest

from cyberthunder.cli import main
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.findings.schema import Finding
from cyberthunder.ingest import scanner_results as imports
from cyberthunder.inventory.targets import Target
from cyberthunder.scan import ScanRun
from cyberthunder.store import StateStore, is_partial_run

SAMPLE = Path(__file__).resolve().parents[1] / "fixtures" / "parsers" / "sample.nessus"
MAPPING = {"ws-014.enclave.example": "workstation", "10.20.1.30": "server"}
ACTOR = "IT2 Rivera"


@pytest.fixture
def passive(ctx, monkeypatch):
    assert ctx.store.info()["backend"] == os.environ["CT_STATE_BACKEND"]
    for tid, kind in (("workstation", "windows"), ("server", "linux"), ("other", "linux")):
        ctx.inventory.add(Target(tid, tid, kind, transport="fixture", in_scope=False))
    ctx.inventory.save()
    for name in ("transport_for", "adapter_for"):
        monkeypatch.setattr(ctx, name, Mock(side_effect=AssertionError("collection is forbidden")))
    for name in ("start", "run"):
        monkeypatch.setattr(ctx.scanner, name, Mock(side_effect=AssertionError("scanning is forbidden")))
    for name in ("propose", "execute", "rollback"):
        monkeypatch.setattr(ctx.engine, name, Mock(side_effect=AssertionError("remediation is forbidden")))
    monkeypatch.setattr(ctx.explain, "precompute", Mock(side_effect=AssertionError("explanation is forbidden")))
    yield ctx
    assert ctx.gate.list() == []
    assert all(not t.in_scope for t in ctx.inventory.all())
    assert ctx.audit.verify().ok


def seed(ctx, *, partial=False, host="other", rule="unrelated", run_id="baseline", targets=None):
    f = Finding(host=host, source="hunt", rule_id=rule, title="Existing observation", severity="high", status="open",
                scan_id=run_id)
    run = ScanRun(id=run_id, targets=targets or [host], status="done", started_at="2020-01-01T00:00:00+00:00",
                  rule_filter=[rule] if partial else None)
    ctx.store.save_findings(run_id, [f])
    ctx.store.save_scan_run(run.to_dict())
    return f


def run_import(ctx, data=None, mapping=None, **kwargs):
    return ctx.ingest.import_scanner(SAMPLE.read_bytes() if data is None else data,
                                     MAPPING if mapping is None else mapping, actor=ACTOR, **kwargs)


def state_snapshot(ctx):
    """Compare logical state, not a backend's database pages, journals or checkpoint files."""
    store = ctx.store
    paths = set(store.list_json(store.root)) | set(store.list_json(store.root, "**/*.json"))
    return {"documents": {str(p.relative_to(store.root)): store.read_json(p) for p in paths},
            "audit": list(ctx.audit.records()), "targets": [t.to_dict() for t in ctx.inventory.all()],
            "kill": ctx.killswitch.status()}


def test_fixture_maps_hosts_cves_ports_and_provenance(passive):
    res = run_import(passive)
    assert res["imported_count"] == 5
    assert not res["repeated"]
    run = passive.store.load_scan_run(res["scan_id"])
    assert is_partial_run(run) and run["rule_filter"]
    assert run["trigger"] == "scanner_import" and run["requested_by"] == ACTOR
    findings = passive.store.load_findings()
    assert len(findings) == 5
    assert {f.host for f in findings} == set(MAPPING.values())
    for f in findings:
        assert f.id == Finding.make_id(f.host, "acas", f.rule_id)
        assert f.scan_id == res["scan_id"]
        assert f.raw_ref == "sha256:" + res["source_sha256"]
        assert "import:nessus" in f.tags
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["nessus:97833"].ref_ids("cve") == ["CVE-2017-0143", "CVE-2017-0144"]
    assert by_rule["nessus:187315"].ref_ids("cve") == ["CVE-2023-48795"]
    assert {"port:443/tcp", "port:8443/tcp"} <= set(by_rule["nessus:51192"].tags)
    assert by_rule["nessus:97833"].asset_type == "windows"
    assert "source-host:ws-014.enclave.example" in by_rule["nessus:97833"].tags
    assert not list(passive.store.scans_dir.glob("*/raw/**/*"))


@pytest.mark.parametrize("partial", [False, True])
def test_import_preserves_unrelated_hosts_and_rules(passive, partial):
    other = seed(passive, partial=partial)
    same_host = seed(passive, partial=True, host="server", rule="same-host-unrelated", run_id="extra")
    res = run_import(passive)
    current = {f.id: f for f in passive.store.current_findings()}
    assert len(current) == 7
    assert current[other.id].to_dict() == other.to_dict()
    assert current[same_host.id].to_dict() == same_host.to_dict()
    assert res["carried_forward_count"] == (2 if partial else 0)
    assert passive.store.load_scan_run(res["scan_id"])["findings_count"] == 5 + res["carried_forward_count"]


def test_repeat_is_idempotent_across_contexts_and_mapping_order(passive):
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext
    first = run_import(passive)
    stored = [f.to_dict() for f in passive.store.load_findings()]
    again = AppContext(Settings(state_dir=passive.store.root, llm_backend="template"))
    assert again.store.info()["backend"] == passive.store.info()["backend"]
    second = run_import(again, mapping=dict(reversed(list(MAPPING.items()))))
    assert second == dict(first, repeated=True)
    assert len(again.store.list_scan_runs()) == 1
    assert [f.to_dict() for f in again.store.load_findings()] == stored
    assert list(again.audit.records())[-1]["action"] == "ingest.scanner.repeat"


def test_concurrent_repeats_publish_one_run(passive):
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run_import(passive), range(2)))
    assert len({r["scan_id"] for r in results}) == 1
    assert sorted(r["repeated"] for r in results) == [False, True]
    assert len(passive.store.list_scan_runs()) == 1


def test_changed_source_overlays_only_present_findings(passive):
    first = run_import(passive)
    before = {f.id: f for f in passive.store.load_findings()}
    changed = SAMPLE.read_bytes().replace(b"Encryption level not enforced.", b"Updated evidence.")
    second = run_import(passive, changed)
    assert second["scan_id"] != first["scan_id"]
    after = {f.id: f for f in passive.store.load_findings()}
    assert after.keys() == before.keys()
    assert "Updated evidence." in next(f.evidence for f in after.values() if f.rule_id == "nessus:18405")
    # A later export omitting another host/rule cannot mark that observation clean or remove it.
    minimal = b'<NessusClientData_v2><Report><ReportHost name="one"><ReportItem pluginID="999" severity="1" port="0" protocol="tcp"/></ReportHost></Report></NessusClientData_v2>'
    third = run_import(passive, minimal, {"one": "other"})
    assert third["carried_forward_count"] == 5
    assert len(passive.store.current_findings()) == 6


def test_mapping_changes_ids_only_for_remapped_host(passive):
    first = run_import(passive)
    originals = {f.rule_id: f for f in passive.store.load_findings(first["scan_id"])}
    second = run_import(passive, mapping=dict(MAPPING, **{"10.20.1.30": "other"}))
    current = passive.store.load_findings(second["scan_id"])
    moved = next(f for f in current if f.host == "other" and f.rule_id == "nessus:187315")
    assert moved.id != originals[moved.rule_id].id
    assert moved.ref_ids("cve") == originals[moved.rule_id].ref_ids("cve")
    assert len(passive.store.load_findings()) == 8  # remapping does not delete earlier observations


@pytest.mark.parametrize("payload", [
    b"", b"<NessusClientData_v2>", b"<other/>",
    b"<NessusClientData_v2><Report/></NessusClientData_v2>",
    b'<!DOCTYPE NessusClientData_v2 [<!ENTITY x SYSTEM "file:///private-secret">]><NessusClientData_v2>&x;</NessusClientData_v2>',
    b'<!DOCTYPE NessusClientData_v2 [<!ENTITY a "secret"><!ENTITY b "&a;&a;">]><NessusClientData_v2>&b;</NessusClientData_v2>',
    SAMPLE.read_bytes().replace(b'severity="4"', b'severity="99"'),
    SAMPLE.read_bytes().replace(b'pluginID="97833"', b'pluginID="private-secret"'),
    SAMPLE.read_bytes().replace(b'port="445"', b'port="99999"'),
    SAMPLE.read_bytes().replace(b"CVE-2017-0143", b"private-secret"),
    SAMPLE.read_bytes().replace(b'<ReportHost name="10.20.1.30">', b'<ReportHost name="ws-014.enclave.example">'),
    b'<NessusClientData_v2><Report><ReportHost name="one"><ReportItem pluginID="1" severity="0" port="0" protocol="tcp"/></ReportHost></Report></NessusClientData_v2>',
])
def test_invalid_or_empty_input_never_writes_or_clears(passive, payload):
    original = seed(passive)
    before = list(passive.audit.records())
    with pytest.raises(imports.ScannerImportError) as error:
        run_import(passive, payload, {"one": "server"} if b'name="one"' in payload else MAPPING)
    assert "private-secret" not in str(error.value)
    assert [f.id for f in passive.store.load_findings()] == [original.id]
    assert len(passive.store.list_scan_runs()) == 1
    assert list(passive.audit.records()) == before


@pytest.mark.parametrize("limit,value", [("MAX_XML_BYTES", 50), ("MAX_HOSTS", 1), ("MAX_ITEMS", 2),
                                       ("MAX_ELEMENTS", 5), ("MAX_DEPTH", 3), ("MAX_FIELD", 20)])
def test_size_and_structure_limits_precede_writes(passive, monkeypatch, limit, value):
    monkeypatch.setattr(imports, limit, value)
    with pytest.raises(imports.ScannerImportError):
        run_import(passive)
    assert passive.store.list_scan_runs() == []


def test_utf16_dtd_cannot_bypass_validation(passive):
    text = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE NessusClientData_v2 [<!ENTITY a "secret">]><NessusClientData_v2>&a;</NessusClientData_v2>'
    with pytest.raises(imports.ScannerImportError):
        run_import(passive, text.encode("utf-16"))
    assert passive.store.list_scan_runs() == []


@pytest.mark.parametrize("mapping", [{}, [], {"unknown-source": "server"},
    dict(MAPPING, **{"extra": "other"}), dict(MAPPING, **{"10.20.1.30": "missing"}),
    dict(MAPPING, **{"10.20.1.30": "workstation"}), {"ws-014.enclave.example": 123}])
def test_mapping_must_be_complete_known_and_unambiguous(passive, mapping):
    with pytest.raises(imports.ScannerImportError):
        run_import(passive, mapping=mapping)
    assert passive.store.list_scan_runs() == []


@pytest.mark.parametrize("data", [b'{"a":"server","a":"other"}', b'"private-secret"', b'{"a":', b'\xff'])
def test_mapping_json_is_strict_and_errors_do_not_echo(data):
    with pytest.raises(imports.ScannerImportError) as error:
        imports.parse_mapping(data)
    assert "private-secret" not in str(error.value)


@pytest.mark.parametrize("actor", ["", " ", "operator", "agent", "system:job", "policy:signed", "Rivera\nforged"])
def test_actor_refusal(passive, actor):
    with pytest.raises(PermissionError, match="named human"):
        passive.ingest.import_scanner(SAMPLE.read_bytes(), MAPPING, actor=actor)
    assert passive.store.list_scan_runs() == []


def test_kill_blocks_new_and_repeat_imports(passive):
    first = run_import(passive)
    passive.killswitch.engage(ACTOR, "test stop")
    with pytest.raises(KillSwitchEngaged):
        run_import(passive)
    with pytest.raises(KillSwitchEngaged):
        run_import(passive, include_info=True)
    assert [r["id"] for r in passive.store.list_scan_runs()] == [first["scan_id"]]
    assert list(passive.audit.records())[-1]["action"] == "action.blocked"


def test_failure_before_publication_preserves_current_results(passive, monkeypatch):
    original = seed(passive)
    monkeypatch.setattr(passive.store, "save_findings", Mock(side_effect=OSError("private-secret")))
    with pytest.raises(OSError, match="scanner import storage is unavailable"):
        run_import(passive)
    assert [f.id for f in passive.store.load_findings()] == [original.id]
    assert len(passive.store.list_scan_runs()) == 1


def test_kill_engaged_after_findings_write_prevents_publication_and_retry_recovers(passive, monkeypatch):
    original = seed(passive)
    save = passive.store.save_findings
    written_ids = []

    def stop_after_findings(*args, **kwargs):
        save(*args, **kwargs)
        written_ids.append(args[0])
        passive.killswitch.engage(ACTOR, "stop before publication")

    monkeypatch.setattr(passive.store, "save_findings", stop_after_findings)
    with pytest.raises(KillSwitchEngaged):
        run_import(passive)
    assert len(passive.store.list_scan_runs()) == 1
    assert [f.id for f in passive.store.current_findings()] == [original.id]
    (unpublished_id,) = written_ids
    assert passive.store.load_scan_run(unpublished_id) is None
    assert len(passive.store.load_findings(unpublished_id)) == 5
    unpublished = passive.store.read_json(passive.store.scans_dir / unpublished_id / "findings.json")
    assert unpublished["meta"]["imported_count"] == 5
    monkeypatch.setattr(passive.store, "save_findings", save)
    passive.killswitch.release(ACTOR)
    result = run_import(passive)
    assert result["scan_id"] == unpublished_id and not result["repeated"]
    assert len(passive.store.current_findings()) == 6


def test_compliance_check_ids_and_status_survive_mapping(passive):
    data = b'''<NessusClientData_v2 xmlns:cm="urn:compliance"><Report name="Audit">
      <ReportHost name="audit-host"><ReportItem port="0" protocol="tcp" severity="3" pluginID="21156">
        <cm:compliance-check-id>check-a</cm:compliance-check-id>
        <cm:compliance-check-name>Guest account</cm:compliance-check-name>
        <cm:compliance-reference>STIG-ID|WN11-SO-000010,VULN-ID|V-253434,CCI|CCI-000366</cm:compliance-reference>
        <cm:compliance-result>FAILED</cm:compliance-result>
      </ReportItem><ReportItem port="0" protocol="tcp" severity="0" pluginID="21156">
        <cm:compliance-check-id>check-b</cm:compliance-check-id>
        <cm:compliance-check-name>Password complexity</cm:compliance-check-name>
        <cm:compliance-reference>STIG-ID|WN11-AC-000040</cm:compliance-reference>
        <cm:compliance-result>PASSED</cm:compliance-result>
      </ReportItem></ReportHost></Report></NessusClientData_v2>'''
    result = run_import(passive, data, {"audit-host": "workstation"}, include_info=True)
    findings = {f.rule_id: f for f in passive.store.load_findings(result["scan_id"])}
    failed = findings["WN11-SO-000010"]
    assert failed.status.value == "open" and failed.group_id == "V-253434"
    assert failed.ref_ids("cci") == ["CCI-000366"]
    assert failed.id == Finding.make_id("workstation", "acas", failed.rule_id)
    assert findings["WN11-AC-000040"].status.value == "not_a_finding"


def compliance_duplicates(results, *, stig=True):
    reference = "STIG-ID|WN11-AC-000035" if stig else "CCI|CCI-000366"
    items = "".join(f'''<ReportItem port="{port}" protocol="tcp" severity="{severity}" pluginID="21156">
      <cm:compliance-check-id>password-length</cm:compliance-check-id>
      <cm:compliance-check-name>Password length</cm:compliance-check-name>
      <cm:compliance-reference>{reference}</cm:compliance-reference>
      <cm:compliance-result>{status}</cm:compliance-result>
      </ReportItem>''' for port, status, severity in results)
    return (f'<NessusClientData_v2 xmlns:cm="urn:compliance"><Report><ReportHost name="audit-host">'
            f'{items}</ReportHost></Report></NessusClientData_v2>').encode()


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("stig", [False, True])
@pytest.mark.parametrize("outcomes", [("PASSED", 0, "FAILED", 3), ("PASSED", 3, "FAILED", 3),
                                      ("FAILED", 1, "FAILED", 3)])
def test_conflicting_compliance_results_are_rejected_before_merge_or_writes(passive, monkeypatch, reverse, stig,
                                                                           outcomes):
    seed(passive)
    before = state_snapshot(passive)
    parser = Mock(side_effect=AssertionError("conflicts must be rejected before the merge parser"))
    monkeypatch.setattr(imports, "parse_nessus", parser)
    results = [(0, outcomes[0], outcomes[1]), (445, outcomes[2], outcomes[3])]
    if reverse:
        results.reverse()
    with pytest.raises(imports.ScannerImportError, match="conflicting compliance"):
        run_import(passive, compliance_duplicates(results, stig=stig), {"audit-host": "workstation"},
                   include_info=True)
    parser.assert_not_called()
    assert state_snapshot(passive) == before


def test_filtering_info_does_not_hide_a_compliance_conflict(passive):
    original = seed(passive)
    data = compliance_duplicates([(0, "PASSED", 0), (445, "FAILED", 3)])
    with pytest.raises(imports.ScannerImportError, match="conflicting compliance"):
        run_import(passive, data, {"audit-host": "workstation"})
    assert len(passive.store.list_scan_runs()) == 1
    assert [f.id for f in passive.store.current_findings()] == [original.id]


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("stig", [False, True])
def test_consistent_compliance_duplicates_keep_stable_mapped_identity(passive, reverse, stig):
    results = [(0, "FAILED", 3), (445, " failed ", 3)]
    if reverse:
        results.reverse()
    result = run_import(passive, compliance_duplicates(results, stig=stig), {"audit-host": "workstation"},
                        include_info=True)
    (finding,) = passive.store.load_findings(result["scan_id"])
    rule_id = "WN11-AC-000035" if stig else "nessus:21156:password-length"
    assert finding.rule_id == rule_id and finding.host == "workstation"
    assert finding.id == Finding.make_id("workstation", "acas", rule_id)
    assert finding.status.value == "open"
    assert {"port:0/tcp", "port:445/tcp"} <= set(finding.tags)


def test_historical_repeat_does_not_reassert_old_results(passive):
    result = run_import(passive)
    # The replacement actually covers the imported hosts, as well as the new one.
    fresh = seed(passive, run_id="new-full", targets=["other", *MAPPING.values()])
    run = passive.store.load_scan_run("new-full")
    run["started_at"] = "2099-01-01T00:00:00+00:00"
    passive.store.save_scan_run(run)
    assert run_import(passive)["scan_id"] == result["scan_id"]
    assert [f.id for f in passive.store.current_findings()] == [fresh.id]


def test_audit_contains_digests_and_counts_not_source_secrets(passive):
    source = SAMPLE.read_bytes().replace(b"<Policy>", b"<Policy><password>private-secret</password>")
    res = run_import(passive, source)
    audit = json.dumps(list(passive.audit.records()))
    assert "private-secret" not in audit and "<Report" not in audit
    assert "ws-014.enclave.example" not in audit
    assert res["source_sha256"] in audit


def test_public_store_documents_persist_on_selected_backend(passive):
    first = run_import(passive)
    path = passive.store.scans_dir / first["scan_id"] / "findings.json"
    doc = passive.store.read_json(path)
    assert doc["meta"]["host_map"] == MAPPING
    assert doc["meta"]["sha256"] == first["source_sha256"]
    assert doc["meta"]["imported_count"] == len(doc["findings"]) == 5
    reopened = StateStore(passive.store.root)
    try:
        assert reopened.info()["backend"] == os.environ["CT_STATE_BACKEND"]
        assert reopened.read_json(path) == doc
        assert path in reopened.list_json(reopened.scans_dir, "*/findings.json")
        assert reopened.load_scan_run(first["scan_id"])["findings_count"] == 5
        assert {f.id for f in reopened.load_findings()} == {f["id"] for f in doc["findings"]}
    finally:
        reopened.close()
    assert run_import(passive)["repeated"]
    assert passive.store.read_json(path) == doc


def test_cli_fixture_import_repeat_and_existing_parse_behavior(passive, tmp_path, capsys, monkeypatch):
    from cyberthunder.ingest import cli
    monkeypatch.setattr(cli, "_service", lambda args: passive.ingest)
    mapping_file = tmp_path / "map.json"
    mapping_file.write_text(json.dumps(MAPPING), encoding="utf-8")
    args = ["--state-dir", str(passive.store.root), "--actor", ACTOR, "ingest", "scanner", str(SAMPLE),
            "--host-map", str(mapping_file)]
    assert main(args) == 0
    first = json.loads(capsys.readouterr().out)
    assert main(args) == 0
    second = json.loads(capsys.readouterr().out)
    assert first["scan_id"] == second["scan_id"] and second["repeated"]
    assert main([*args, "--include-info"]) == 0
    assert json.loads(capsys.readouterr().out)["imported_count"] == 6
    out = tmp_path / "parsed.json"
    assert main(["--state-dir", str(passive.store.root), "parse", str(SAMPLE), "--out", str(out), "--no-audit"]) == 0
    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert len(parsed["findings"]) == 5
    assert {f["host"] for f in parsed["findings"]} == set(MAPPING)
    assert len(passive.store.list_scan_runs()) == 2


@pytest.mark.parametrize("case", ["actor", "kill", "mapping", "empty", "missing", "oversized"])
def test_cli_refusals_are_safe(passive, tmp_path, capsys, monkeypatch, case):
    from cyberthunder.ingest import cli
    monkeypatch.setattr(cli, "_service", lambda args: passive.ingest)
    source = tmp_path / "private-secret.nessus"
    source.write_bytes(b"" if case == "empty" else SAMPLE.read_bytes())
    mapping_file = tmp_path / "map.json"
    mapping_file.write_text(json.dumps({} if case == "mapping" else MAPPING), encoding="utf-8")
    if case == "kill":
        passive.killswitch.engage(ACTOR)
    if case == "missing":
        source.unlink()
    if case == "oversized":
        monkeypatch.setattr(imports, "MAX_XML_BYTES", 50)
    assert main(["--state-dir", str(passive.store.root), "--actor", "agent" if case == "actor" else ACTOR,
                 "ingest", "scanner", str(source), "--host-map", str(mapping_file)]) == 2
    assert "private-secret" not in capsys.readouterr().err
    assert passive.store.list_scan_runs() == []
