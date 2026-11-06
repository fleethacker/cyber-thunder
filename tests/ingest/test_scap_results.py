"""Strict XCCDF ingestion and publication boundaries, on both document backends."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import time
from unittest.mock import Mock

import pytest

from cyberthunder.control.principal import principal_scope
from cyberthunder.findings.schema import Finding
from cyberthunder.ingest import scap_results as scap
from cyberthunder.inventory.targets import Target
from cyberthunder.scan import ScanRun
from tests.security.job_helpers import enable_auth, revoke

NS = "http://checklists.nist.gov/xccdf/1.2"
ACTOR = "Joshua Ott"


def xml(results=None, *, test_id="result-1", end=True):
    results = results if results is not None else ["pass", "fail", "error", "notapplicable", "notchecked", "unknown"]
    rules = "".join(f'<Rule id="r{i}" severity="medium"><title>Rule {i}</title></Rule>' for i in range(len(results)))
    rows = "".join(f'<rule-result idref="r{i}"><result>{value}</result></rule-result>' for i, value in enumerate(results))
    ended = ' end-time="2026-11-05T12:00:00Z"' if end else ""
    return (f'<Benchmark xmlns="{NS}" id="benchmark">{rules}<TestResult id="{test_id}"{ended}>'
            '<benchmark id="benchmark" href="file:///never-read.xml"/><profile idref="profile"/>'
            f'<target>DO-NOT-MAP-THIS-HOST</target>{rows}</TestResult></Benchmark>').encode()


def manifest(n=6):
    return {"source_id": "range-export", "test_result_id": "result-1", "target_id": "container-a",
            "benchmark_id": "benchmark", "profile_id": "profile", "expected_rule_ids": [f"r{i}" for i in range(n)],
            "provenance": {"engine": "openscap", "engine_version": "1.3.10", "mode": "rootfs",
                           "image_ref": "registry.example.test/ubi9:fixture", "subject_ref": "/mounted/rootfs",
                           "platform": "UBI 9 (operator declaration)", "exit_code": 2}}


def setup_targets(ctx):
    for tid in ("container-a", "unrelated"):
        ctx.inventory.add(Target(tid, tid, "containers", transport="fixture", in_scope=False))
    ctx.inventory.save()


@pytest.fixture
def prepared(ctx, monkeypatch):
    setup_targets(ctx)
    for name in ("transport_for", "adapter_for"):
        monkeypatch.setattr(ctx, name, Mock(side_effect=AssertionError("no live connection")))
    for name in ("start", "run"):
        monkeypatch.setattr(ctx.scanner, name, Mock(side_effect=AssertionError("no scanner execution")))
    monkeypatch.setattr(ctx.engine, "propose", Mock(side_effect=AssertionError("no proposal")))
    return ctx


def load(ctx, *, actor=ACTOR, data=None, declaration=None):
    return scap.import_results(ctx, xml() if data is None else data,
                               manifest() if declaration is None else declaration, actor=actor)


def auth(ctx, **kw):
    return enable_auth(ctx, node=["import", "export", "audit"], grants=[
        {"actions": ["import", "read", "export"], "target_ids": ["container-a"]}], **kw)


def test_preserves_all_raw_states_and_explicit_container_identity(prepared):
    receipt = load(prepared)
    findings = [f for f in prepared.store.current_findings() if "raw_result" in f.collection_provenance]
    assert receipt["imported_count"] == 6 and not receipt["result_scope_complete"]
    assert receipt["compliance_claim"] is False and receipt["platform_applicability"] == "unverified"
    assert {f.host for f in findings} == {"container-a"}
    assert {f.source for f in findings} == {"openscap-container"}
    assert [f.status.value for f in sorted(findings, key=lambda f: f.rule_id)] == [
        "not_a_finding", "open", "error", "not_applicable", "not_reviewed", "not_reviewed"]
    assert {f.collection_provenance["raw_result"] for f in findings} == set(receipt["result_counts"])
    assert all(f.collection_provenance["provenance"] == manifest()["provenance"] for f in findings)
    assert all(not f.fix_ref and not f.fix_script for f in findings)
    assert prepared.store.load_scan_run(receipt["scan_id"])["coverage_incomplete"] is True
    assert all(not t.in_scope for t in prepared.inventory.all())


@pytest.mark.parametrize("results,expected,missing", [(["pass"], 2, ["r1"]),
    (["notselected"], 1, []), (["notapplicable"], 1, []), (["fixed", "informational"], 2, [])])
def test_missing_unselected_and_nonfinding_results_are_not_certification(prepared, results, expected, missing):
    receipt = load(prepared, data=xml(results), declaration=manifest(expected))
    assert receipt["missing_rule_ids"] == missing and receipt["compliance_claim"] is False
    assert prepared.store.load_scan_run(receipt["scan_id"])["coverage_incomplete"] is True
    if missing or "notselected" in results or "informational" in results:
        assert not receipt["result_scope_complete"]
        assert any(f.status.value == "not_reviewed" for f in prepared.store.current_findings())


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-le", "utf-16-be"])
@pytest.mark.parametrize("declaration", [
    '<!DOCTYPE Benchmark [<!ENTITY secret "private-secret">]>',
    '<!DOCTYPE Benchmark SYSTEM "file:///private-secret">',
    '<!DOCTYPE Benchmark [<!ENTITY % p SYSTEM "https://invalid.test/secret">%p;]>',
])
def test_rejects_dtd_entities_before_expansion(encoding, declaration):
    text = '<?xml version="1.0" encoding="' + encoding + '"?>' + declaration + xml().decode()
    with pytest.raises(scap.ScapImportError, match="invalid or unsafe"):
        scap.parse_results(text.encode(encoding), manifest())


@pytest.mark.parametrize("transform", [
    lambda s: s.replace('</TestResult>', '</TestResult>' + s[s.index('<TestResult'):s.index('</Benchmark>')]),
    lambda s: s.replace('id="result-1"', 'id="wrong"'),
    lambda s: s.replace('idref="profile"', 'idref="wrong"'),
    lambda s: s.replace('id="benchmark"', 'id="wrong"', 1),
    lambda s: s.replace('<benchmark id="benchmark"', '<benchmark id="wrong"'),
    lambda s: s.replace('<result>pass</result>', '<result>pass</result><result>fail</result>'),
    lambda s: s.replace('<result>pass</result>', '<result><foo/>pass</result>'),
    lambda s: s.replace('<result>pass</result>', '<result>PASS</result>'),
    lambda s: s.replace('idref="r1"', 'idref="r0"'),
    lambda s: s.replace('id="r1"', 'id="r0"'),
    lambda s: s.replace('<result>pass', '<result xmlns="urn:foreign">pass'),
    lambda s: s.replace('<TestResult', '<wrapper><TestResult').replace('</TestResult>', '</TestResult></wrapper>'),
    lambda s: s.replace('<profile idref="profile"/>', '<profile idref="profile"/><profile idref="profile"/>'),
    lambda s: '<arf>' + s + '</arf>',
    lambda s: s.replace(' xmlns="' + NS + '"', ''),
    lambda s: s[:-10],
])
def test_rejects_ambiguous_or_malformed_xml(transform):
    with pytest.raises(scap.ScapImportError):
        scap.parse_results(transform(xml().decode()).encode(), manifest())


@pytest.mark.parametrize("limit", ["MAX_XML_BYTES", "MAX_DEPTH", "MAX_ELEMENTS", "MAX_FIELD", "MAX_RESULTS"])
def test_source_caps(limit, monkeypatch):
    monkeypatch.setattr(scap, limit, 2)
    with pytest.raises(scap.ScapImportError):
        scap.parse_results(xml(), manifest())


@pytest.mark.parametrize("mutation", [
    lambda m: m.update(path="/private-secret"), lambda m: m.pop("provenance"),
    lambda m: m.update(target_id=" container-a"), lambda m: m.update(expected_rule_ids=["r0", "r0"]),
    lambda m: m.update(expected_rule_ids=[]), lambda m: m["provenance"].update(exit_code=True),
    lambda m: m["provenance"].update(engine="other"), lambda m: m["provenance"].update(image_digest="latest"),
    lambda m: m.update(source_id="invalid\ud800"), lambda m: m.update(source_id="invalid\x00"),
])
def test_manifest_exactness(mutation):
    value = manifest()
    mutation(value)
    with pytest.raises(scap.ScapImportError):
        scap.validate_manifest(value)


def test_duplicate_json_keys():
    with pytest.raises(scap.ScapImportError):
        scap.parse_manifest(b'{"target_id":"a","target_id":"b"}')


@pytest.mark.parametrize("baseline", [False, True])
def test_repeat_history_and_current_overlay(prepared, baseline):
    prior = Finding(host="unrelated", source="hunt", rule_id="risk", title="Keep this risk", severity="high",
                    status="open", scan_id="prior")
    prepared.store.save_findings("prior", [prior])
    prepared.store.save_scan_run(ScanRun(id="prior", targets=["unrelated"], status="done",
        rule_filter=None if baseline else ["risk"]).to_dict())
    first = load(prepared)
    original = prepared.store.load_scan_run(first["scan_id"])
    revised = load(prepared, data=xml(["fail", "fail", "error", "notapplicable", "notchecked", "unknown"]))
    repeated = load(prepared)
    assert repeated == {**first, "repeated": True}
    assert prepared.store.load_scan_run(first["scan_id"]) == original
    assert len(prepared.store.list_scan_runs()) == 3
    current = {f.rule_id: f for f in prepared.store.current_findings()}
    assert current["r0"].status.value == "open" and current["r0"].scan_id == revised["scan_id"]
    assert current["risk"].id == prior.id
    assert next(f for f in prepared.store.load_findings(first["scan_id"]) if f.rule_id == "r0").status.value == "not_a_finding"
    from cyberthunder.report.onepager import resolve_scan
    assert {f.id for f in resolve_scan(prepared, None)[2]} == {f.id for f in current.values()}


@pytest.mark.parametrize("change", ["source_id", "test_result_id", "image_ref"])
def test_distinct_source_testresult_and_container_do_not_collide(prepared, change):
    first = load(prepared)
    decl = manifest()
    data = xml()
    if change == "image_ref":
        decl["provenance"][change] = "another-image"
    else:
        decl[change] = "another-source"
        if change == "test_result_id":
            data = xml(test_id="another-source")
    second = load(prepared, data=data, declaration=decl)
    assert first["scan_id"] != second["scan_id"]
    assert len(prepared.store.current_findings()) == 14


@pytest.mark.parametrize("node,actions", [([], ["read", "import"]), (["import"], ["read"]), (["import"], ["import"])])
def test_requires_node_and_exact_resource_grants(prepared, node, actions):
    p = enable_auth(prepared, node=node, grants=[{"actions": actions, "target_ids": ["container-a"]}])
    with principal_scope(p), pytest.raises(PermissionError):
        load(prepared, actor=p.actor)
    assert not prepared.store.list_scan_runs() and not prepared.store.current_findings()


@pytest.mark.parametrize("bad", ["raw_actor", "wrong_actor", "expired", "role", "revoked_session"])
def test_no_raw_actor_or_stale_principal_bypass(prepared, bad):
    p = auth(prepared)
    actor = p.actor
    validity = None
    if bad == "raw_actor":
        p = None
    elif bad == "wrong_actor":
        actor = ACTOR
    elif bad == "expired":
        p = replace(p, expires_at=time.time() - 1)
    elif bad == "role":
        p = replace(p, roles=("viewer",))
    else:
        validity = Mock(side_effect=PermissionError("revoked"))
    with principal_scope(p, validity=validity), pytest.raises(PermissionError):
        load(prepared, actor=actor)
    assert not prepared.store.list_scan_runs()


@pytest.mark.parametrize("point", ["parse", "stage", "audit"])
@pytest.mark.parametrize("change", ["revoke", "kill", "reuse", "move"])
def test_rechecks_at_publication_boundaries(prepared, monkeypatch, point, change):
    p = auth(prepared)
    def change_state():
        if change == "revoke":
            revoke(prepared)
        elif change == "kill":
            (prepared.store.root / "KILL").write_text("stop")
        elif change == "reuse":
            prepared.inventory.remove("container-a")
            prepared.inventory.add(Target("container-a", "Replacement", "containers", transport="fixture"))
            prepared.inventory.save()
        else:
            prepared.inventory.get("container-a").environment = "another"
            prepared.inventory.save()
    if point == "parse":
        original = scap.parse_results
        def wrapped(*args, **kw):
            result = original(*args, **kw)
            change_state()
            return result
        monkeypatch.setattr(scap, "parse_results", wrapped)
    elif point == "stage":
        original = prepared.store.save_findings
        def wrapped(*args, **kw):
            original(*args, **kw)
            change_state()
        monkeypatch.setattr(prepared.store, "save_findings", wrapped)
    else:
        original = prepared.audit.append
        def wrapped(action, *args, **kw):
            result = original(action, *args, **kw)
            if action == "ingest.scap.publish":
                change_state()
            return result
        monkeypatch.setattr(prepared.audit, "append", wrapped)
    from cyberthunder.control.killswitch import KillSwitchEngaged
    with principal_scope(p), pytest.raises((PermissionError, KillSwitchEngaged)):
        load(prepared, actor=p.actor)
    assert not prepared.store.list_scan_runs() and not prepared.store.current_findings()


@pytest.mark.parametrize("published", [False, True])
@pytest.mark.parametrize("change", ["account", "reuse", "move", "revoke"])
def test_repeat_and_interrupted_receipt_ownership(prepared, monkeypatch, published, change):
    p = auth(prepared)
    with principal_scope(p):
        if published:
            load(prepared, actor=p.actor)
        else:
            with monkeypatch.context() as m:
                m.setattr(prepared.store, "save_scan_run", Mock(side_effect=OSError("private-secret")))
                with pytest.raises(OSError, match="storage is unavailable"):
                    load(prepared, actor=p.actor)
    if change == "account":
        p = auth(prepared, subject="second-account")
    elif change == "reuse":
        prepared.inventory.remove("container-a")
        prepared.inventory.add(Target("container-a", "Replacement", "containers", transport="fixture"))
        prepared.inventory.save()
    elif change == "move":
        prepared.inventory.get("container-a").environment = "another"
        prepared.inventory.save()
    else:
        revoke(prepared)
    with principal_scope(p), pytest.raises(PermissionError):
        load(prepared, actor=p.actor)
    assert len(prepared.store.list_scan_runs()) == int(published)


def test_interrupted_publication_can_resume_for_same_owner(prepared, monkeypatch):
    with monkeypatch.context() as m:
        m.setattr(prepared.store, "save_scan_run", Mock(side_effect=OSError("private-secret")))
        with pytest.raises(OSError):
            load(prepared)
    assert not prepared.store.current_findings() and not prepared.store.list_scan_runs()
    receipt = load(prepared)
    assert not receipt["repeated"] and len(prepared.store.current_findings()) == 7
    assert load(prepared)["repeated"]


def test_existing_native_fixture_is_imported_without_reclassifying_platform(prepared):
    data = (Path(__file__).resolve().parents[1] / "fixtures/scap/linux_disa/oscap_results.xml").read_bytes()
    declaration = manifest()
    declaration.update(test_result_id="xccdf_org.open-scap_testresult_xccdf_mil.disa.stig_profile_MAC-1_Classified",
        benchmark_id="xccdf_mil.disa.stig_benchmark_RHEL_9_STIG", profile_id="xccdf_mil.disa.stig_profile_MAC-1_Classified",
        expected_rule_ids=["xccdf_mil.disa.stig_rule_SV-257947r1044853_rule", "xccdf_mil.disa.stig_rule_SV-258094r1045179_rule"])
    receipt = load(prepared, data=data, declaration=declaration)
    assert receipt["imported_count"] == 2 and receipt["result_scope_complete"]
    assert not receipt["compliance_claim"]
    assert {f.asset_type for f in prepared.store.current_findings()} == {"containers"}


@pytest.mark.parametrize("exit_code,end", [(1, True), (0, False), (137, True)])
def test_pass_only_engine_failure_remains_visible_in_reports(prepared, exit_code, end):
    declaration = manifest(1)
    declaration["provenance"]["exit_code"] = exit_code
    receipt = load(prepared, data=xml(["pass"], end=end), declaration=declaration)
    assert not receipt["result_scope_complete"] and not receipt["evaluation_finished"]
    from cyberthunder.report.assurance import build_assurance
    counts = build_assurance(prepared, prepared.store.current_findings())["counts"]
    assert counts["scanner_pass"] == 1 and counts["scanner_error"] == 1


def test_later_completed_same_evaluation_updates_coverage_and_rules(prepared):
    declaration = manifest(1)
    declaration["provenance"]["exit_code"] = 1
    load(prepared, data=xml(["fail"], end=False), declaration=declaration)
    declaration["provenance"]["exit_code"] = 0
    receipt = load(prepared, data=xml(["pass"]), declaration=declaration)
    current = prepared.store.current_findings()
    assert receipt["result_scope_complete"] and len(current) == 2
    assert {f.status.value for f in current} == {"not_a_finding", "not_reviewed"}
    assert next(f for f in current if f.rule_id == "r0").collected_at == "2026-11-05T12:00:00Z"


def test_verified_workload_import_requires_same_current_resource_grants(prepared):
    p = replace(auth(prepared), kind="workload")
    with principal_scope(p):
        receipt = load(prepared, actor=p.actor)
        assert load(prepared, actor=p.actor)["repeated"]
        revoke(prepared)
        with pytest.raises(PermissionError):
            load(prepared, actor=p.actor)
    assert prepared.store.load_scan_run(receipt["scan_id"])["requested_by"] == p.actor


def test_standalone_testresult_and_utf16_supported():
    source = xml().decode()
    source = source[source.index("<TestResult"):source.index("</Benchmark>")]
    source = source.replace("<TestResult ", f'<TestResult xmlns="{NS}" ', 1)
    data = ('<?xml version="1.0" encoding="UTF-16"?>' + source).encode("utf-16")
    rows, coverage = scap.parse_results(data, manifest())
    assert len(rows) == 6 and not coverage["compliance_claim"]


@pytest.mark.parametrize("data", [b"", b"<Benchmark/>", b"not xml"])
def test_rejection_has_no_persisted_observation(prepared, data):
    with pytest.raises(scap.ScapImportError):
        load(prepared, data=data)
    assert not prepared.store.list_scan_runs() and not prepared.store.current_findings()
    assert not prepared.store.list_json(prepared.store.scans_dir, "*/findings.json")


def test_unknown_target_is_not_created(prepared):
    declaration = manifest()
    declaration["target_id"] = "DO-NOT-MAP-THIS-HOST"
    with pytest.raises(scap.ScapImportError):
        load(prepared, declaration=declaration)
    assert {t.id for t in prepared.inventory.all()} == {"container-a", "unrelated"}
    assert not prepared.store.list_scan_runs()


def test_concurrent_exact_repeats_publish_once(prepared):
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = list(pool.map(lambda _: load(prepared), range(2)))
    assert sorted(r["repeated"] for r in receipts) == [False, True]
    assert len({r["scan_id"] for r in receipts}) == 1
    assert len(prepared.store.list_scan_runs()) == 1


def test_invalid_completion_timestamp_is_rejected():
    with pytest.raises(scap.ScapImportError, match="timestamp"):
        scap.parse_results(xml().replace(b"2026-11-05T12:00:00Z", b"not-a-time"), manifest())
