"""Isolated signed catalog metadata reads on both document backends."""
import copy
import hashlib
import json
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from cyberthunder import catalog_rule_metadata as metadata
from cyberthunder.adapters.base import Collected
from cyberthunder.control.principal import principal_scope
from cyberthunder.findings.schema import Finding
from cyberthunder.findings.review import evidence_fingerprint, review_scope
from cyberthunder.findings.confidence import assess
from cyberthunder.ingest.content import publication as pub
from cyberthunder.ingest.content.index import Entry
from cyberthunder.inventory.targets import Target
from tests.ingest.test_content_publication import accept
from tests.ingest.test_content_signatures import key_directory, signing, verified
from tests.ingest.test_content_uploads import benchmark


@pytest.fixture
def reader(verified):
    ctx, human = verified
    path = ctx.store.root / "auth/access.json"
    policy = json.loads(path.read_text())
    policy["entries"][0]["node_actions"].append("read")
    path.write_text(json.dumps(policy))
    return ctx, human


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("metadata tests must not contact a network")
    monkeypatch.setattr(socket.socket, "connect", forbidden)


def native(tmp_path, family="windows11"):
    asset, source, prefix, product, relative = metadata.FAMILIES[family]
    path = Path(metadata.__file__).parent / "adapters" / relative
    bundled = json.loads(path.read_bytes())
    rows = bundled["rules"] if isinstance(bundled, dict) else {r["stig_id"]: r for r in bundled}
    sid = next(s for s in rows if s.startswith(prefix))
    row = rows[sid]
    target = Target(id="metadata-target", name="Disposable target", asset_type=asset, transport="simulated",
                    simulated=True, options={"native_catalog_bindings": {family: {
                        "product_key": product, "benchmark_id": "Fixture_Benchmark"}}})
    finding = Finding(host=target.id, asset_type=asset, source=source, rule_id=row.get("rule_id") or sid,
                      rule_version=sid, title=row["title"], severity=row["severity"], status="not_a_finding",
                      benchmark="Bundled benchmark", benchmark_release="Bundled release", evidence="Native evidence",
                      fix_ref="library:original", check_text="Native check", fix_text="Native fix",
                      collection_provenance={"collector": "fixture"})
    return target, Collected(target.id, asset, str(tmp_path), modules=["check"]), finding


def package(tmp_path, target, finding, release=10, *, mode="match", product=None, bid="Fixture_Benchmark"):
    family = next(iter(target.options["native_catalog_bindings"]))
    data = benchmark(bid=bid, release=str(release)).replace(b"TEST-000001", finding.rule_version.encode())
    data = data.replace(b"SV-100001r1_rule", f"SV-100001r{release}_rule".encode())
    data = data.replace(b"Check the setting", f"Active title {release}".encode()).replace(b'severity="medium"', b'severity="high"')
    data = data.replace(b"</Rule>", b'<ident system="cci">CCI-000366</ident></Rule>')
    if mode == "missing":
        data = data.replace(finding.rule_version.encode(), b"UNRELATED-01-000001")
    elif mode == "withdrawn":
        data = data.replace(b"</Rule>", b'<status date="2026-01-01">deprecated</status></Rule>')
    elif mode == "duplicate":
        rule = data[data.index(b"<Rule "):data.index(b"</Rule>") + len(b"</Rule>")]
        data = data.replace(b"</Group>", rule.replace(b"SV-100001", b"SV-100002") + b"</Group>")
    elif mode == "multiple_versions":
        data = data.replace(b"</Rule>", b"<version>OTHER-01-000001</version></Rule>")
    path = tmp_path / f"fixture-{release}.xml"
    path.write_bytes(data)
    return path, Entry(filename=path.name, url="", host="", title="Disposable fixture", kind="manual_stig",
                       product_key=product or metadata.FAMILIES[family][3], version=(2, release), version_label=f"V2R{release}")


def annotate(reader, target, collected, finding):
    ctx, human = reader
    with principal_scope(human):
        metadata.annotate_native_findings(ctx, target, collected, [finding], actor=human.actor)
    return finding.catalog_rule_metadata


@pytest.mark.parametrize("family", metadata.FAMILIES)
def test_signed_metadata_preserves_all_finding_semantics(reader, tmp_path, monkeypatch, family):
    ctx, _ = reader
    target, collected, finding = native(tmp_path, family)
    before = finding.to_dict()
    fingerprint, scope = evidence_fingerprint(finding), review_scope(finding)
    confidence = assess(finding, now=finding.collected_at)
    path, entry = package(tmp_path, target, finding)
    committed = accept(reader, (path, entry))
    def forbidden(*args, **kwargs):
        pytest.fail("imported content must never execute")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = annotate(reader, target, collected, finding)
    assert result["mapping_status"] == "matched" and result["assessment"] == "not_assessed"
    assert result["rule"] == {"rule_id": "SV-100001r10_rule", "stig_id": finding.rule_version,
                              "group_id": "V-100001", "title": "Active title 10", "severity": "high", "cci": ["CCI-000366"]}
    catalog = result["catalog"]
    assert catalog["release"] == [2, 10] and catalog["benchmark_version"] == "2"
    assert catalog["benchmark_release"] == "Release: 10 Benchmark Date: 01 Jan 2025"
    assert catalog["publication_generation"] == result["snapshot_generation"] == committed["generation"]
    assert catalog["source_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert catalog["catalog_sha256"] == hashlib.sha256(Path(committed["ingest"]["catalog_path"]).read_bytes()).hexdigest()
    assert catalog["authenticity"]["operator_attested"] and not catalog["authenticity"]["disa_signature"]
    after = finding.to_dict()
    after[metadata.KEY] = None
    assert after == before
    assert evidence_fingerprint(finding) == fingerprint and review_scope(finding) == scope
    assert assess(finding, now=finding.collected_at) == confidence
    assert finding.check_text == "Native check" and finding.fix_text == "Native fix"
    assert "this must never execute" not in json.dumps(result)
    assert collected.raw[metadata.KEY]["coverage_added"] == 0
    ctx.store.save_findings("metadata-original", [finding])
    assert ctx.store.load_findings("metadata-original")[0].to_dict() == finding.to_dict()


def test_upgrade_renamed_rule_id_does_not_rewrite_history(reader, tmp_path):
    ctx, _ = reader
    target, collected, finding = native(tmp_path, "linux_rhel9")
    original = copy.deepcopy(finding)
    accept(reader, package(tmp_path, target, finding))
    first = annotate(reader, target, collected, finding)
    ctx.store.save_findings("old", [finding])
    saved = ctx.store.load_findings("old")[0].to_dict()
    accept(reader, package(tmp_path, target, original, 11))
    second = annotate(reader, target, collected, original)
    assert first["rule"]["rule_id"] == "SV-100001r10_rule"
    assert second["rule"]["rule_id"] == "SV-100001r11_rule"
    assert second["rule"]["title"] == "Active title 11"
    assert first["catalog"]["source_sha256"] != second["catalog"]["source_sha256"]
    assert finding.id == original.id and finding.rule_id == original.rule_id
    assert evidence_fingerprint(finding) == evidence_fingerprint(original)
    assert ctx.store.load_findings("old")[0].to_dict() == saved


@pytest.mark.parametrize("mode,status", [("missing", "missing"), ("withdrawn", "withdrawn"),
                                         ("duplicate", "ambiguous"), ("multiple_versions", "ambiguous")])
def test_unassessed_mapping_never_claims_catalog_pass(reader, tmp_path, mode, status):
    target, collected, finding = native(tmp_path)
    accept(reader, package(tmp_path, target, finding, mode=mode))
    result = annotate(reader, target, collected, finding)
    assert result["mapping_status"] == status and result["assessment"] == "not_assessed"
    assert result["native"]["status"] == "not_a_finding"
    assert collected.raw[metadata.KEY]["counts"] == {status: 1}
    if status in {"missing", "ambiguous"}:
        assert "rule" not in result


@pytest.mark.parametrize("configured", [False, True])
def test_bundled_fallback_is_explicit(reader, tmp_path, configured):
    target, collected, finding = native(tmp_path)
    if not configured:
        target.options = {}
    result = annotate(reader, target, collected, finding)
    assert result["mapping_status"] == ("no_active_catalog" if configured else "not_configured")
    assert result["metadata_source"] == "bundled_extract"
    path = Path(metadata.__file__).parent / result["bundled"]["path"]
    assert result["bundled"]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_product_mismatch_is_an_error_not_fallback(reader, tmp_path):
    target, collected, finding = native(tmp_path)
    accept(reader, package(tmp_path, target, finding, product="MS_Windows_Server_2022"))
    with pytest.raises(pub.PublicationError, match="product"):
        annotate(reader, target, collected, finding)
    assert finding.catalog_rule_metadata is None


def test_exact_lineage_not_title_or_stig_id_similarity(reader, tmp_path):
    target, collected, finding = native(tmp_path)
    accept(reader, package(tmp_path, target, finding, bid="Another_Benchmark"))
    assert annotate(reader, target, collected, finding)["mapping_status"] == "no_active_catalog"


@pytest.mark.parametrize("bad", [None, [], {"unknown": {}}, {"windows11": {"product_key": "MS_Windows_10", "benchmark_id": "x"}},
                                {"windows11": {"product_key": "MS_Windows_11", "benchmark_id": "x", "release": "V2R10"}}])
def test_invalid_bindings_and_implicit_pins_are_refused(reader, tmp_path, bad):
    target, collected, finding = native(tmp_path)
    target.options["native_catalog_bindings"] = bad
    with pytest.raises(ValueError):
        annotate(reader, target, collected, finding)


@pytest.mark.parametrize("fault", ["artifact", "missing", "ledger", "legacy"])
def test_integrity_errors_cannot_become_bundled_success(reader, tmp_path, fault):
    ctx, _ = reader
    target, collected, finding = native(tmp_path)
    if fault == "legacy":
        path = ctx.store.root / "content/files/unindexed.xml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"unindexed")
    else:
        record = accept(reader, package(tmp_path, target, finding))
        path = Path(record["ingest"]["catalog_path"])
        if fault == "artifact":
            path.write_bytes(b"changed")
        elif fault == "missing":
            path.unlink()
        else:
            ctx.store.delete_json(ctx.store.root / "content/index.json")
    with pytest.raises(pub.PublicationError):
        annotate(reader, target, collected, finding)
    assert finding.catalog_rule_metadata is None


def test_read_permission_and_revocation_fail_closed(reader, tmp_path, monkeypatch):
    ctx, human = reader
    target, collected, finding = native(tmp_path)
    accept(reader, package(tmp_path, target, finding))
    # An import-capable identity without node read authority is insufficient.
    policy_path = ctx.store.root / "auth/access.json"
    policy = json.loads(policy_path.read_text())
    policy["entries"][0]["node_actions"].remove("read")
    policy_path.write_text(json.dumps(policy))
    with pytest.raises(PermissionError):
        annotate(reader, target, collected, finding)
    policy["entries"][0]["node_actions"].append("read")
    policy_path.write_text(json.dumps(policy))
    original = ctx.authorize
    calls = []
    def revoke(action, **kwargs):
        calls.append(action)
        if len(calls) == 2:
            policy["entries"][0]["node_actions"].remove("read")
            policy_path.write_text(json.dumps(policy))
        return original(action, **kwargs)
    monkeypatch.setattr(ctx, "authorize", revoke)
    with pytest.raises(PermissionError):
        annotate(reader, target, collected, finding)
    assert finding.catalog_rule_metadata is None


def test_existing_read_scope_pins_metadata_across_publication(reader, tmp_path):
    ctx, _ = reader
    target, collected, finding = native(tmp_path)
    first = accept(reader, package(tmp_path, target, finding))
    next_package = package(tmp_path, target, finding, 11)
    with pub.read_scope(ctx.store):
        with ThreadPoolExecutor() as pool:
            second = pool.submit(accept, reader, next_package).result()
        result = annotate(reader, target, collected, finding)
        assert result["snapshot_generation"] == first["generation"]
        assert result["catalog"]["release"] == [2, 10]
    assert pub.generation(ctx.store) == second["generation"]


def test_pinned_reader_rechecks_exact_bytes(reader, tmp_path):
    ctx, _ = reader
    target, collected, finding = native(tmp_path)
    record = accept(reader, package(tmp_path, target, finding))
    with pub.read_scope(ctx.store):
        Path(record["ingest"]["catalog_path"]).write_bytes(b"changed after pin")
        with pytest.raises(pub.PublicationError, match="changed during"):
            annotate(reader, target, collected, finding)


def test_development_active_catalog_never_claims_authorized_metadata(reader, tmp_path):
    ctx, human = reader
    target, collected, finding = native(tmp_path)
    path, entry = package(tmp_path, target, finding)
    ctx.settings.auth_mode = "dev"
    record = ctx.ingest.content._accept(path, entry, source="imported", actor=human.actor,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(), size=path.stat().st_size, etag=None)
    assert record["active"] and record["authenticity"]["status"] == "unsigned_dev"
    result = annotate(reader, target, collected, finding)
    assert result["mapping_status"] == "untrusted_active_catalog" and "rule" not in result


@pytest.mark.parametrize("source", ["openscap", "scc", "evaluate-stig", "powerstig", "hunt", "cve"])
def test_external_scanner_and_non_native_metadata_are_untouched(reader, tmp_path, source):
    ctx, human = reader
    target, collected, finding = native(tmp_path)
    accept(reader, package(tmp_path, target, finding))
    finding.source = source
    before = finding.to_dict()
    with principal_scope(human):
        metadata.annotate_native_findings(ctx, target, collected, [finding], actor=human.actor)
    assert finding.to_dict() == before and collected.raw[metadata.KEY]["counts"] == {}


def test_scan_integration_preserves_prior_results_on_catalog_failure(reader, tmp_path):
    ctx, human = reader
    target, _, finding = native(tmp_path)
    record = accept(reader, package(tmp_path, target, finding))
    ctx.settings.auth_mode = "dev"
    ctx.inventory.add(target)
    ctx.inventory.save()
    run = ctx.scanner.start([target.id], modules=["check"], requested_by=human.actor, background=False)
    assert run.status == "done" and run.results[target.id].status == "done"
    saved = [f.to_dict() for f in ctx.store.load_findings(run.id)]
    annotations = [f[metadata.KEY] for f in saved if f.get(metadata.KEY)]
    assert annotations and any(m["mapping_status"] == "matched" for m in annotations)
    Path(record["ingest"]["catalog_path"]).write_bytes(b"changed")
    failed = ctx.scanner.start([target.id], modules=["check"], requested_by=human.actor, background=False)
    assert failed.status == "error" and failed.results[target.id].status == "error"
    assert not ctx.store.load_findings(failed.id)
    assert [f.to_dict() for f in ctx.store.load_findings(run.id)] == saved


@pytest.mark.parametrize("family", ["linux_rhel9", "windows11", "cisco_ndm", "kubernetes"])
def test_actual_native_rule_output_keeps_identity_evidence_and_fixes(reader, tmp_path, family):
    ctx, human = reader
    target, collected, _ = native(tmp_path, family)
    target.options = {}
    if family == "linux_rhel9":
        from cyberthunder.adapters.linux.checks import native_findings
        findings = native_findings(target, collected)
    elif family == "windows11":
        from cyberthunder.adapters.windows.checks import evaluate
        findings = evaluate(target, {})
    elif family == "cisco_ndm":
        from cyberthunder.adapters.cisco.adapter import CiscoIOSAdapter, CONFIG_ARTIFACT
        collected.artifacts[CONFIG_ARTIFACT] = str(Path(__file__).parents[1] / "fixtures/cisco/clean_router.cfg")
        findings = CiscoIOSAdapter().check(target, collected)
    else:
        from cyberthunder.adapters.kubernetes.checks import run_checks
        findings = run_checks(target, collected)
    before = [f.to_dict() for f in findings]
    with principal_scope(human):
        metadata.annotate_native_findings(ctx, target, collected, findings, actor=human.actor)
    assert collected.raw[metadata.KEY]["counts"]["not_configured"] > 0
    for original, finding in zip(before, findings, strict=True):
        actual = finding.to_dict()
        actual[metadata.KEY] = None
        assert actual == original
        assert evidence_fingerprint(finding) == evidence_fingerprint(Finding.from_dict(original))


def test_existing_annotation_cannot_be_replaced(reader, tmp_path):
    target, collected, finding = native(tmp_path)
    annotate(reader, target, collected, finding)
    before = finding.to_dict()
    with pytest.raises(ValueError, match="already attached"):
        annotate(reader, target, collected, finding)
    assert finding.to_dict() == before
