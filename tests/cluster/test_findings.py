"""Fixture-only managed database scanning and normalized cluster observations."""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import subprocess
from types import SimpleNamespace

import pytest

from cyberthunder.cluster.findings import parse_report
from cyberthunder.findings.confidence import assess
from cyberthunder.findings.review import ReviewService
from cyberthunder.findings.schema import Finding
from cyberthunder.store import StateStore
from tests.cluster.test_guardrails import (
    ACTOR, APP_IMAGE, HELPER_IMAGE, completed, ctx, external_calls, fake_tools, target,
)


def positives(store):
    return [f for f in store.current_findings() if f.source == "trivy" and f.is_open]


def test_snapshot_is_pinned_and_calls_cannot_update_databases(ctx, target, external_calls, monkeypatch):
    ctx.settings.trivy_skip_db_update = False
    entered, exited, snapshots = [], [], []
    real_context = ctx.vulnerabilities.scan_context

    @contextmanager
    def pinned():
        with real_context() as snapshot:
            entered.append(True)
            snapshots.append(snapshot)
            yield snapshot
            exited.append(True)

    ctx.vulnerabilities.scan_context = pinned
    monkeypatch.setenv("TRIVY_SKIP_DB_UPDATE", "false")
    monkeypatch.setenv("TRIVY_DB_REPOSITORY", "registry.invalid/unapproved")
    monkeypatch.setenv("TRIVY_CONFIG", "unapproved.yaml")
    monkeypatch.setenv("TRIVY_SEVERITY", "CRITICAL")
    monkeypatch.setenv("TRIVY_IGNORE_UNFIXED", "true")

    def run(argv, **kwargs):
        assert entered and not exited
        if argv[0] == "trivy":
            assert all(flag in argv for flag in ("--skip-db-update", "--skip-java-db-update",
                                                 "--offline-scan", "--skip-version-check"))
            assert argv[argv.index("--cache-dir") + 1] == str(snapshots[0]["cache_dir"])
            assert argv[argv.index("--scanners") + 1] == "vuln"
            assert argv[argv.index("--cache-backend") + 1] == "memory"
            assert not any(key.upper().startswith("TRIVY_") for key in kwargs["env"])
            assert argv[-2] == "--"
        return fake_tools(argv, **kwargs)

    external_calls[0].side_effect = run
    original = ctx.store.save_scan_run

    def publish(run):
        assert entered and not exited
        return original(run)

    monkeypatch.setattr(ctx.store, "save_scan_run", publish)
    doc = ctx.cluster.scan(actor=ACTOR)
    assert len(entered) == len(exited) == 1
    assert doc["status"] == "done"
    assert "cache_dir" not in json.dumps(doc)
    assert len(positives(ctx.store)) == 3  # one shared image, two separate deployment observations
    assert ctx.store.load_scan_run(doc["id"])["trigger"] == "cluster_vulnerabilities"
    assert ctx.scanner.get(doc["id"]).findings_count == 3
    assert ctx.scanner.list()[0].progress == {"done": 1, "total": 1}
    reopened = StateStore(ctx.store.root, backend=ctx.store.backend_name)
    assert len(positives(reopened)) == 3
    reopened.close()


def test_normalization_has_provenance_and_no_automatic_patch_fix(ctx, target, external_calls):
    def run(argv, **kwargs):
        result = fake_tools(argv, **kwargs)
        if argv[0] == "trivy":
            report = json.loads(result.stdout)
            report["Metadata"] = {"RepoDigests": ["registry.invalid/app@sha256:" + "a" * 64],
                                  "ImageID": "sha256:" + "b" * 64}
            report["Results"][0]["Vulnerabilities"][0]["DataSource"] = {
                "ID": "debian", "Name": "Debian", "URL": "https://security-tracker.debian.org/"}
            return completed(argv, report)
        return result

    external_calls[0].side_effect = run
    ctx.cluster.scan(actor=ACTOR)
    finding = next(f for f in positives(ctx.store) if f.ref_ids("cve") == ["CVE-2026-12345"])
    provenance = finding.collection_provenance
    assert finding.host == target.id and finding.asset_type == "kubernetes"
    assert finding.fix_ref is finding.fix_script is finding.fix_ansible is None
    assert provenance["package"]["name"] == "fixture-package"
    assert provenance["package"]["version"] == "1" and provenance["package"]["fixed_version"] == "2"
    assert provenance["workload"]["namespace"] == "mission"
    assert provenance["image"]["reference"] == APP_IMAGE
    assert provenance["image"]["repo_digests"]
    assert provenance["image"]["digest"] == "sha256:" + "a" * 64
    assert provenance["database"]["generation"] == "fixture-generation"
    assert provenance["database"]["provenance"] == "offline_import"
    assert provenance["advisory"]["source"]["ID"] == "debian"
    assert assess(finding)["grade"] == "low"
    assert assess(finding)["evidence"]["version_only"] is True
    assert assess(finding)["evidence"]["authenticated"] is None


@pytest.mark.parametrize("broken", [{}, {"Results": None}, {"Results": []}, [],
                                     {"Results": [{"Target": "unknown"}]},
                                     {"Results": [{"Target": "file", "Class": "config", "Type": "yaml"}]}])
def test_empty_and_unsupported_output_never_clears_prior(ctx, target, external_calls, broken):
    external_calls[0].side_effect = fake_tools
    ctx.cluster.scan(actor=ACTOR)
    previous = {f.id for f in positives(ctx.store)}

    def run(argv, **kwargs):
        return completed(argv, broken) if argv[0] == "trivy" else fake_tools(argv, **kwargs)

    external_calls[0].side_effect = run
    doc = ctx.cluster.scan(actor=ACTOR)
    assert doc["status"] == "partial" and doc["errors"]
    assert {f.id for f in positives(ctx.store)} == previous
    assert any(f.status.value == "not_reviewed" for f in ctx.store.current_findings())
    assert all(p["risk_rating"] == "unknown" for p in doc["namespaces"] if p["images"])


@pytest.mark.parametrize("failure", ["missing-db", "bad-json", "process", "timeout", "missing-binary"])
def test_scan_failures_preserve_prior_and_publish_error(ctx, target, external_calls, failure):
    external_calls[0].side_effect = fake_tools
    ctx.cluster.scan(actor=ACTOR)
    previous = {f.id for f in positives(ctx.store)}
    if failure == "missing-db":
        @contextmanager
        def missing():
            raise RuntimeError("private DB path or other diagnostic")
            yield  # pragma: no cover

        ctx.vulnerabilities = SimpleNamespace(scan_context=missing)

    def run(argv, **kwargs):
        if argv[0] != "trivy":
            return fake_tools(argv, **kwargs)
        if failure == "timeout":
            raise subprocess.TimeoutExpired(argv, 1)
        if failure == "missing-binary":
            raise FileNotFoundError()
        return subprocess.CompletedProcess(argv, 1 if failure == "process" else 0,
                                           stdout="not json", stderr="private registry credential diagnostic")

    external_calls[0].reset_mock(side_effect=True)
    external_calls[0].side_effect = run
    doc = ctx.cluster.scan(actor=ACTOR)
    assert {f.id for f in positives(ctx.store)} == previous
    assert doc["status"] == "partial"
    assert any(f.status.value == "error" for f in ctx.store.current_findings())
    assert "private" not in json.dumps(doc)
    if failure == "missing-db":
        assert all(call.args[0][0] != "trivy" for call in external_calls[0].call_args_list)


def test_success_reconciles_only_observed_workload_image_sections(ctx, target, external_calls):
    external_calls[0].side_effect = fake_tools
    ctx.cluster.scan(actor=ACTOR)
    before = positives(ctx.store)
    # A subsequent inventory cannot assess deployment "two"; the helper image fails entirely.
    def run(argv, **kwargs):
        if argv[0] == "trivy":
            if argv[-1] == HELPER_IMAGE:
                return subprocess.CompletedProcess(argv, 1, "", "unavailable")
            return completed(argv, {"Results": [{"Target": "fixture-image", "Class": "os-pkgs", "Type": "debian"}]})
        result = fake_tools(argv, **kwargs)
        if "deployments" in argv:
            doc = json.loads(result.stdout)
            doc["items"] = doc["items"][:1]
            return completed(argv, doc)
        return result

    external_calls[0].side_effect = run
    ctx.cluster.scan(actor=ACTOR)
    expected = {f.id for f in before if f.collection_provenance["workload"]["name"] != "one"}
    assert {f.id for f in positives(ctx.store)} == expected
    stig = Finding(host="host", source="native", rule_id="r", title="r", severity="high", status="open")
    ctx.store.save_findings("later-full", [stig])
    ctx.store.save_scan_run({"id": "later-full", "started_at": "9999-01-01T00:00:00Z", "status": "done"})
    assert {f.id for f in positives(ctx.store)} == expected
    assert stig.id in {f.id for f in ctx.store.current_findings()}


def test_stale_database_does_not_clear_absent_matches(ctx, target, external_calls):
    external_calls[0].side_effect = fake_tools
    ctx.cluster.scan(actor=ACTOR)
    previous = {f.id for f in positives(ctx.store)}
    real_context = ctx.vulnerabilities.scan_context

    @contextmanager
    def stale():
        with real_context() as snapshot:
            snapshot["state"] = "stale"
            snapshot["databases"][0]["stale"] = True
            yield snapshot

    ctx.vulnerabilities.scan_context = stale

    def run(argv, **kwargs):
        if argv[0] == "trivy":
            return completed(argv, {"Results": [{"Target": "fixture-image", "Class": "os-pkgs", "Type": "debian"}]})
        return fake_tools(argv, **kwargs)

    external_calls[0].side_effect = run
    doc = ctx.cluster.scan(actor=ACTOR)
    assert doc["database"]["state"] == "stale" and doc["status"] == "partial"
    assert {f.id for f in positives(ctx.store)} == previous
    assert any(f.status.value == "not_reviewed" for f in ctx.store.current_findings())


def test_stale_positive_provenance_has_unknown_confidence(ctx, target, external_calls):
    real_context = ctx.vulnerabilities.scan_context

    @contextmanager
    def stale():
        with real_context() as snapshot:
            snapshot["state"] = "stale"
            snapshot["databases"][0]["stale"] = True
            yield snapshot

    ctx.vulnerabilities.scan_context = stale
    external_calls[0].side_effect = fake_tools
    ctx.cluster.scan(actor=ACTOR)
    for finding in positives(ctx.store):
        provenance = finding.collection_provenance
        assert provenance["version_only"] is True and provenance["partial"] is True
        assert provenance["complete"] is False and provenance["collection_status"] == "partial"
        assert provenance["database"]["state"] == "stale"
        confidence = assess(finding)
        assert confidence["grade"] == "unknown" and confidence["evidence"]["partial"] is True


def test_database_generation_change_invalidates_review_durably(ctx, target, external_calls):
    external_calls[0].side_effect = fake_tools
    ctx.cluster.scan(actor=ACTOR)
    finding = positives(ctx.store)[0]
    reviews = ReviewService(ctx)
    summary = reviews.summary(finding)
    reviews.save(finding, actor=ACTOR, disposition="false_positive", reason="Reviewed applicability",
                 supporting_evidence="Fixture vendor guidance", expected_revision=summary["revision"],
                 evidence_fingerprint=summary["evidence_fingerprint"],
                 expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat())
    real_context = ctx.vulnerabilities.scan_context

    @contextmanager
    def changed():
        with real_context() as snapshot:
            snapshot["generation"] = "new-generation"
            yield snapshot

    ctx.vulnerabilities.scan_context = changed
    ctx.cluster.scan(actor=ACTOR)
    current = next(f for f in positives(ctx.store) if f.id == finding.id)
    assert not reviews.summary(current)["suppressed"]
    assert reviews.summary(current)["revision"] == 2
    # Even the old identical evidence cannot silently restore the dismissed review.
    assert not reviews.summary(finding)["suppressed"]


def test_malformed_section_does_not_authorize_its_reconciliation():
    section = {"Target": "fixture", "Class": "os-pkgs", "Type": "debian"}
    invalid = {**deepcopy(section), "Vulnerabilities": [{"VulnerabilityID": "CVE-2026-12345"}]}
    report = parse_report({"Results": [section, invalid]})
    assert report["errors"] and report["sections"] == []


def test_eol_operating_system_retains_matches_but_cannot_clear_absences():
    report = json.loads(fake_tools(["trivy", APP_IMAGE]).stdout)
    report["Metadata"] = {"OS": {"Family": "debian", "EOSL": True}}
    parsed = parse_report(report)
    assert parsed["vulnerabilities"] and parsed["errors"] and parsed["sections"] == []


def test_changed_target_binding_cannot_reconcile_previous_cluster(ctx, target, external_calls):
    external_calls[0].side_effect = fake_tools
    ctx.cluster.scan(actor=ACTOR)
    previous = {f.id for f in positives(ctx.store)}
    target.options["context"] = "another-approved-cluster"
    ctx.inventory.save()

    def run(argv, **kwargs):
        if argv[0] == "trivy":
            return completed(argv, {"Results": [{"Target": "fixture-image", "Class": "os-pkgs", "Type": "debian"}]})
        return fake_tools(argv, **kwargs)

    external_calls[0].side_effect = run
    ctx.cluster.scan(actor=ACTOR)
    assert {f.id for f in positives(ctx.store)} == previous


def test_missing_result_section_retains_that_section(ctx, target, external_calls):
    def first(argv, **kwargs):
        result = fake_tools(argv, **kwargs)
        if argv[0] == "trivy":
            report = json.loads(result.stdout)
            language = deepcopy(report["Results"][0])
            language.update(Target="requirements.txt", Class="lang-pkgs", Type="pip")
            report["Results"].append(language)
            return completed(argv, report)
        return result

    external_calls[0].side_effect = first
    ctx.cluster.scan(actor=ACTOR)
    before = positives(ctx.store)

    def second(argv, **kwargs):
        if argv[0] == "trivy":
            return completed(argv, {"Results": [{"Target": "fixture-image", "Class": "os-pkgs", "Type": "debian"}]})
        return fake_tools(argv, **kwargs)

    external_calls[0].side_effect = second
    result = ctx.cluster.scan(actor=ACTOR)
    assert result["status"] == "partial"
    assert all(p["risk_rating"] == "unknown" for p in result["namespaces"] if p["images"])
    assert {f.id for f in positives(ctx.store)} == {
        f.id for f in before if f.collection_provenance["result"]["class"] == "lang-pkgs"}


def test_missing_workload_identity_is_incomplete(ctx, target, external_calls):
    def run(argv, **kwargs):
        if "deployments" in argv:
            return completed(argv, {"items": [{"metadata": {}, "spec": {}}]})
        return fake_tools(argv, **kwargs)

    external_calls[0].side_effect = run
    doc = ctx.cluster.scan(actor=ACTOR)
    assert doc["status"] == "partial" and doc["survey"]["errors"]
    assert any(f.rule_id.startswith("cluster-survey:") for f in ctx.store.current_findings())


def test_fatal_survey_error_keeps_prior_observations_and_publishes_failed_run(ctx, target, external_calls):
    external_calls[0].side_effect = fake_tools
    ctx.cluster.scan(actor=ACTOR)
    before = {f.id for f in positives(ctx.store)}
    external_calls[0].side_effect = OSError("fixture collection unavailable")
    with pytest.raises(OSError):
        ctx.cluster.scan(actor=ACTOR)
    assert {f.id for f in positives(ctx.store)} == before
    run = ctx.scanner.list()[0]
    assert run.status == "error" and run.results[target.id].errors
    assert any(f.status.value == "error" for f in ctx.store.current_findings())
