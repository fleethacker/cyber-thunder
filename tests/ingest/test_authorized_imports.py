"""Imports authorize destination hosts; stored bulletin rematches retain scan authority."""
from __future__ import annotations

from pathlib import Path

import pytest

from cyberthunder.control.principal import operation_scope, principal_scope
from cyberthunder.findings.schema import Finding
from cyberthunder.ingest import bulletin, scanner_results
from cyberthunder.inventory.targets import Target
from cyberthunder.scan import ScanRun
from tests.ingest.conftest import add_targets, write_collected
from tests.security.job_helpers import enable_auth, revoke

SAMPLE = Path(__file__).resolve().parents[1] / "fixtures" / "parsers" / "sample.nessus"
MAPPING = {"ws-014.enclave.example": "A", "10.20.1.30": "B"}
PACKAGES = [{"name": "fixture-package", "version": "1", "release": "1"}]
BULLETIN = {"id": "2026-A-0001", "title": "Fixture bulletin", "severity": "high",
            "affected": [{"package": "fixture-package", "versions_below": "2"}]}


def policy(ctx, hosts, *, node=("import",), action="import"):
    ctx.inventory.save()
    grants = [{"actions": [action], "target_ids": list(hosts)}] if hosts else []
    if action == "import" and ctx.inventory.all():
        grants.append({"actions": ["read"], "target_ids": [t.id for t in ctx.inventory.all()]})
    return enable_auth(ctx, node=node, grants=grants)


def load(ctx, principal):
    return ctx.ingest.import_scanner(SAMPLE.read_bytes(), MAPPING, actor=principal.actor)


@pytest.mark.parametrize("node,hosts", [([], ["A", "B"]), (["import"], ["A"]), (["import"], [])])
def test_scanner_import_denies_missing_node_or_any_destination_before_publication(ctx, node, hosts):
    add_targets(ctx, "A", "B")
    p = policy(ctx, hosts, node=node)
    with principal_scope(p), pytest.raises(PermissionError):
        load(ctx, p)
    assert ctx.store.list_scan_runs() == [] and ctx.store.current_findings() == []
    assert not ctx.store.list_json(ctx.store.scans_dir, "**/findings.json")


def test_scanner_import_accepts_explicit_destinations_and_rechecks_repeat(ctx):
    add_targets(ctx, "A", "B")
    p = policy(ctx, ["A", "B"])
    with principal_scope(p):
        result = load(ctx, p)
        assert result["imported_count"] == 5
        assert load(ctx, p)["repeated"] is True
        revoke(ctx)
        with pytest.raises(PermissionError):
            load(ctx, p)
    assert {f.host for f in ctx.store.load_findings(result["scan_id"])} == {"A", "B"}


def test_scanner_import_rechecks_after_parsing_and_preserves_denial(ctx, monkeypatch):
    add_targets(ctx, "A", "B")
    p = policy(ctx, ["A", "B"])
    parse = scanner_results.parse_nessus

    def revoke_after_parse(*args, **kwargs):
        findings = parse(*args, **kwargs)
        revoke(ctx)
        return findings

    monkeypatch.setattr(scanner_results, "parse_nessus", revoke_after_parse)
    with principal_scope(p), pytest.raises(PermissionError):
        load(ctx, p)
    assert ctx.store.list_scan_runs() == [] and ctx.store.current_findings() == []


def test_scanner_import_revocation_before_run_marker_leaves_no_visible_partial_scan(ctx, monkeypatch):
    add_targets(ctx, "A", "B")
    p = policy(ctx, ["A", "B"])
    save = ctx.store.save_findings

    def revoke_after_stage(*args, **kwargs):
        save(*args, **kwargs)
        revoke(ctx)

    monkeypatch.setattr(ctx.store, "save_findings", revoke_after_stage)
    with principal_scope(p), pytest.raises(PermissionError):
        load(ctx, p)
    assert ctx.store.list_scan_runs() == [] and ctx.store.current_findings() == []


def collected(ctx, hosts=("A", "B")):
    add_targets(ctx, *hosts)
    ctx.inventory.save()
    for tid in hosts:
        write_collected(ctx.store, "source-scan", tid, PACKAGES)
    ctx.store.save_scan_run(ScanRun(id="source-scan", targets=list(hosts), status="done").to_dict())


def test_new_bulletin_requires_import_on_every_matched_host(ctx):
    collected(ctx)
    p = policy(ctx, ["A"])
    with principal_scope(p), pytest.raises(PermissionError):
        ctx.ingest.ingest_bulletin(BULLETIN, actor=p.actor)
    assert [r["id"] for r in ctx.store.list_scan_runs()] == ["source-scan"]
    assert bulletin.list_bulletins(ctx.store) == []


def test_new_bulletin_publishes_when_node_and_all_host_imports_are_authorized(ctx):
    collected(ctx)
    p = policy(ctx, ["A", "B"])
    with principal_scope(p):
        result = ctx.ingest.ingest_bulletin(BULLETIN, actor=p.actor)
    assert set(result["hosts_affected"]) == {"A", "B"}
    assert len(ctx.store.load_findings(result["scan_id"])) == 2


def test_new_bulletin_without_findings_still_requires_node_import(ctx):
    p = policy(ctx, [], node=[])
    with principal_scope(p), pytest.raises(PermissionError):
        ctx.ingest.ingest_bulletin(BULLETIN, actor=p.actor)
    assert bulletin.list_bulletins(ctx.store) == []


def test_bulletin_revocation_before_run_marker_does_not_publish_empty_run_or_catalog(ctx, monkeypatch):
    collected(ctx, ("A",))
    p = policy(ctx, ["A"])
    save = ctx.store.save_findings

    def revoke_after_stage(*args, **kwargs):
        save(*args, **kwargs)
        revoke(ctx)

    monkeypatch.setattr(ctx.store, "save_findings", revoke_after_stage)
    with principal_scope(p), pytest.raises(PermissionError):
        ctx.ingest.ingest_bulletin(BULLETIN, actor=p.actor)
    assert [r["id"] for r in ctx.store.list_scan_runs()] == ["source-scan"]
    assert ctx.store.current_findings() == [] and bulletin.list_bulletins(ctx.store) == []


def test_full_scan_rematches_existing_bulletin_with_scan_only_and_initiating_actor(ctx):
    collected(ctx, ("A",))
    bulletin.save_bulletin(ctx.store, bulletin.parse_bulletin(BULLETIN))
    before = bulletin.list_bulletins(ctx.store)
    p = policy(ctx, ["A"], node=[], action="scan")
    ctx.settings.auto_propose = False
    run = ScanRun(id="source-scan", targets=["A"], requested_by=p.actor, status="done")
    with principal_scope(p), operation_scope("scan"):
        # Exercise the actual scanner callback, which intentionally supplies no actor argument.
        ctx.scanner._after_scan(run, [])
        with pytest.raises(PermissionError):
            ctx.ingest.ingest_bulletin(BULLETIN, actor=p.actor)
    assert "bulletin_rematch_error" not in run.summary
    assert run.summary["bulletins_rematched"]["findings"] == 1
    partial = ctx.store.load_scan_run(run.summary["bulletins_rematched"]["scan_id"])
    assert partial["requested_by"] == p.actor
    assert bulletin.list_bulletins(ctx.store) == before


def test_rematch_does_not_use_import_to_bypass_missing_scan_authority(ctx):
    collected(ctx, ("A",))
    bulletin.save_bulletin(ctx.store, bulletin.parse_bulletin(BULLETIN))
    p = policy(ctx, ["A"])
    with principal_scope(p), pytest.raises(PermissionError):
        ctx.ingest.rematch_all("source-scan")
    assert [r["id"] for r in ctx.store.list_scan_runs()] == ["source-scan"]


@pytest.mark.parametrize("change", ["missing_grant", "moved", "legacy", "authorized"])
def test_scanner_carry_forward_requires_authorized_historical_ownership(ctx, change):
    add_targets(ctx, "A", "B", "C")
    ctx.inventory.save()
    finding = Finding(host="C", source="acas", rule_id="old-rule", title="Private prior finding",
                      severity="high", status="open", scan_id="prior")
    ctx.store.save_findings("prior", [finding])
    ctx.store.save_scan_run(ScanRun(id="prior", targets=["C"], status="done", trigger="scanner_import",
                                  rule_filter=["old-rule"], findings_count=1).to_dict())
    if change == "legacy":
        doc = ctx.store.read_json(ctx.store.scans_dir / "prior" / "findings.json")
        for row in doc["findings"]:
            row.pop("authorization_scope", None)
        ctx.store.write_json(ctx.store.scans_dir / "prior" / "findings.json", doc)
    elif change == "moved":
        ctx.inventory.get("C").environment = "new-environment"
    p = policy(ctx, ["A", "B"] if change == "missing_grant" else ["A", "B", "C"])
    if change == "authorized":
        with principal_scope(p):
            result = load(ctx, p)
        assert result["carried_forward_count"] == 1
        retained = next(f for f in ctx.store.load_findings(result["scan_id"]) if f.host == "C")
        assert retained.authorization_scope == finding.authorization_scope
        return
    with principal_scope(p), pytest.raises(PermissionError):
        load(ctx, p)
    assert [r["id"] for r in ctx.store.list_scan_runs()] == ["prior"]


def test_scanner_repeat_cannot_return_historical_metadata_after_target_move(ctx):
    add_targets(ctx, "A", "B")
    p = policy(ctx, ["A", "B"])
    with principal_scope(p):
        result = load(ctx, p)
        ctx.inventory.get("B").environment = "new-environment"
        ctx.inventory.save()
        with pytest.raises(PermissionError):
            load(ctx, p)
    assert [r["id"] for r in ctx.store.list_scan_runs()] == [result["scan_id"]]


@pytest.mark.parametrize("entry", ["manual", "rematch"])
@pytest.mark.parametrize("change", ["moved", "reused", "legacy"])
def test_bulletins_cannot_reclassify_historical_raw_scan_data(ctx, entry, change):
    collected(ctx, ("A",))
    if change == "legacy":
        path = ctx.store.scans_dir / "source-scan" / "run.json"
        doc = ctx.store.read_json(path)
        doc.pop("authorization_scopes", None)
        ctx.store.write_json(path, doc)
    elif change == "moved":
        ctx.inventory.get("A").environment = "new-environment"
    else:
        ctx.inventory.remove("A")
        ctx.inventory.add(Target(id="A", name="Replacement", asset_type="linux", transport="fixture"))
    bulletin.save_bulletin(ctx.store, bulletin.parse_bulletin(BULLETIN))
    p = policy(ctx, ["A"], action="import" if entry == "manual" else "scan")
    with principal_scope(p), pytest.raises(PermissionError):
        if entry == "manual":
            ctx.ingest.ingest_bulletin(BULLETIN, actor=p.actor)
        else:
            ctx.ingest.rematch_all("source-scan")
    assert [r["id"] for r in ctx.store.list_scan_runs()] == ["source-scan"]
    assert ctx.store.current_findings() == []


def test_manual_bulletin_cannot_reveal_unreadable_checked_hosts(ctx):
    collected(ctx)
    p = enable_auth(ctx, node=["import"], grants=[{"actions": ["import"], "target_ids": ["A", "B"]}])
    with principal_scope(p), pytest.raises(PermissionError):
        ctx.ingest.ingest_bulletin(BULLETIN, actor=p.actor)
    assert bulletin.list_bulletins(ctx.store) == []
