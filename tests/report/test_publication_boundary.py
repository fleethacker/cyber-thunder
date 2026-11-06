"""Release boundary regressions with real policy/ownership and no approval-feature dependency."""
from contextlib import contextmanager
import json
import socket
import time

import pytest

from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.control.access import AccessPolicy
from cyberthunder.control.principal import Principal, principal_scope
from cyberthunder.findings.schema import Finding
from cyberthunder.inventory.targets import Target
from cyberthunder.report import checklist
from cyberthunder.report.service import ReportService
from cyberthunder.security.resources import target_scope


@pytest.fixture
def boundary(state_dir, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("report fixtures must not contact a target or external service")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(AppContext, "transport_for", forbidden)
    ctx = AppContext(Settings(state_dir=state_dir, auth_mode="oidc", security_mode="range",
                              llm_backend="template", auto_propose=False, explain_precompute=False))
    for name in ("alpha", "beta"):
        ctx.inventory.add(Target(name, name, "linux", "simulated", simulated=True, environment=name))
    ctx.inventory.save()
    ctx.store.save_scan_run({"id": "boundary", "targets": ["alpha"], "status": "done",
                             "authorization_scopes": [target_scope(ctx.inventory.get("alpha"))]})
    finding = Finding(host="alpha", source="fixture", rule_id="boundary-rule", title="Owned finding",
                      severity="high", status="open", evidence="Owned scanner evidence")
    finding.authorization_scope = target_scope(ctx.inventory.get("alpha"))
    ctx.store.save_findings("boundary", [finding])
    who = Principal("https://fixture.example", "exporter", "Exporter", roles=("auditor",),
                    expires_at=time.time() + 600)
    path = state_dir / "auth" / "access.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps({"version": 1, "entries": [{"issuer": who.issuer, "subject": who.subject,
        "node_actions": ["export", "audit"], "grants": [{"target_ids": ["alpha"], "actions": ["export"]}]}]}))
    path.chmod(0o600)
    ctx.access = AccessPolicy(path)
    yield ctx, who, path
    ctx.store.close()


def revoke(boundary, action):
    ctx, _, path = boundary
    if action == "ownership":
        ctx.inventory.get("alpha").environment = "moved"
        ctx.inventory.save()
        return
    policy = json.loads(path.read_text())
    entry = policy["entries"][0]
    if action == "target_export":
        entry["grants"][0]["actions"].remove("export")
    else:
        entry["node_actions"].remove(action)
    path.write_text(json.dumps(policy))


def no_saved_report(ctx):
    assert not list((ctx.store.root / "reports" / "history").glob("*.json"))


def test_audit_revocation_during_render_prevents_publication(boundary, monkeypatch):
    ctx, who, _ = boundary
    render = checklist.build_checklist
    def changed(*args, **kwargs):
        result = render(*args, **kwargs)
        revoke(boundary, "audit")
        return result
    monkeypatch.setattr(checklist, "build_checklist", changed)
    with principal_scope(who), pytest.raises(PermissionError):
        ReportService(ctx).checklist_cklb("boundary", "alpha")
    no_saved_report(ctx)


@pytest.mark.parametrize("action", ["audit", "export", "target_export", "ownership"])
def test_authority_rechecked_inside_history_writer_lock(boundary, monkeypatch, action):
    ctx, who, _ = boundary
    lock = ctx.store.files.lock
    @contextmanager
    def changed(name):
        with lock(name):
            if name == "report-history":
                revoke(boundary, action)
            yield
    monkeypatch.setattr(ctx.store.files, "lock", changed)
    with principal_scope(who), pytest.raises(PermissionError):
        ReportService(ctx).checklist_cklb("boundary", "alpha")
    no_saved_report(ctx)


def test_audit_revocation_after_save_still_blocks_return(boundary, monkeypatch):
    ctx, who, _ = boundary
    service = ReportService(ctx)
    audited = service._audited
    def changed(*args, **kwargs):
        audited(*args, **kwargs)
        revoke(boundary, "audit")
    monkeypatch.setattr(service, "_audited", changed)
    with principal_scope(who), pytest.raises(PermissionError):
        service.checklist_cklb("boundary", "alpha")


def raw_checklist(ctx, owner, comment):
    path = ctx.store.scans_dir / "boundary" / "raw" / owner / "original.cklb"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"target_data": {"host_name": "alpha"}, "stigs": [{"rules": [
        {"rule_id": "boundary-rule", "comments": comment, "status": "open"}]}]}))
    return path


def test_display_hostname_cannot_adopt_other_targets_raw_metadata(boundary, monkeypatch):
    ctx, who, _ = boundary
    path = raw_checklist(ctx, "beta", "OTHER-TARGET-PRIVATE-METADATA")
    before = path.read_bytes()
    read = type(path).read_text
    def guarded_read(candidate, *args, **kwargs):
        assert candidate != path, "other target raw metadata must not be opened"
        return read(candidate, *args, **kwargs)
    monkeypatch.setattr(type(path), "read_text", guarded_read)
    with principal_scope(who):
        doc = ReportService(ctx).checklist_cklb("boundary", "alpha")
    assert "OTHER-TARGET-PRIVATE-METADATA" not in json.dumps(doc)
    assert path.read_bytes() == before


@pytest.mark.parametrize("alias", ["ALPHA", "alpha.", "alpha "])
def test_ambiguous_windows_raw_directory_names_are_refused(boundary, alias):
    ctx, who, _ = boundary
    target = Target(alias, "Other target", "linux", "simulated", simulated=True, environment="other")
    ctx.inventory.add(target)
    ctx.inventory.save()
    run = ctx.store.load_scan_run("boundary")
    run["targets"].append(alias)
    run["authorization_scopes"].append(target_scope(target))
    ctx.store.save_scan_run(run)
    raw_checklist(ctx, "alpha", "Ambiguous path metadata")
    with principal_scope(who), pytest.raises(PermissionError):
        ReportService(ctx).checklist_cklb("boundary", "alpha")
    no_saved_report(ctx)


def test_owned_checklist_still_preserves_original_comments(boundary):
    ctx, who, _ = boundary
    path = raw_checklist(ctx, "alpha", "Owned original comment")
    before = path.read_bytes()
    with principal_scope(who):
        doc = ReportService(ctx).checklist_cklb("boundary", "alpha")
    assert "Owned original comment" in doc["stigs"][0]["rules"][0]["comments"]
    assert path.read_bytes() == before
