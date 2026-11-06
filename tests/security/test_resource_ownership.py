"""Historical evidence cannot be reassigned by moving or reusing a target identifier."""
from copy import deepcopy
import json

import pytest

from cyberthunder.control.principal import principal_scope
from cyberthunder.findings.schema import Finding, Severity, Status
from cyberthunder.inventory.targets import Target
from cyberthunder.security.resources import capture, check_record, visible_record
from tests.security.test_identity_boundary import verified_app, identity, headers


@pytest.mark.parametrize("change", ["move", "delete", "reuse", "legacy"])
def test_saved_evidence_is_not_reclassified_from_current_inventory(verified_app, change):
    ctx, proposals, tokens, client, _ = verified_app
    original = ctx.inventory.get("alpha")
    finding = next(f for f in ctx.store.load_findings() if f.host == "alpha")
    if change == "move":
        original.environment = "beta"
        ctx.inventory.add(original)
        ctx.inventory.save()
    elif change in {"delete", "reuse"}:
        ctx.inventory.remove("alpha")
        ctx.inventory.save()
        if change == "reuse":
            ctx.inventory.add_new(Target("alpha", "replacement", "linux", transport="simulated",
                                         simulated=True, environment="alpha"))
    else:
        for path, field in ((ctx.store.scans_dir / "scan-both" / "run.json", "authorization_scopes"),):
            value = ctx.store.read_json(path)
            if value:
                value.pop(field, None)
                ctx.store.write_json(path, value)
        items = json.loads(ctx.store.proposals.read_text())
        for row in items:
            row.pop("authorization_scope", None)
        ctx.store.proposals.write_text(json.dumps(items))
        finding.authorization_scope = None
        doc = ctx.store.read_json(ctx.store.scans_dir / "scan-both" / "findings.json")
        for row in doc["findings"]:
            if row["host"] == "alpha":
                row.pop("authorization_scope", None)
        ctx.store.write_json(ctx.store.scans_dir / "scan-both" / "findings.json", doc)
    with principal_scope(identity()):
        assert not visible_record(ctx, finding)
        with pytest.raises(PermissionError):
            check_record(ctx, finding, "propose")
    # All failed lookups have the same public result as an inaccessible target.
    h = headers(tokens)
    assert client.get(f"/api/v1/findings/{finding.id}", headers=h).status_code == 403
    assert client.get("/api/v1/scans/scan-both", headers=h).status_code == 403
    assert client.post(f"/api/v1/proposals/{proposals['alpha'].id}/approve", headers=h,
                       json={}).status_code == 403


def test_scan_keeps_initial_ownership_if_target_moves_during_collection(verified_app):
    ctx, _, _, _, _ = verified_app
    ctx.store.save_scan_run({"id": "started", "targets": ["alpha"], "status": "running"})
    prior = deepcopy(ctx.store.load_scan_run("started")["authorization_scopes"])
    target = ctx.inventory.get("alpha")
    target.environment = "changed"
    ctx.inventory.add(target)
    ctx.inventory.save()
    finding = Finding(host="alpha", asset_type="linux", source="fixture", rule_id="changed",
                      title="Collected before move", severity=Severity.MEDIUM, status=Status.OPEN, scan_id="started")
    ctx.store.save_findings("started", [finding])
    ctx.store.save_scan_run({"id": "started", "targets": ["alpha"], "status": "done"})
    assert ctx.store.load_scan_run("started")["authorization_scopes"] == prior
    assert ctx.store.load_findings("started")[0].authorization_scope == prior[0]
    with principal_scope(identity()):
        assert not visible_record(ctx, finding)


@pytest.mark.parametrize("record", [
    {}, {"targets": [{}], "authorization_scopes": []},
    {"targets": ["alpha"], "authorization_scopes": [{"target_id": []}]},
    {"host": "beta", "authorization_scope": {"target_id": "alpha"}},
])
def test_missing_or_malformed_ownership_fails_closed(verified_app, record):
    ctx, _, _, _, _ = verified_app
    with principal_scope(identity()):
        assert not visible_record(ctx, record)
        with pytest.raises(PermissionError):
            check_record(ctx, record)


def test_outbox_filters_ownership_and_rechecks_export_before_staging(verified_app):
    ctx, _, _, _, _ = verified_app
    box = ctx.ingest.outbox
    ctx.settings.auth_mode = "dev"
    first = box.enqueue("report", "alpha.txt", b"alpha-only", {"authorization_scopes": capture(ctx, ["alpha"])})
    second = box.enqueue("report", "beta.txt", b"beta-only", {"authorization_scopes": capture(ctx, ["beta"])})
    legacy = box.enqueue("report", "legacy.txt", b"unclassified")
    ctx.settings.auth_mode = "oidc"
    policy = ctx.access.path
    data = json.loads(policy.read_text())
    data["entries"][0]["node_actions"] += ["read", "export"]
    policy.write_text(json.dumps(data))
    person = identity(roles=("auditor",))
    with principal_scope(person):
        assert [e["id"] for e in box.list()["pending"]] == [first["id"]]
        with pytest.raises(PermissionError):
            box.enqueue("report", "forbidden.txt", b"wrong owner",
                        {"authorization_scopes": capture(ctx, ["beta"])}, actor=person.actor)
        # Changing the grant between enqueue and flush must not stage the old payload.
        data["entries"][0]["grants"][0]["actions"] = ["read"]
        policy.write_text(json.dumps(data))
        assert box.sync(force=True, actor=person.actor)["sent"] == 0
        assert all((box.pending_dir / entry["id"]).exists() for entry in (first, second, legacy))


def test_new_target_generation_cannot_be_chosen_by_a_client(verified_app):
    ctx, _, _, _, _ = verified_app
    original = ctx.inventory.get("alpha")
    generation = original.authorization_id
    ctx.inventory.remove("alpha")
    ctx.inventory.save()
    ctx.inventory.add_new(original)
    assert ctx.inventory.get("alpha").authorization_id != generation
