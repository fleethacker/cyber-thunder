"""Findings list/detail history is scoped to the account and original target generation."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json

import pytest

from cyberthunder.control.principal import principal_scope
from cyberthunder.findings.reassessment import ReassessmentView
from cyberthunder.inventory.targets import Target
from tests.findings.test_reassessment import OLD, LATER, NEWEST, observation, save_run, seed
from tests.security.test_identity_boundary import verified_app, headers, identity

URL = "/api/v1/findings"


def detail(client, fid, **kwargs):
    response = client.get(f"{URL}/{fid}", **kwargs)
    assert response.status_code == 200, response.text
    return response.json()


def test_list_detail_historical_and_pagination_share_the_derived_result(client, ctx):
    f = seed(ctx)
    save_run(ctx, findings=[f])
    save_run(ctx, "newest", at=NEWEST)
    page = client.get(URL, params={"limit": 1, "status": "open", "sort_by": "collected_at"}).json()
    item = page["findings"][0]
    assert item["reassessment"] == detail(client, f.id)["reassessment"]
    assert item["reassessment"]["latest_attempt"]["scan_id"] == "newest"
    assert item["collected_at"] == OLD and item["source"] == "native" and item["scan_id"] == "base"
    assert item["scanner_status"] == item["status"] == "open"
    historical = client.get(URL, params={"scan_id": "later"}).json()["findings"][0]
    assert historical["reassessment"] == detail(client, f.id, params={"scan_id": "later"})["reassessment"]
    assert historical["reassessment"]["latest_attempt"]["scan_id"] == "later"
    assert detail(client, f.id, params={"scan_id": "base"})["reassessment"]["status"] == "no_known_gap"
    assert page["summary"]["total"] == page["total"] == page["unfiltered_total"] == 1


@pytest.mark.parametrize("lifecycle", ["reviewed", "verified", "rolled_back"])
def test_decisions_confidence_and_rollback_semantics_are_unchanged(client, ctx, lifecycle, monkeypatch):
    from cyberthunder.findings import confidence
    confidence_now = datetime.now(timezone.utc)
    assess_confidence = confidence.assess_for_context
    monkeypatch.setattr(confidence, "assess_for_context", lambda context, finding, **kw:
                        assess_confidence(context, finding, now=confidence_now))
    f = seed(ctx, status="not_a_finding" if lifecycle == "rolled_back" else "open")
    if lifecycle == "reviewed":
        from cyberthunder.findings.review import ReviewService
        service = ReviewService(ctx)
        summary = service.summary(f)
        service.save(f, actor="Joshua Ott", disposition="false_positive", reason="Manual evidence review",
                     expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                     expected_revision=summary["revision"], evidence_fingerprint=summary["evidence_fingerprint"])
    else:
        p = ctx.gate.propose(actor="Joshua Ott", finding_id=f.id, host=f.host, title="Fixture", fix_ref="fixture",
                             fix_preview="test", rollback_plan="restore", risk="test")
        ctx.gate.approve(p.id, "Joshua Ott")
        ctx.gate.start_apply(p.id, "Joshua Ott")
        ctx.gate.applied(p.id)
        ctx.gate.verified(p.id)
        if lifecycle == "rolled_back":
            ctx.gate.rolled_back(p.id, "Joshua Ott")
    before = detail(client, f.id)
    observations = deepcopy(ctx.store.load_findings("base")[0].to_dict())
    save_run(ctx)
    after = detail(client, f.id)
    assert after["reassessment"]["status"] == "not_reassessed"
    for field in ("scanner_status", "status", "review", "remediated", "rollback", "needs_rescan", "proposal", "evidence", "collected_at"):
        assert after[field] == before[field], field
    assert after["confidence"] == before["confidence"]
    assert ctx.store.load_findings("base")[0].to_dict() == observations
    if lifecycle == "rolled_back":
        assert after["needs_rescan"] and after["status"] == "not_reviewed" and after["remediated"] is None


def owned_observation(ctx):
    f = observation()
    save_run(ctx, "base", at=OLD, findings=[f], coverage_incomplete=False, scheduling=None)
    return ctx.store.load_findings("base")[0]


def test_unauthorized_and_mixed_runs_cannot_change_badge_or_leak_metadata(verified_app):
    ctx, _, tokens, client, _ = verified_app
    f = owned_observation(ctx)
    h = headers(tokens)
    save_run(ctx)
    expected = detail(client, f.id, headers=h)["reassessment"]
    for sid, targets in (("private-beta", ["beta"]), ("private-mixed", ["alpha", "beta"])):
        save_run(ctx, sid, at=NEWEST, targets=targets)
        doc = detail(client, f.id, headers=h)
        assert doc["reassessment"] == expected
        assert "private-" not in json.dumps(doc["reassessment"])
        assert "beta" not in json.dumps(doc["reassessment"])
        page = client.get(URL, headers=h).json()
        item = next(row for row in page["findings"] if row["id"] == f.id)
        assert item["reassessment"] == expected
        assert "private-" not in json.dumps(page)
    assert client.get(f"{URL}/{f.id}", headers=headers(tokens, identity("second-user"))).status_code == 403
    assert client.get(URL, params={"scan_id": "private-mixed"}, headers=h).status_code == 403


@pytest.mark.parametrize("change", ["move", "move_back", "delete", "reuse"])
def test_reassigned_or_reused_target_ids_cannot_grant_observation_history(verified_app, change):
    ctx, _, tokens, client, _ = verified_app
    f = owned_observation(ctx)
    save_run(ctx)
    target = ctx.inventory.get("alpha")
    if change in {"move", "move_back"}:
        target.environment = "beta"
        ctx.inventory.add(target)
        ctx.inventory.save()
        if change == "move_back":
            target.environment = "alpha"
            ctx.inventory.add(target)
            ctx.inventory.save()
    else:
        ctx.inventory.remove("alpha")
        ctx.inventory.save()
        if change == "reuse":
            ctx.inventory.add_new(Target("alpha", "Replacement", "linux", transport="simulated", simulated=True, environment="alpha"))
    h = headers(tokens)
    assert client.get(f"{URL}/{f.id}", headers=h).status_code == 403
    assert all(row["id"] != f.id for row in client.get(URL, headers=h).json()["findings"])
    with principal_scope(identity()):
        hidden = ReassessmentView(ctx).assess(f.to_dict())
        assert hidden["latest_attempt"] is None
        assert hidden["observation"] == {"observed_at": None, "source": None, "scan_id": None}
    if change == "reuse":
        fresh = replace(f, scan_id="replacement", authorization_scope=None)
        save_run(ctx, "replacement", at=OLD, findings=[fresh])
        assert detail(client, f.id, headers=h)["reassessment"]["status"] == "no_known_gap"


@pytest.mark.parametrize("ownership", [None, [], [{"target_id": "alpha"}]])
def test_missing_or_malformed_historical_run_ownership_is_ignored(verified_app, ownership):
    ctx, _, tokens, client, _ = verified_app
    f = owned_observation(ctx)
    expected = detail(client, f.id, headers=headers(tokens))["reassessment"]
    save_run(ctx)
    path = ctx.store.scans_dir / "later" / "run.json"
    doc = ctx.store.read_json(path)
    doc["authorization_scopes"] = ownership
    ctx.store.write_json(path, doc)
    assert detail(client, f.id, headers=headers(tokens))["reassessment"] == expected


def test_account_grant_revocation_is_rechecked_without_cross_request_cache(verified_app):
    ctx, _, tokens, client, _ = verified_app
    f = owned_observation(ctx)
    save_run(ctx)
    h = headers(tokens)
    assert detail(client, f.id, headers=h)["reassessment"]["status"] == "not_reassessed"
    policy = json.loads(ctx.access.path.read_text())
    policy["entries"][0]["grants"] = []
    ctx.access.path.write_text(json.dumps(policy))
    assert client.get(f"{URL}/{f.id}", headers=h).status_code == 403
    assert client.get(URL, headers=h).json()["findings"] == []


def test_revoked_run_access_is_rechecked_even_inside_a_request(verified_app):
    ctx, _, _, _, _ = verified_app
    f = owned_observation(ctx)
    save_run(ctx, "mixed", targets=["alpha", "beta"])
    policy = json.loads(ctx.access.path.read_text())
    original = deepcopy(policy)
    policy["entries"][0]["grants"][0]["target_ids"] = ["alpha", "beta"]
    ctx.access.path.write_text(json.dumps(policy))
    with principal_scope(identity()):
        view = ReassessmentView(ctx)
        assert view.assess(f.to_dict())["status"] == "not_reassessed"
        ctx.access.path.write_text(json.dumps(original))
        assert view.assess(f.to_dict())["status"] == "no_known_gap"


def test_retention_metadata_is_account_scoped_and_list_detail_consistent(verified_app):
    ctx, _, tokens, client, _ = verified_app
    f = owned_observation(ctx)
    h = headers(tokens)
    metadata = {"partial_targets": ["alpha"], "retained_incomplete_observations": {"alpha": [f.id]}}
    before = detail(client, f.id, headers=h)
    save_run(ctx, "hidden-retention", targets=["alpha", "beta"], scheduling=metadata)
    assert detail(client, f.id, headers=h)["reassessment"] == before["reassessment"]
    save_run(ctx, "visible-retention", at=NEWEST, scheduling=metadata)
    after = detail(client, f.id, headers=h)
    assert after["reassessment"]["reason"] == "retained_incomplete_observation"
    for key in ("scanner_status", "status", "review", "evidence", "source", "collected_at", "scan_id"):
        assert after[key] == before[key]
    page = client.get(URL, headers=h).json()
    assert next(row for row in page["findings"] if row["id"] == f.id)["reassessment"] == after["reassessment"]
    assert "hidden-retention" not in json.dumps(after["reassessment"])
