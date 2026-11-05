"""Review router tests using temporary state and an in-process HTTP client only."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
import pytest

from cyberthunder.api.app import create_app
from cyberthunder.findings.review import MAX_REASON_LENGTH, MAX_SUPPORTING_EVIDENCE_LENGTH
from cyberthunder.findings.schema import Finding

ACTOR = {"X-Actor": "ITC Rivera"}


def seed(ctx, finding, scan_id="scan-1", at="2026-11-05T10:00:00Z", **run):
    ctx.store.save_scan_run({"id": scan_id, "started_at": at, "status": "done", **run})
    ctx.store.save_findings(scan_id, [finding])


@pytest.fixture
def review_api(ctx, tmp_path):
    ctx.settings.ui_dist = tmp_path / "no-ui"
    ctx.settings.scan_interval_s = 0
    ctx.settings.content_check_interval_s = 0
    ctx.settings.bootstrap_cluster_target = False
    finding = Finding(host="range-01", source="openscap", rule_id="SV-12345r1_rule", title="SSH configuration",
                      severity="high", status="open", evidence="PermitRootLogin yes", scan_id="scan-1")
    seed(ctx, finding)
    app = create_app(ctx)
    with TestClient(app) as client:
        yield client, ctx, finding, f"/api/v1/findings/{finding.id}/review"


def payload(client, path, **changes):
    view = client.get(path).json()
    return {"disposition": "false_positive", "reason": "Verified against local export",
            "supporting_evidence": "Reviewed configuration", "expected_revision": view["revision"],
            "evidence_fingerprint": view["evidence_fingerprint"],
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=2)).isoformat(), **changes}


def test_response_contract_roundtrip_and_reversal(review_api):
    client, ctx, finding, path = review_api
    initial = client.get(path)
    assert initial.status_code == 200
    assert set(initial.json()) == {"disposition", "active", "suppressed", "revision", "evidence_fingerprint",
                                   "current", "history_count", "reopened_reason", "identity_verified", "history"}
    assert initial.json()["current"] is None
    original = ctx.store.load_findings("scan-1")[0].to_dict()
    saved = client.put(path, json=payload(client, path), headers=ACTOR)
    assert saved.status_code == 200, saved.text
    view = saved.json()
    assert view["active"] and view["suppressed"] and view["revision"] == 1
    assert view["current"]["identity_verified"] is False
    assert view["current"]["reviewed_by"] == "ITC Rivera"
    assert {"id", "disposition", "reason", "supporting_evidence", "expires_at", "reviewed_at", "reviewed_by",
            "identity_verified", "scope", "evidence_fingerprint"} <= set(view["current"])
    assert ctx.store.load_findings("scan-1")[0].to_dict() == original
    reversal = client.put(path, json=payload(client, path, disposition="unreviewed", expires_at=None,
                                           reason="New investigation"), headers=ACTOR)
    assert reversal.status_code == 200, reversal.text
    assert reversal.json()["revision"] == 2 and not reversal.json()["suppressed"]
    assert reversal.json()["history"][0] == view["current"]
    assert client.get(path).json() == reversal.json()


def test_stale_revision_and_changed_evidence_return_409(review_api):
    client, ctx, finding, path = review_api
    old = payload(client, path)
    assert client.put(path, json=old, headers=ACTOR).status_code == 200
    stale = client.put(path, json=old, headers=ACTOR)
    assert stale.status_code == 409 and "revision" in stale.json()["detail"]
    current = payload(client, path)
    seed(ctx, replace(finding, evidence="changed", scan_id="scan-2"), "scan-2", "2026-11-05T11:00:00Z",
         trigger="verify")
    stale = client.put(path, json=current, headers=ACTOR)
    assert stale.status_code == 409 and any(word in stale.json()["detail"] for word in ("evidence", "revision"))
    reopened = client.get(path).json()
    assert reopened["disposition"] == "unreviewed" and not reopened["suppressed"]
    assert reopened["history_count"] == 1 and reopened["reopened_reason"]


def test_service_rechecks_after_router_read(review_api, monkeypatch):
    from cyberthunder.api.routes import finding_reviews
    client, ctx, finding, path = review_api
    body = payload(client, path)
    original = finding_reviews._finding
    def racing_lookup(*args, **kwargs):
        stale = original(*args, **kwargs)
        seed(ctx, replace(finding, benchmark_release="new content"))
        return stale
    monkeypatch.setattr(finding_reviews, "_finding", racing_lookup)
    response = client.put(path, json=body, headers=ACTOR)
    assert response.status_code == 409, response.text


def test_historical_get_is_read_only_and_historical_put_is_refused(review_api, monkeypatch):
    client, ctx, finding, path = review_api
    body = payload(client, path)
    assert client.put(path, json=body, headers=ACTOR).status_code == 200
    seed(ctx, replace(finding, evidence="changed"), "scan-2", "2026-11-05T11:00:00Z")
    monkeypatch.setattr(ctx.store, "write_json", lambda *a, **kw: pytest.fail("GET wrote state"))
    monkeypatch.setattr(ctx.audit, "append", lambda *a, **kw: pytest.fail("GET wrote audit"))
    historical = client.get(path, params={"scan_id": "scan-1"})
    assert historical.status_code == 200 and not historical.json()["suppressed"]
    assert historical.json()["reopened_reason"]
    assert not client.get(path).json()["suppressed"]
    assert client.put(path + "?scan_id=scan-1", json=body, headers=ACTOR).status_code == 400
    assert client.get(path + "?scan_id=missing").status_code == 404
    assert client.get(path, params={"scan_id": "../../outside"}).status_code == 400


def test_missing_current_finding_cannot_be_reviewed_via_history_fallback(review_api):
    client, ctx, finding, path = review_api
    body = payload(client, path)
    ctx.store.save_scan_run({"id": "scan-2", "started_at": "2026-11-05T11:00:00Z", "status": "done"})
    ctx.store.save_findings("scan-2", [])
    assert client.get(path).status_code == 404
    assert client.put(path, json=body, headers=ACTOR).status_code == 404
    assert client.get(path + "?scan_id=scan-1").status_code == 200


@pytest.mark.parametrize("changes", [
    {"disposition": "not_a_finding"}, {"disposition": "unreviewed", "reason": " "},
    {"reason": None}, {"reason": ""}, {"reason": "x" * (MAX_REASON_LENGTH + 1)},
    {"supporting_evidence": "x" * (MAX_SUPPORTING_EVIDENCE_LENGTH + 1)},
    {"expires_at": None}, {"expires_at": ""}, {"expires_at": "2026-12-01"},
    {"expires_at": "2026-12-01T00:00:00"}, {"expires_at": 9999999999},
    {"expires_at": "2001-01-01T00:00:00Z"}, {"expected_revision": True},
    {"expected_revision": "0"}, {"evidence_fingerprint": "bad"}, {"unexpected": "field"},
])
def test_bad_input_is_400_without_side_effects(review_api, changes):
    client, ctx, _, path = review_api
    response = client.put(path, json=payload(client, path, **changes), headers=ACTOR)
    assert response.status_code == 400, response.text
    assert client.get(path).json()["history_count"] == 0
    assert not list(ctx.audit.records())


@pytest.mark.parametrize("missing", ["reason", "disposition", "expected_revision", "evidence_fingerprint"])
def test_required_fields(review_api, missing):
    client, _, _, path = review_api
    body = payload(client, path)
    body.pop(missing)
    assert client.put(path, json=body, headers=ACTOR).status_code == 400


@pytest.mark.parametrize("actor", [None, "", "system", "agent:worker", "policy:maintenance"])
def test_actor_dependency_rejects_missing_or_reserved_names(review_api, actor):
    client, _, _, path = review_api
    response = client.put(path, json=payload(client, path), headers={"X-Actor": actor} if actor is not None else {})
    assert response.status_code == 400
    assert client.get(path).json()["revision"] == 0


def test_kill_guard_blocks_save_but_allows_history(review_api):
    client, ctx, _, path = review_api
    body = payload(client, path)
    ctx.killswitch.engage("ITC Rivera", "hold changes")
    response = client.put(path, json=body, headers=ACTOR)
    assert response.status_code == 423
    assert client.get(path).status_code == 200
    assert client.get(path).json()["history_count"] == 0


def test_apply_lifecycle_guard_makes_put_conflict_and_get_remains_available(review_api):
    from cyberthunder.findings.review import ReviewService
    client, ctx, finding, path = review_api
    body = payload(client, path)
    with ReviewService(ctx).remediation_guard(finding):
        response = client.put(path, json=body, headers=ACTOR)
        assert response.status_code == 409 and "lifecycle is busy" in response.json()["detail"]
        assert client.get(path).status_code == 200
        assert client.get(path).json()["history_count"] == 0
    assert client.put(path, json=body, headers=ACTOR).status_code == 200


def test_recurrence_invalidates_without_get_and_requires_new_revision(review_api):
    client, ctx, finding, path = review_api
    initial = client.put(path, json=payload(client, path), headers=ACTOR).json()
    stale = payload(client, path)
    seed(ctx, replace(finding, status="not_a_finding"), "scan-2", "2026-11-05T11:00:00Z")
    seed(ctx, finding, "scan-3", "2026-11-05T12:00:00Z")
    assert client.put(path, json=stale, headers=ACTOR).status_code == 409
    view = client.get(path).json()
    assert view["revision"] == 2 and view["history"] == initial["history"]
    assert not view["suppressed"] and view["disposition"] == "unreviewed"
    fresh = client.put(path, json=payload(client, path), headers=ACTOR)
    assert fresh.status_code == 200 and fresh.json()["revision"] == 3
    assert fresh.json()["suppressed"]
