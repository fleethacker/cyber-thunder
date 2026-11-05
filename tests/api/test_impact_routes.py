"""Assessment HTTP boundaries with real receipts and no model/network access."""
from copy import deepcopy
from datetime import datetime, timedelta
import socket
from uuid import uuid4

import pytest

from cyberthunder.api import util
from cyberthunder.control.approvals import ProposalState
from cyberthunder.impact import service as impact_module
from cyberthunder.remediation.dependencies import collect_dependencies
from cyberthunder.remediation.engine import fix_digest

from tests.engine.test_assessment_gate import ACK, ACTOR, block_external, seed_assessment, stored_receipt

API = "/api/v1"
HEADERS = {"X-Actor": ACTOR}


@pytest.fixture(autouse=True)
def offline(client, monkeypatch):
    # Windows builds TestClient's internal wakeup socket pair during initialization.
    # Install the guard afterwards; requests still use the in-process ASGI transport.
    def forbidden(*args, **kwargs):
        pytest.fail("impact route tests must not contact the network")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)


def test_post_assessment_stored_mode_persists_receipt_without_changing_proposal(client, ctx, monkeypatch):
    proposal, _, _, _ = seed_assessment(ctx, with_receipt=False)
    before = deepcopy(proposal.to_dict())
    block_external(ctx, monkeypatch)
    monkeypatch.setattr(impact_module, "collect_dependencies", collect_dependencies)
    response = client.post(f"{API}/proposals/{proposal.id}/impact", json={"live": False}, headers=HEADERS)
    assert response.status_code == 200, response.text
    receipt = response.json()
    assert receipt["proposal_id"] == proposal.id
    assert receipt["assessment"]["advisory_only"] and not receipt["assessment"]["approval_authority"]
    assert receipt["evidence_packet"]["mode"] == "stored" and not receipt["model"]["used"]
    assert ctx.gate.get(proposal.id).to_dict() == before
    raw = ctx.store.read_json(stored_receipt(ctx, receipt))
    assert raw["id"] == receipt["id"] and "freshness" not in raw
    if ctx.store.backend_name == "sqlite":
        assert not stored_receipt(ctx, receipt).exists()
        assert ctx.store.docs.get(f"change_assessments/{receipt['id']}.json") == raw


@pytest.mark.parametrize("actor", [None, "", "agent", "policy:Joshua"])
@pytest.mark.parametrize("action", ["impact", "approve", "review-impact"])
def test_mutating_assessment_routes_require_human_before_work(client, ctx, monkeypatch, actor, action):
    proposal, receipt, _, _ = seed_assessment(ctx)
    if action == "review-impact":
        ctx.gate.approve(proposal.id, ACTOR)
    before = deepcopy(proposal.to_dict())
    block_external(ctx, monkeypatch)
    monkeypatch.setattr(ctx.impact, "assess", lambda *a, **k: pytest.fail("actor rejection performed assessment"))
    body = {"live": False} if action == "impact" else {"assessment_id": receipt["id"], "assessment_note": ACK, "note": ACK}
    headers = {} if actor is None else {"X-Actor": actor}
    response = client.post(f"{API}/proposals/{proposal.id}/{action}", json=body, headers=headers)
    assert response.status_code == 400, response.text
    assert ctx.gate.get(proposal.id).to_dict() == before


def test_kill_blocks_assessment_and_apply_before_model_or_target_io(client, ctx, monkeypatch):
    proposal, receipt, _, _ = seed_assessment(ctx)
    ctx.gate.approve(proposal.id, ACTOR, assessment_id=receipt["id"], assessment_note=ACK)
    before = deepcopy(proposal.to_dict())
    block_external(ctx, monkeypatch)
    monkeypatch.setattr(util, "run_background", lambda *a, **k: pytest.fail("kill queued execution"))
    monkeypatch.setenv("CT_KILL", "1")
    for action, body in (("impact", {"live": False}), ("apply", {})):
        response = client.post(f"{API}/proposals/{proposal.id}/{action}", json=body, headers=HEADERS)
        assert response.status_code == 423, response.text
    assert ctx.gate.get(proposal.id).to_dict() == before


@pytest.mark.parametrize("control", ["current", "kill", "missing_inventory"])
def test_get_receipts_never_generate_collect_or_write(client, ctx, monkeypatch, control):
    proposal, receipt, _, _ = seed_assessment(ctx)
    raw = ctx.store.read_json(stored_receipt(ctx, receipt))
    before = deepcopy(proposal.to_dict())
    audit_count = len(ctx.audit)
    block_external(ctx, monkeypatch)
    if control == "kill":
        monkeypatch.setenv("CT_KILL", "1")
    elif control == "missing_inventory":
        ctx.store.targets.unlink()

    def forbidden(*args, **kwargs):
        pytest.fail("GET wrote state or invoked assessment")

    monkeypatch.setattr(ctx.impact, "assess", forbidden)
    monkeypatch.setattr(ctx.store, "write_json", forbidden)
    monkeypatch.setattr(ctx.store.docs, "put", forbidden)
    monkeypatch.setattr(ctx.audit, "append", forbidden)
    latest = client.get(f"{API}/proposals/{proposal.id}/impact")
    specific = client.get(f"{API}/change-assessments/{receipt['id']}")
    assert latest.status_code == specific.status_code == 200
    for result in (latest.json()["assessment"], specific.json()):
        assert result["id"] == receipt["id"]
        assert result["freshness"]["stale"] == (control != "current")
        assert ("kill_engaged" in result["freshness"]["reasons"]) == (control == "kill")
        if control == "missing_inventory":
            assert not result["freshness"]["ready"] and result["freshness"]["reasons"]
    assert ctx.store.read_json(stored_receipt(ctx, receipt)) == raw
    assert ctx.gate.get(proposal.id).to_dict() == before and len(ctx.audit) == audit_count


def test_empty_latest_unknown_ids_and_missing_service(client, ctx, monkeypatch):
    proposal, _, _, _ = seed_assessment(ctx, with_receipt=False)
    block_external(ctx, monkeypatch)
    assert client.get(f"{API}/proposals/{proposal.id}/impact").json() == {"assessment": None}
    assert client.get(f"{API}/change-assessments/{uuid4()}").status_code == 404
    assert client.get(f"{API}/change-assessments/not-a-uuid").status_code == 400
    assert client.get(f"{API}/proposals/no-such-proposal/impact").status_code == 404
    ctx.impact = None
    assert client.get(f"{API}/proposals/{proposal.id}/impact").status_code == 501
    assert client.post(f"{API}/proposals/{proposal.id}/impact", headers=HEADERS).status_code == 501


@pytest.mark.parametrize("note", [None, "I chose a manual dependency review because this site is disconnected."])
def test_api_legacy_approval_records_unassessed_and_optional_bypass_reason(client, ctx, monkeypatch, note):
    proposal, _, _, _ = seed_assessment(ctx, with_receipt=False)
    block_external(ctx, monkeypatch)
    response = client.post(f"{API}/proposals/{proposal.id}/approve", headers=HEADERS,
                           json={"assessment_note": note} if note else {})
    assert response.status_code == 200, response.text
    assessment = response.json()["assessment"]
    assert assessment["status"] == "not_assessed" and assessment["id"] is None and assessment["note"]
    if note:
        assert assessment["note"] == note
    assert ctx.gate.get(proposal.id).assessment == assessment


def test_bulk_legacy_approval_also_records_unassessed(client, ctx, monkeypatch):
    proposal, _, _, _ = seed_assessment(ctx, with_receipt=False)
    block_external(ctx, monkeypatch)
    response = client.post(f"{API}/proposals/bulk", headers=HEADERS, json={"ids": [proposal.id], "action": "approve"})
    assert response.status_code == 200, response.text
    assert response.json()["results"] == [{"id": proposal.id, "state": "approved"}]
    assert ctx.gate.get(proposal.id).assessment["status"] == "not_assessed"


@pytest.mark.parametrize("problem", ["unknowns_unacknowledged", "stale", "wrong_proposal", "binding_changed", "missing_inventory"])
def test_reviewed_api_approval_rejects_unusable_receipt_without_state_change(client, ctx, monkeypatch, problem):
    proposal, receipt, fix, finding = seed_assessment(ctx)
    if problem == "stale":
        now = datetime.fromisoformat(receipt["valid_until"]) + timedelta(seconds=1)
        monkeypatch.setattr(impact_module, "_now", lambda: now)
    elif problem == "wrong_proposal":
        proposal = ctx.gate.propose(actor=ACTOR, finding_id=finding.id, host=finding.host, title="Another proposal",
                                   fix_ref=fix.fix_ref, fix_preview=fix.preview_text(), rollback_plan="Restore", risk="Unknown",
                                   meta={"fix_sha256": fix_digest(fix)})
    elif problem == "binding_changed":
        ctx.inventory.get(finding.host).address = "192.0.2.88"
        ctx.inventory.save()
    elif problem == "missing_inventory":
        ctx.store.targets.unlink()
    before = deepcopy(proposal.to_dict())
    block_external(ctx, monkeypatch)
    body = {"assessment_id": receipt["id"], "assessment_note": None if problem == "unknowns_unacknowledged" else ACK}
    response = client.post(f"{API}/proposals/{proposal.id}/approve", json=body, headers=HEADERS)
    assert response.status_code == 409, response.text
    assert ctx.gate.get(proposal.id).to_dict() == before


def test_api_rereview_only_approved_and_binds_receipt(client, ctx, monkeypatch):
    proposal, receipt, _, _ = seed_assessment(ctx)
    block_external(ctx, monkeypatch)
    url = f"{API}/proposals/{proposal.id}/review-impact"
    body = {"assessment_id": receipt["id"], "note": ACK}
    assert client.post(url, json=body, headers=HEADERS).status_code == 409
    ctx.gate.approve(proposal.id, ACTOR)
    response = client.post(url, json=body, headers=HEADERS)
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "approved" and response.json()["assessment"]["id"] == receipt["id"]
    ctx.gate.start_apply(proposal.id, ACTOR)
    before = deepcopy(proposal.to_dict())
    assert client.post(url, json=body, headers=HEADERS).status_code == 409
    assert proposal.to_dict() == before


def test_stale_reviewed_apply_is_rejected_before_queue_or_demo_toggle(client, ctx, monkeypatch):
    from cyberthunder.api.routes import proposals

    proposal, receipt, _, _ = seed_assessment(ctx)
    ctx.gate.approve(proposal.id, ACTOR, assessment_id=receipt["id"], assessment_note=ACK)
    before = deepcopy(proposal.to_dict())
    now = datetime.fromisoformat(receipt["valid_until"]) + timedelta(seconds=1)
    monkeypatch.setattr(impact_module, "_now", lambda: now)
    block_external(ctx, monkeypatch)
    monkeypatch.setattr(util, "run_background", lambda *a, **k: pytest.fail("stale assessment queued apply"))
    monkeypatch.setattr(proposals, "_demo_forces_failure", lambda *a: pytest.fail("stale assessment consumed demo toggle"))
    response = client.post(f"{API}/proposals/{proposal.id}/apply", headers=HEADERS)
    assert response.status_code == 409, response.text
    assert ctx.gate.get(proposal.id).to_dict() == before


def test_valid_reviewed_approval_returns_exact_binding(client, ctx, monkeypatch):
    proposal, receipt, _, _ = seed_assessment(ctx)
    block_external(ctx, monkeypatch)
    response = client.post(f"{API}/proposals/{proposal.id}/approve", headers=HEADERS,
                           json={"assessment_id": receipt["id"], "assessment_note": ACK})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["state"] == ProposalState.APPROVED.value
    assert data["assessment"]["id"] == receipt["id"] and data["assessment"]["note"] == ACK
    assert data["assessment"]["evidence_sha256"] == receipt["evidence_sha256"]
