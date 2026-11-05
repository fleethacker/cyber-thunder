from copy import deepcopy
from datetime import timedelta

import pytest

from cyberthunder.impact import validate_receipt_binding
from cyberthunder.impact.bindings import BINDING_FIELDS
from cyberthunder.impact.packet import evidence_digest
from cyberthunder.impact.service import _now


def test_readiness_contract_and_pure_binding_helper(rig, monkeypatch):
    receipt = rig.service.assess(rig.proposal.id, actor="Joshua")
    bindings = {k: receipt[k] for k in BINDING_FIELDS}
    check = rig.service.readiness(rig.proposal.id, receipt["id"])
    assert set(check) == {"ready", "status", "stale", "age_seconds", "assessment_id", "proposal_id",
                          "valid_until", "reasons", "unknowns", "approval_authority"}
    assert check["ready"] and not check["stale"] and check["reasons"] == []
    assert check["unknowns"] and not check["approval_authority"]

    def forbidden(*args, **kwargs):
        pytest.fail("pure binding helper must not perform any I/O")

    monkeypatch.setattr(rig.ctx.store, "read_json", forbidden)
    monkeypatch.setattr(rig.ctx.audit, "append", forbidden)
    monkeypatch.setattr(rig.ctx.inventory, "get", forbidden)
    monkeypatch.setattr(rig.ctx.gate, "get", forbidden)
    monkeypatch.setattr(rig.backend, "generate", forbidden)
    monkeypatch.setattr(rig.backend, "available", forbidden)
    result = validate_receipt_binding(receipt, bindings, now=_now())
    assert result["ready"] and result["assessment_id"] == receipt["id"]


@pytest.mark.parametrize("changed", ["fix_sha256", "target_binding_sha256", "finding_binding_sha256",
                                     "finding_fingerprint", "proposal_id", "evidence", "ttl", "expired"])
def test_pure_helper_rejects_binding_evidence_and_time_changes(rig, changed):
    receipt = rig.service.assess(rig.proposal.id, actor="Joshua")
    bindings = {k: receipt[k] for k in BINDING_FIELDS}
    if changed in bindings:
        bindings[changed] = "changed"
    elif changed == "evidence":
        receipt["evidence_packet"]["evidence"][0]["facts"]["active_state"] = "failed"
    elif changed == "ttl":
        receipt["valid_until"] = (_now() + timedelta(minutes=16)).isoformat()
    result = validate_receipt_binding(receipt, bindings,
                                     now=_now() + (timedelta(minutes=16) if changed == "expired" else timedelta()))
    assert result["stale"] and not result["ready"] and result["reasons"]


def test_explicit_receipt_rejects_rebound_packet_with_new_hash(rig):
    receipt = rig.service.assess(rig.proposal.id, actor="Joshua")
    bindings = {k: receipt[k] for k in BINDING_FIELDS}
    receipt = deepcopy(receipt)
    receipt["evidence_packet"]["target_id"] = "other-target"
    receipt["evidence_packet"]["evidence_sha256"] = evidence_digest(receipt["evidence_packet"])
    receipt["evidence_sha256"] = receipt["evidence_packet"]["evidence_sha256"]
    result = validate_receipt_binding(receipt, bindings, now=_now())
    assert not result["ready"] and "evidence_binding_changed" in result["reasons"]


def test_parent_binding_accepts_unknowns_only_with_human_note(rig):
    from cyberthunder.control.assessment import bind_assessment
    rig.ctx.impact = rig.service
    receipt = rig.service.assess(rig.proposal.id, actor="Joshua")
    with pytest.raises(Exception, match="acknowledge"):
        bind_assessment(rig.ctx, rig.proposal.id, receipt["id"])
    binding = bind_assessment(rig.ctx, rig.proposal.id, receipt["id"], "I reviewed the unresolved service dependencies.")
    assert binding["id"] == receipt["id"] and binding["has_unknowns"]
    assert binding["status"] == "reviewed"
