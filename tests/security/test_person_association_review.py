"""Independent adversarial checks for exact person-bound approval evidence."""
from copy import deepcopy

import pytest

from cyberthunder.control import separation
from cyberthunder.control.principal import principal_scope
from tests.security.test_person_association import mapped, mutate
from tests.security.test_separation_of_duties import (
    ACK, approve, edit_proposal, offline, person, propose, setup,
)


@pytest.mark.parametrize("policy_version", [1, 2])
@pytest.mark.parametrize("field", ["receipt_principal", "decision_principal", "assessment"])
def test_equal_numeric_types_cannot_relabel_audited_evidence(mapped, policy_version, field):
    ctx, _, _, path = mapped
    if policy_version == 1:
        mutate(path, "downgrade")
    p = propose(mapped)
    with principal_scope(person("bob")):
        receipt = ctx.impact.assess(p.id, actor=person("bob").actor, live=False)
    for subject in ("bob", "carol"):
        approve(ctx, p.id, subject, assessment_id=receipt["id"], assessment_note=ACK)
    assert separation.validate_history(ctx.gate, p, quorum=True)

    def edit(row):
        if field == "assessment":
            assert type(row["assessment"]["model_used"]) is bool
            row["assessment"]["model_used"] = int(row["assessment"]["model_used"])
        else:
            evidence = row["approvals"][0]["principal"] if field == "receipt_principal" else row["decided_principal"]
            assert type(evidence["auth_time"]) is int
            evidence["auth_time"] = float(evidence["auth_time"])

    edit_proposal(ctx, p.id, edit)
    with pytest.raises(PermissionError):
        separation.validate_history(ctx.gate, ctx.gate.get(p.id), quorum=True)
    with principal_scope(person("carol")), pytest.raises(PermissionError):
        ctx.gate.start_apply(p.id, person("carol").actor)


def test_reviewed_person_receipt_and_target_generation_remain_bound(mapped):
    ctx, _, _, _ = mapped
    p = propose(mapped)
    with principal_scope(person("bob")):
        receipt = ctx.impact.assess(p.id, actor=person("bob").actor, live=False)
    for subject in ("bob", "carol"):
        approve(ctx, p.id, subject, assessment_id=receipt["id"], assessment_note=ACK)
    before = deepcopy(p.to_dict())
    ctx.inventory.get("alpha").authorization_id = "replacement-generation"
    ctx.inventory.save()
    assert separation.validate_history(ctx.gate, p, quorum=True)
    with principal_scope(person("carol")), pytest.raises(PermissionError):
        ctx.gate.start_apply(p.id, person("carol").actor)
    assert p.to_dict() == before


@pytest.mark.parametrize("stage", ["approve", "start_apply"])
def test_fresh_assessment_type_changes_cannot_reuse_recorded_approvals(mapped, stage):
    ctx, _, _, _ = mapped
    p = propose(mapped)
    with principal_scope(person("bob")):
        receipt = ctx.impact.assess(p.id, actor=person("bob").actor, live=False)
    approve(ctx, p.id, assessment_id=receipt["id"], assessment_note=ACK)
    if stage == "start_apply":
        approve(ctx, p.id, "carol", assessment_id=receipt["id"], assessment_note=ACK)
    original = ctx.gate.assessment_validator

    def changed(*args):
        result = original(*args)
        result["model_used"] = int(result["model_used"])
        return result

    ctx.gate.assessment_validator = changed
    before = deepcopy(p.to_dict())
    with principal_scope(person("carol")), pytest.raises(PermissionError):
        if stage == "approve":
            ctx.gate.approve(p.id, person("carol").actor, assessment_id=receipt["id"], assessment_note=ACK)
        else:
            ctx.gate.start_apply(p.id, person("carol").actor)
    assert p.to_dict() == before
