"""An admission is an explicit, revocable transfer capability, never a general admin lease."""
from contextvars import copy_context
from copy import copy
from dataclasses import replace
import json
import time

import pytest

from cyberthunder.control.principal import principal_scope
from cyberthunder.security.step_up import admit_transfer, authorize_transfer, transfer_continuation, StepUpRequired
from tests.security.test_identity_boundary import verified_app, identity
from tests.security.test_sessions import advance


@pytest.fixture
def admitted(verified_app):
    ctx, _, _, _, _ = verified_app
    person = replace(identity(roles=("admin", "approver")), expires_at=time.time() + 1800)
    policy = json.loads(ctx.access.path.read_text())
    for entry in policy["entries"]:
        entry["node_actions"] += ["admin", "policy"]
    ctx.access.path.write_text(json.dumps(policy))
    intent = {"files": ["reviewed-file.zip"], "source": "reviewed-source"}
    with principal_scope(person):
        admission = admit_transfer(ctx, operation="content.pull", job_id="job-one", intent=intent, actor=person.actor)
        captured = copy_context()
    return ctx, person, admission, intent, captured


def test_copied_job_can_continue_after_step_up_age_but_new_decisions_cannot(admitted, monkeypatch):
    ctx, person, receipt, intent, captured = admitted
    advance(monkeypatch, 301)
    proof = transfer_continuation(receipt, operation="content.pull", job_id="job-one", intent=intent)
    assert captured.run(authorize_transfer, ctx, continuation=proof, actor=person.actor) == person
    for action, target in [("admin", None), ("admin", "alpha"), ("policy", None), ("approve", "alpha"), ("kill.release", None)]:
        with pytest.raises(StepUpRequired):
            captured.run(ctx.authorize, action, actor=person.actor, target=target)
    with pytest.raises(StepUpRequired):
        captured.run(admit_transfer, ctx, operation="content.pull", job_id="job-two", intent=intent, actor=person.actor)


@pytest.mark.parametrize("fault", ["job", "operation", "intent", "account", "roles", "node", "mode", "policy", "assurance", "closed", "expiry", "session", "serialized", "target", "wrong_action"])
def test_receipt_cannot_escape_job_account_policy_session_or_lifetime(admitted, monkeypatch, fault):
    ctx, person, receipt, intent, _ = admitted
    operation, job_id = "content.pull", "job-one"
    if fault == "job": job_id = "job-two"
    elif fault == "operation": operation = "vulnerabilities.update"
    elif fault == "intent": intent["files"].append("unapproved-file.zip")
    elif fault == "account": person = replace(person, subject="fixture-proposer")
    elif fault == "roles": person = replace(person, roles=("admin",))
    elif fault == "node": ctx = copy(ctx)
    elif fault == "mode": ctx.settings.auth_mode = "dev"
    elif fault == "policy": ctx.access.path.write_text(ctx.access.path.read_text() + "\n")
    elif fault == "assurance": ctx.settings.step_up_max_age_s = 301
    elif fault == "closed": receipt.close()
    elif fault == "expiry": advance(monkeypatch, 1801)
    proof = transfer_continuation(receipt, operation=operation, job_id=job_id, intent=intent)
    if fault == "serialized": proof = {"operation": operation, "job_id": job_id}
    def validity():
        if fault == "session": raise PermissionError("fixture session revoked")
    with principal_scope(person, validity=validity), pytest.raises(PermissionError):
        ctx.authorize("policy" if fault == "wrong_action" else "admin", actor=person.actor,
                      target="alpha" if fault == "target" else None, step_up_continuation=proof)
