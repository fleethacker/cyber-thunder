"""Assessment model calls retain the initiating plan authority across threads."""
from __future__ import annotations

import threading
from copy import deepcopy

import pytest

from cyberthunder.control.principal import current_principal, principal_scope, require_current
from cyberthunder.impact import service as module
from cyberthunder.inventory.targets import Target
from cyberthunder.security.resources import capture
from tests.security.job_helpers import enable_auth


def identity(rig, subject="job-owner"):
    # The rig creates its fixtures before verified mode. Stamp the same immutable
    # scopes as the real gate/store do when publishing a new authorized record.
    scope = capture(rig.ctx, [rig.target.id])[0]
    with rig.ctx.gate._locked():
        rig.ctx.gate.get(rig.proposal.id).authorization_scope = dict(scope)
        rig.ctx.gate._save()
    rig.current[0].authorization_scope = dict(scope)
    return enable_auth(rig.ctx, grants=[{"actions": ["plan"], "target_ids": [rig.target.id]}], subject=subject)


def test_model_probe_and_generate_receive_plan_identity_and_session(rig):
    p = identity(rig)
    seen, validated = [], []
    rig.backend.on_probe = lambda: seen.append(("probe", current_principal()))
    rig.backend.on_generate = lambda: seen.append(("generate", current_principal()))
    with principal_scope(p, validity=lambda: validated.append(threading.current_thread().name)):
        receipt = rig.service.assess(rig.proposal.id, actor=p.actor)
    assert receipt["model"]["used"]
    assert seen == [("probe", p), ("generate", p)]
    assert "impact-model" in validated and current_principal() is None


@pytest.mark.parametrize("phase", ["probe", "generate"])
def test_revoked_worker_identity_stops_before_backend_io_and_receipt(rig, monkeypatch, phase):
    p = identity(rig)
    denied = [False]
    calls = [0]
    bounded = module._bounded_call

    def validity():
        if denied[0]:
            raise PermissionError("fixture session revoked")

    def queued(call, timeout):
        calls[0] += 1
        if calls[0] == (1 if phase == "probe" else 2):
            denied[0] = True
        return bounded(call, timeout)

    monkeypatch.setattr(module, "_bounded_call", queued)
    with principal_scope(p, validity=validity), pytest.raises(PermissionError):
        rig.service.assess(rig.proposal.id, actor=p.actor)
    assert rig.backend.probes == (0 if phase == "probe" else 1)
    assert not rig.backend.calls and rig.service.latest(rig.proposal.id) is None
    assert [r for r in rig.ctx.audit.records() if r["action"] == "impact.error"][-1]["details"]["error"] == "scope_or_actor"


def test_separate_model_calls_do_not_reuse_previous_principal(rig):
    people = [identity(rig, subject=name) for name in ("first", "second")]
    seen = []
    for p in people:
        with principal_scope(p):
            value, error = module._bounded_call(lambda: require_current("plan"), 2)
        assert error is None
        seen.append(value)
    assert seen == people and current_principal() is None


@pytest.mark.parametrize("change", ["deleted", "moved", "reused"])
def test_historical_proposal_is_denied_before_collection_even_with_current_target_grant(rig, change):
    p = identity(rig)
    inventory = rig.ctx.inventory
    if change == "moved":
        rig.target.environment = "another-environment"
    else:
        inventory.remove(rig.target.id)
        if change == "reused":
            inventory.add(Target(id=rig.target.id, name="Replacement", asset_type="linux", transport="ssh"))
    inventory.save()
    with principal_scope(p), pytest.raises(PermissionError):
        rig.service.assess(rig.proposal.id, actor=p.actor)
    assert not rig.calls and not rig.backend.probes and not rig.backend.calls
    assert not rig.ctx.store.list_json(rig.service.directory)


@pytest.mark.parametrize("record", ["proposal", "finding"])
@pytest.mark.parametrize("scope", [None, "moved", "reused"])
def test_each_impact_record_requires_its_own_immutable_ownership(rig, record, scope):
    p = identity(rig)
    obj = deepcopy(rig.ctx.gate.get(rig.proposal.id)) if record == "proposal" else rig.current[0]
    if scope is None:
        obj.authorization_scope = None
    elif scope == "moved":
        obj.authorization_scope["environment"] = "old-environment"
    else:
        obj.authorization_scope["authorization_id"] = "0" * 32
    if record == "proposal":
        with rig.ctx.gate._locked():
            rig.ctx.gate._save([obj])
            rig.ctx.gate._reload(force=True)
    with principal_scope(p), pytest.raises(PermissionError):
        rig.service.assess(rig.proposal.id, actor=p.actor)
    assert not rig.calls and not rig.backend.probes and not rig.backend.calls
    assert not rig.ctx.store.list_json(rig.service.directory)


def test_finding_ownership_change_after_model_probe_prevents_generation_and_receipt(rig):
    p = identity(rig)
    rig.backend.on_probe = lambda: rig.current[0].authorization_scope.update(environment="old-environment")
    with principal_scope(p), pytest.raises(PermissionError):
        rig.service.assess(rig.proposal.id, actor=p.actor)
    assert rig.backend.probes == 1 and not rig.backend.calls
    assert not rig.ctx.store.list_json(rig.service.directory)
