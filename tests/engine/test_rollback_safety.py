"""Cooperating target operations, history ordering and endpoint bindings on both stores."""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import subprocess
import sys
import threading

import pytest

from cyberthunder.control.approvals import ProposalState
from cyberthunder.findings.lifecycle import ReviewConflict
from cyberthunder.remediation import rollback_guard
from . import fakes
from .conftest import HOST, OUT_OF_SCOPE
from .test_engine import SAILOR, root_login_proposal, scan, sshd


@pytest.mark.parametrize("later_state", ["applying", "failed", "verified", "rolled_back"])
def test_later_attempt_on_other_finding_blocks_old_restore(make_ctx, later_state):
    ctx = make_ctx(auto_propose=False)
    first = root_login_proposal(ctx)
    ctx.engine.execute(first.id, actor=SAILOR)
    finding = scan(ctx)[fakes.RULE_PASS_MAX]
    later = ctx.engine.propose(finding)
    ctx.gate.approve(later.id, SAILOR)
    ctx.gate.start_apply(later.id)
    if later_state == "failed":
        ctx.gate.failed(later.id)
    elif later_state in {"verified", "rolled_back"}:
        ctx.gate.applied(later.id)
        ctx.gate.verified(later.id)
        if later_state == "rolled_back":
            ctx.gate.rolled_back(later.id, SAILOR)
    before = sshd(ctx)
    with pytest.raises(rollback_guard.RollbackBlocked, match=later.id):
        ctx.engine.rollback(first.id, actor=SAILOR)
    assert sshd(ctx) == before and ctx.gate.get(first.id).state is ProposalState.VERIFIED
    assert ctx.engine.diff(first.id)["rollback"] is None
    assert ctx.engine.rollback_status(first.id)["conflicting_proposals"] == [later.id]


def test_old_proposal_applied_later_is_ordered_by_action_not_creation(make_ctx):
    ctx = make_ctx(auto_propose=False)
    findings = scan(ctx)
    other = ctx.engine.propose(findings[fakes.RULE_PASS_MAX])
    ctx.gate.approve(other.id, SAILOR)
    first = ctx.engine.propose(findings[fakes.RULE_ROOT_LOGIN])
    ctx.gate.approve(first.id, SAILOR)
    ctx.engine.execute(first.id, actor=SAILOR)
    ctx.engine.execute(other.id, actor=SAILOR)
    with pytest.raises(rollback_guard.RollbackBlocked, match=other.id):
        ctx.engine.rollback(first.id, actor=SAILOR)
    # Losing a later proposal row must not erase the audit's record of its target/mutation.
    ctx.gate._save([q for q in ctx.gate.list() if q.id != other.id])
    assert other.id in ctx.engine.rollback_status(first.id)["conflicting_proposals"]


@pytest.mark.parametrize("field,value", [("address", "other-host"), ("port", 2222),
                                         ("options", {"fixture_dir": "different"}), ("transport", "ssh")])
def test_identity_change_blocks_before_connection(make_ctx, fake_adapter, field, value):
    ctx = make_ctx(auto_propose=False)
    p = root_login_proposal(ctx)
    ctx.engine.execute(p.id, actor=SAILOR)
    ctx.inventory.update(HOST, **{field: value})
    ctx.inventory.save()
    count = len(fake_adapter.transports_made)
    with pytest.raises(rollback_guard.RollbackBlocked, match="identity changed"):
        ctx.engine.rollback(p.id, actor=SAILOR)
    assert len(fake_adapter.transports_made) == count


def test_lock_covers_execute_verify_rollback_and_leaves_other_target_and_store_free(make_ctx, fake_adapter, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    findings = scan(ctx)
    first = ctx.engine.propose(findings[fakes.RULE_ROOT_LOGIN])
    ctx.gate.approve(first.id, SAILOR)
    older = ctx.engine.propose(findings[fakes.RULE_PASS_MAX])
    ctx.gate.approve(older.id, SAILOR)
    ctx.engine.execute(older.id, actor=SAILOR)
    later = ctx.engine.propose(findings[fakes.RULE_PASS_MAX])
    ctx.gate.approve(later.id, SAILOR)
    ctx.inventory.update(OUT_OF_SCOPE, in_scope=True)
    ctx.inventory.save()
    other_findings = ctx.scanner.start([OUT_OF_SCOPE], background=False)
    other = ctx.engine.propose(next(f for f in ctx.store.load_findings(other_findings.id) if f.rule_id == fakes.RULE_ROOT_LOGIN))
    ctx.gate.approve(other.id, SAILOR)
    entered, release = threading.Event(), threading.Event()
    apply = fake_adapter.apply
    def pause(target, *args):
        if target.id == HOST:
            entered.set()
            assert release.wait(10), "test failed to release target I/O"
        return apply(target, *args)
    monkeypatch.setattr(fake_adapter, "apply", pause)
    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(ctx.engine.execute, first.id, actor=SAILOR)
        try:
            assert entered.wait(5)
            for method, pid in ((ctx.engine.execute, later.id), (ctx.engine.verify, older.id), (ctx.engine.rollback, older.id)):
                with pytest.raises(ReviewConflict, match="active remediation operation"):
                    method(pid, actor=SAILOR)
            # These writes would deadlock if the target lock were a SQLite document transaction.
            write = pool.submit(ctx.store.write_json, ctx.store.root / "scans" / "unrelated" / "run.json", {"id": "unrelated"})
            write.result(timeout=3)
            other_run = pool.submit(ctx.engine.execute, other.id, actor=SAILOR)
            assert other_run.result(timeout=5).state is ProposalState.VERIFIED
        finally:
            release.set()
        assert future.result(timeout=5).state is ProposalState.VERIFIED
    with pytest.raises(rollback_guard.RollbackBlocked, match="same-target"):
        ctx.engine.rollback(older.id, actor=SAILOR)


def test_target_lock_crosses_processes_and_releases_on_exit(state_dir):
    root = Path(__file__).resolve().parents[2]
    code = """import sys
from pathlib import Path
from cyberthunder.remediation.rollback_guard import target_operation
from cyberthunder.findings.lifecycle import ReviewConflict
try:
    with target_operation(Path(sys.argv[1]), sys.argv[2]):
        print('acquired')
except ReviewConflict:
    print('busy')
"""
    env = {**os.environ, "PYTHONPATH": str(root)}
    def attempt(target):
        return subprocess.check_output([sys.executable, "-c", code, str(state_dir), target], env=env, text=True, timeout=5).strip()
    with rollback_guard.target_operation(state_dir, HOST):
        assert attempt(HOST) == "busy"
        assert attempt("other") == "acquired"
    assert attempt(HOST) == "acquired"


def test_unknown_adapter_explicitly_reports_no_live_guard(make_ctx):
    ctx = make_ctx(auto_propose=False)
    p = root_login_proposal(ctx)
    ctx.engine.execute(p.id, actor=SAILOR)
    ctx.engine.rollback(p.id, actor=SAILOR)
    status = ctx.engine.rollback_status(p.id)["last_preflight"]
    assert status["status"] == "limited" and status["coverage"] == "unsupported"
    assert status["identity_bound"] and not status["live_checked"]
    assert any("overwrite" in note for note in status["limitations"])


def test_immediate_recovery_keeps_target_lock(make_ctx, fake_adapter, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    p = root_login_proposal(ctx)
    rollback = fake_adapter.rollback
    def check(*args):
        with pytest.raises(ReviewConflict):
            with rollback_guard.target_operation(ctx.store.root, HOST):
                pytest.fail("recovery released the operation lock")
        return rollback(*args)
    monkeypatch.setattr(fake_adapter, "rollback", check)
    assert ctx.engine.execute(p.id, actor=SAILOR, simulate_verify_fail=True).state is ProposalState.ROLLED_BACK


def test_changed_identity_during_capture_stops_before_apply(make_ctx, fake_adapter, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    p = root_login_proposal(ctx)
    capture = fake_adapter.capture_before_state
    def change(*args):
        before = capture(*args)
        ctx.inventory.update(HOST, address="new-endpoint")
        ctx.inventory.save()
        return before
    monkeypatch.setattr(fake_adapter, "capture_before_state", change)
    before = sshd(ctx)
    with pytest.raises(rollback_guard.RollbackBlocked, match="identity changed"):
        ctx.engine.execute(p.id, actor=SAILOR)
    assert sshd(ctx) == before and ctx.gate.get(p.id).state is ProposalState.FAILED


def test_delayed_verify_cannot_restore_over_later_change(make_ctx, fake_adapter, monkeypatch):
    from cyberthunder.remediation.models import HealthResult, VerifyResult
    ctx = make_ctx(auto_propose=False)
    p = root_login_proposal(ctx)
    monkeypatch.setattr(fake_adapter, "verify", lambda *args: VerifyResult(ok=True, rule_passed=None, health=HealthResult(ok=True)))
    assert ctx.engine.execute(p.id, actor=SAILOR).state is ProposalState.APPLIED
    other = ctx.engine.propose(scan(ctx)[fakes.RULE_PASS_MAX])
    ctx.gate.approve(other.id, SAILOR)
    ctx.engine.execute(other.id, actor=SAILOR)
    before = sshd(ctx)
    with pytest.raises(rollback_guard.RollbackBlocked, match="same-target"):
        ctx.engine.verify(p.id, actor=SAILOR)
    assert sshd(ctx) == before and ctx.gate.get(p.id).state is ProposalState.APPLIED


def test_legacy_unsupported_adapter_is_labeled_without_claiming_identity(make_ctx):
    ctx = make_ctx(auto_propose=False)
    p = root_login_proposal(ctx)
    ctx.engine.execute(p.id, actor=SAILOR)
    # Existing deployments did not record either of these immutable manifests.
    for name in ("execution", "post_apply"):
        (ctx.store.snapshots_dir / p.id / f"{name}.json").unlink()
    ctx.engine.rollback(p.id, actor=SAILOR)
    status = ctx.engine.rollback_status(p.id)["last_preflight"]
    assert not status["identity_bound"] and not status["live_checked"]
    assert any("Legacy" in note for note in status["limitations"])
