"""Rollback changes current interpretation, never the detector's stored observations."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from cyberthunder.api import util
from cyberthunder.control.approvals import ProposalState
from cyberthunder.findings.current import CurrentFindings, policy_block_reason
from cyberthunder.remediation import snapshot
from cyberthunder.remediation.engine import EngineError
from cyberthunder.remediation.models import RollbackResult
from cyberthunder.report import onepager, poam
from cyberthunder.report.service import ReportService
from . import fakes
from .conftest import HOST
from .test_engine import SAILOR, scan, sshd


@pytest.fixture
def timeline(make_ctx, fake_adapter, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    now = [datetime.now(timezone.utc) - timedelta(days=7)]
    clock = lambda: now[0].isoformat(timespec="seconds")
    monkeypatch.setattr("cyberthunder.control.approvals.utcnow", clock)
    detect = fake_adapter._findings
    monkeypatch.setattr(fake_adapter, "_findings", lambda *args: [replace(f, collected_at=clock()) for f in detect(*args)])

    def observe():
        now[0] += timedelta(seconds=2)
        # Scan ids are independent of collection times; save the run ordering explicitly.
        finding = scan(ctx)[fakes.RULE_ROOT_LOGIN]
        run = ctx.store.load_scan_run(finding.scan_id)
        run["started_at"] = clock()
        ctx.store.save_scan_run(run)
        return finding

    first = observe()
    proposal = ctx.engine.propose(first)
    ctx.gate.approve(proposal.id, SAILOR)
    now[0] += timedelta(seconds=2)
    assert ctx.engine.execute(proposal.id, actor=SAILOR).state is ProposalState.VERIFIED
    return ctx, proposal, first, observe, now


def assert_current(ctx, finding, status):
    detail = util.finding_plus(ctx, ctx.store.get_finding(finding.id))
    assert detail["status"] == status
    listing = util.list_findings(ctx, scan_id=None, limit=100, offset=0, status=status)
    assert finding.id in {row["id"] for row in listing["findings"]}
    assert listing["summary"]["by_status"][status] >= 1
    assert detail["scanner_status"] == ctx.store.get_finding(finding.id).status.value
    return detail


@pytest.mark.parametrize("fresh_pass", [False, True])
def test_verify_pass_rescan_rollback_then_fresh_evidence(timeline, fresh_pass):
    ctx, proposal, first, observe, now = timeline
    assert_current(ctx, first, "not_a_finding")
    passed = observe()
    assert passed.status.value == "not_a_finding"
    saved = {f.scan_id: ctx.store.read_json(ctx.store.scans_dir / f.scan_id / "findings.json") for f in (first, passed)}
    snap = ctx.store.snapshot_dir(proposal.id)
    snapshots = {path: path.read_bytes() for path in snap.rglob("*") if path.is_file()}
    now[0] = datetime.now(timezone.utc) + timedelta(seconds=2)
    assert ctx.engine.rollback(proposal.id, actor=SAILOR).state is ProposalState.ROLLED_BACK
    assert "PermitRootLogin yes" in sshd(ctx)
    row = assert_current(ctx, passed, "not_reviewed")
    assert row["needs_rescan"] is True
    assert row["rollback"]["proposal_id"] == proposal.id
    assert row["remediated"] is None
    for path, original in snapshots.items():
        assert path.read_bytes() == original
    attempts = [r for r in ctx.audit.records() if r["action"] == "remediation.rollback" and r["subject"] == proposal.id]
    assert attempts[-1]["details"]["ok"] is True and attempts[-1]["outcome"] == "ok"
    assert attempts[-1]["details"]["finished_at"] == row["rollback"]["finished_at"]
    # The original failure remains open; rollback does not manufacture a new detector failure.
    assert util.finding_plus(ctx, ctx.store.get_finding(first.id, first.scan_id))["status"] == "open"
    if fresh_pass:
        fakes.HOSTS[HOST]["files"][fakes.SSHD] = fakes._set_line(sshd(ctx), "PermitRootLogin", "no")
    fresh = observe()
    row = assert_current(ctx, fresh, "not_a_finding" if fresh_pass else "open")
    assert row["needs_rescan"] is False
    for sid, original in saved.items():
        assert ctx.store.read_json(ctx.store.scans_dir / sid / "findings.json") == original


def test_old_proposal_rollback_is_not_hidden_by_newer_proposal(timeline):
    from cyberthunder.remediation.rollback_guard import RollbackBlocked
    ctx, old, first, observe, now = timeline
    newer = ctx.engine.propose(first)
    ctx.gate.approve(newer.id, SAILOR)
    now[0] += timedelta(seconds=2)
    assert ctx.engine.execute(newer.id, actor=SAILOR).state is ProposalState.VERIFIED
    passed = observe()
    now[0] = datetime.now(timezone.utc) + timedelta(seconds=2)
    with pytest.raises(RollbackBlocked, match="same-target"):
        ctx.engine.rollback(old.id, actor=SAILOR)
    row = assert_current(ctx, passed, "not_a_finding")
    assert row["rollback"] is None  # a blocked preflight is not a host restore attempt
    assert ctx.gate.get(newer.id).state is ProposalState.VERIFIED


@pytest.mark.parametrize("raises", [False, True])
def test_failed_rollback_records_result_without_claiming_success(timeline, fake_adapter, monkeypatch, raises):
    ctx, proposal, first, observe, now = timeline
    passed = observe()
    before = ctx.gate.get(proposal.id).to_dict()
    def fail(*args):
        if raises:
            raise RuntimeError("restore interrupted")
        return RollbackResult(ok=False, output="restore interrupted")
    monkeypatch.setattr(fake_adapter, "rollback", fail)
    with pytest.raises(EngineError, match="restore interrupted"):
        ctx.engine.rollback(proposal.id, actor=SAILOR)
    assert ctx.gate.get(proposal.id).to_dict() == before
    result = ctx.engine.diff(proposal.id)["rollback"]
    assert result["ok"] is False
    attempts = [r for r in ctx.audit.records() if r["action"] == "remediation.rollback" and r["subject"] == proposal.id]
    assert attempts[-1]["details"]["ok"] is False
    assert attempts[-1]["outcome"] == "error"
    assert_current(ctx, passed, "not_reviewed")


def test_reports_keep_raw_evidence_and_withdraw_current_pass(timeline):
    ctx, proposal, first, observe, now = timeline
    passed = observe()
    reports = ReportService(ctx)
    archived = reports.checklist_cklb(host=HOST)
    assert next(r for s in archived["stigs"] for r in s["rules"] if r["rule_version"] == first.rule_version)["status"] == "not_a_finding"
    archive_paths = ctx.store.list_json(ctx.store.root / "reports" / "history")
    assert archive_paths
    originals = {path: ctx.store.read_json(path) for path in archive_paths}
    ctx.engine.rollback(proposal.id, actor=SAILOR)
    data = onepager.build_commander(ctx, None, "md")
    row = next(row for row in data["assurance"]["findings"] if row["id"] == passed.id)
    assert row["status"] == "not_a_finding" and row["current_status"] == "not_reviewed"
    assert row["evidence"] == passed.evidence
    assert any("need a rescan after rollback" in sentence for sentence in data["bluf"])
    row = next(row for row in poam.poam_rows(ctx) if row["Finding ID"] == passed.id)
    assert row["Status"] == "Needs investigation"
    assert row["Scanner Status"] == "not_a_finding" and row["Scanner Evidence"] == passed.evidence
    assert "Rescan after rollback" in row["Milestone"]
    doc = reports.checklist_cklb(host=HOST)
    rule = next(r for s in doc["stigs"] for r in s["rules"] if r["rule_version"] == first.rule_version)
    assert rule["status"] == "not_reviewed" and rule["finding_details"] == passed.evidence
    assert proposal.id in rule["comments"] and "rescan required" in rule["comments"]
    for path, original in originals.items():
        assert ctx.store.read_json(path) == original


def test_failed_attempt_survives_retry_in_audit_and_restart(timeline, fake_adapter, make_ctx, monkeypatch):
    ctx, proposal, first, observe, now = timeline
    passed = observe()
    rollback = fake_adapter.rollback
    monkeypatch.setattr(fake_adapter, "rollback", lambda *args: RollbackResult(ok=False, output="blocked restore"))
    with pytest.raises(EngineError):
        ctx.engine.rollback(proposal.id, actor=SAILOR)
    fresh_ctx = make_ctx(auto_propose=False)
    row = assert_current(fresh_ctx, passed, "not_reviewed")
    assert row["rollback"]["ok"] is False
    assert fresh_ctx.gate.get(proposal.id).state is ProposalState.VERIFIED
    monkeypatch.setattr(fake_adapter, "rollback", rollback)
    assert fresh_ctx.engine.rollback(proposal.id, actor=SAILOR).state is ProposalState.ROLLED_BACK
    row = assert_current(ctx, passed, "not_reviewed")
    assert row["rollback"]["ok"] is True
    attempts = [r for r in ctx.audit.records() if r["action"] == "remediation.rollback" and r["subject"] == proposal.id]
    assert [r["details"]["ok"] for r in attempts] == [False, True]


def test_rollback_withholds_standing_approval_without_affecting_human_approval(timeline, fake_adapter, monkeypatch):
    from cyberthunder.control.policy import PolicyDecision, evaluate_for_context
    from cyberthunder.remediation.engine import PolicyEvidenceBlocked
    from .test_engine import _policy

    ctx, proposal, first, observe, now = timeline
    ctx.engine.rollback(proposal.id, actor=SAILOR)
    _policy(ctx, fix_allowlist=[proposal.fix_ref])
    decision = evaluate_for_context(ctx, ctx.library.get(proposal.fix_ref), first, ctx.inventory.get(HOST))
    assert not decision.auto_eligible and "rollback" in decision.reasons[0]
    # Ordinary policy eligibility cannot override the rollback lifecycle guard.
    monkeypatch.setattr("cyberthunder.control.policy.evaluate_for_context",
                        lambda *args: PolicyDecision(True, "test", ["eligible"]))
    newer = ctx.engine.propose(first)
    ctx.engine._apply_policy(newer, first)
    assert ctx.gate.get(newer.id).state is ProposalState.PROPOSED
    assert util.proposal_plus(ctx, newer)["policy"]["auto_eligible"] is False
    ctx.gate.approve_by_policy(newer.id, ctx.policy)
    plan = ctx.engine.plan(newer.id, actor=SAILOR)
    assert next(check for check in plan["checks"] if check["code"] == "policy_evidence")["status"] == "blocked"
    transports = len(fake_adapter.transports_made)
    with pytest.raises(PolicyEvidenceBlocked, match="rescan"):
        ctx.engine.execute(newer.id, actor=SAILOR)
    assert len(fake_adapter.transports_made) == transports
    ctx.gate.cancel(newer.id, SAILOR)
    manual = ctx.engine.propose(first)
    ctx.gate.approve(manual.id, SAILOR)
    assert ctx.engine.execute(manual.id, actor=SAILOR).state is ProposalState.VERIFIED


def test_auto_rollback_invalidates_a_pass(timeline, fake_adapter, monkeypatch):
    ctx, proposal, first, observe, now = timeline
    passed = observe()
    newer = ctx.engine.propose(first)
    ctx.gate.approve(newer.id, SAILOR)
    # Recreate a regression on the host without publishing an observation before the failed fix.
    fakes.HOSTS[HOST]["files"][fakes.SSHD] = fakes.seed_state()["files"][fakes.SSHD]
    def fail(*args):
        raise RuntimeError("apply failed")
    monkeypatch.setattr(fake_adapter, "apply", fail)
    assert ctx.engine.execute(newer.id, actor=SAILOR).state is ProposalState.ROLLED_BACK
    row = assert_current(ctx, passed, "not_reviewed")
    assert row["rollback"]["proposal_id"] == newer.id


@pytest.mark.parametrize("lost", ["result_write", "audit_write", "proposal_row"])
def test_durable_rollback_receipts_withdraw_stale_pass_despite_storage_loss(timeline, make_ctx, monkeypatch, lost):
    ctx, proposal, first, observe, now = timeline
    passed = observe()
    original = ctx.store.read_json(ctx.store.scans_dir / passed.scan_id / "findings.json")
    if lost == "result_write":
        save = snapshot.save_result
        def fail(path, name, obj):
            if name == "rollback":
                raise OSError("result write failed")
            return save(path, name, obj)
        monkeypatch.setattr(snapshot, "save_result", fail)
    elif lost == "audit_write":
        append = ctx.audit.append
        def fail(action, *args, **kwargs):
            if action == "remediation.rollback":
                raise OSError("audit write failed")
            return append(action, *args, **kwargs)
        monkeypatch.setattr(ctx.audit, "append", fail)
    if lost == "proposal_row":
        ctx.engine.rollback(proposal.id, actor=SAILOR)
        ctx.gate._save([p for p in ctx.gate.list() if p.id != proposal.id])
    else:
        with pytest.raises(OSError, match="write failed"):
            ctx.engine.rollback(proposal.id, actor=SAILOR)
        assert ctx.gate.get(proposal.id).state is ProposalState.VERIFIED
    assert "PermitRootLogin yes" in sshd(ctx)
    row = assert_current(ctx, passed, "not_reviewed")
    assert row["needs_rescan"] and row["rollback"]["ok"] is True
    assert policy_block_reason(ctx, passed)
    restarted = make_ctx(auto_propose=False)
    assert_uncertain_views(restarted, passed)
    assert ctx.store.read_json(ctx.store.scans_dir / passed.scan_id / "findings.json") == original
    now[0] = datetime.now(timezone.utc) + timedelta(seconds=2)
    fresh = observe()
    assert CurrentFindings.for_context(ctx).assess(fresh).needs_rescan is False


def test_failed_restore_of_original_open_is_not_completed_in_poam(timeline, fake_adapter, monkeypatch):
    ctx, proposal, first, observe, now = timeline
    rollback = fake_adapter.rollback
    def partial(*args):
        rollback(*args)
        return RollbackResult(ok=False, output="partial restore")
    monkeypatch.setattr(fake_adapter, "rollback", partial)
    with pytest.raises(EngineError, match="partial restore"):
        ctx.engine.rollback(proposal.id, actor=SAILOR)
    row = next(row for row in poam.poam_rows(ctx) if row["Finding ID"] == first.id)
    assert row["Status"] != "Completed" and row["Scheduled Completion"]
    assert "Rescan after rollback" in row["Milestone"]


def assert_uncertain_views(ctx, finding):
    from cyberthunder.control.policy import assurance_block_reason
    detail = assert_current(ctx, finding, "not_reviewed")
    assert detail["needs_rescan"] and detail["remediated"] is None
    assert "rollback" in assurance_block_reason(ctx, finding)
    row = next(row for row in poam.poam_rows(ctx) if row["Finding ID"] == finding.id)
    assert row["Status"] == "Needs investigation" and row["Scheduled Completion"]
    assert row["Scanner Status"] == "not_a_finding" and row["Scanner Evidence"] == finding.evidence
    data = onepager.build_commander(ctx, None, "md")
    row = next(row for row in data["assurance"]["findings"] if row["id"] == finding.id)
    assert row["current_status"] == "not_reviewed" and row["status"] == "not_a_finding"


@pytest.mark.parametrize("interruption", ["both_completion_writes", "adapter_interrupted"])
def test_unmatched_mutation_boundary_remains_uncertain_after_restart(timeline, make_ctx, fake_adapter, monkeypatch, interruption):
    ctx, proposal, first, observe, now = timeline
    passed = observe()
    before = ctx.store.read_json(ctx.store.scans_dir / passed.scan_id / "findings.json")
    if interruption == "both_completion_writes":
        append, save = ctx.audit.append, snapshot.save_result
        def fail_audit(action, *args, **kwargs):
            if action == "remediation.rollback":
                raise OSError("completion audit failed")
            return append(action, *args, **kwargs)
        def fail_result(path, name, obj):
            if name == "rollback":
                raise OSError("completion result failed")
            return save(path, name, obj)
        monkeypatch.setattr(ctx.audit, "append", fail_audit)
        monkeypatch.setattr(snapshot, "save_result", fail_result)
        expected_error = OSError
    else:
        class InterruptedRestore(BaseException):
            pass
        rollback = fake_adapter.rollback
        def interrupted(*args):
            rollback(*args)
            raise InterruptedRestore("process interrupted after mutation")
        monkeypatch.setattr(fake_adapter, "rollback", interrupted)
        expected_error = InterruptedRestore
    with pytest.raises(expected_error):
        ctx.engine.rollback(proposal.id, actor=SAILOR)
    assert "PermitRootLogin yes" in sshd(ctx)
    assert ctx.gate.get(proposal.id).state is ProposalState.VERIFIED
    # Missing current proposal rows cannot erase the unmatched mutation receipt either.
    ctx.gate._save([p for p in ctx.gate.list() if p.id != proposal.id])
    restarted = make_ctx(auto_propose=False)
    assert_uncertain_views(restarted, passed)
    detail = util.finding_plus(restarted, passed)
    assert detail["rollback"]["uncertain"] and detail["rollback"]["ok"] is None
    assert detail["rollback"]["finished_at"] is None
    assert ctx.store.read_json(ctx.store.scans_dir / passed.scan_id / "findings.json") == before


@pytest.mark.parametrize("boundary", ["mutation_audit", "scope_after_start", "kill_after_start"])
def test_no_mutation_receipt_when_final_guards_or_audit_block_write(timeline, make_ctx, fake_adapter, monkeypatch, boundary):
    from cyberthunder.control.killswitch import KillSwitchEngaged
    from cyberthunder.inventory.targets import ScopeViolation
    ctx, proposal, first, observe, now = timeline
    passed = observe()
    append = ctx.audit.append
    def stop(action, *args, **kwargs):
        if boundary == "mutation_audit" and action == "remediation.rollback_mutation":
            raise OSError("mutation audit failed")
        result = append(action, *args, **kwargs)
        if action == "remediation.rollback_started":
            if boundary == "scope_after_start":
                ctx.inventory.path.unlink()
            elif boundary == "kill_after_start":
                monkeypatch.setenv("CT_KILL", "1")
        return result
    monkeypatch.setattr(ctx.audit, "append", stop)
    monkeypatch.setattr(fake_adapter, "rollback", lambda *args: pytest.fail("restore ran without final authorization/audit"))
    with pytest.raises((OSError, ScopeViolation, KillSwitchEngaged)):
        ctx.engine.rollback(proposal.id, actor=SAILOR)
    assert "PermitRootLogin no" in sshd(ctx)
    assert ctx.gate.get(proposal.id).state is ProposalState.VERIFIED
    assert not any(r["action"] == "remediation.rollback_mutation" for r in ctx.audit.records())
    assert snapshot.load_result(ctx.store.snapshots_dir / proposal.id, "rollback") is None
    view = CurrentFindings.for_context(ctx).assess(passed)
    assert view.finding.status.value == "not_a_finding" and not view.needs_rescan
