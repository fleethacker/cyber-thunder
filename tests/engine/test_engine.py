import pytest

from cyberthunder.control.approvals import IllegalTransition, ProposalState
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.control.policy import AutomationPolicy, PolicyRule
from cyberthunder.inventory.targets import ScopeViolation
from cyberthunder.remediation.engine import EngineError, fix_digest
from cyberthunder.remediation.library import FixEntry

from . import fakes
from .conftest import HOST

SAILOR = "it1.jones"


def scan(ctx):
    run = ctx.scanner.start([HOST], background=False)
    return {f.rule_id: f for f in ctx.store.load_findings(run.id)}


def root_login_proposal(ctx, approve=True):
    f = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    p = ctx.engine.propose(f)
    if approve:
        ctx.gate.approve(p.id, SAILOR, "approved at the deckplate")
    return p


def audit(ctx, action=None, subject=None):
    return [r for r in ctx.audit.records()
            if (action is None or r["action"] == action) and (subject is None or r["subject"] == subject)]


def sshd(ctx):
    return fakes.HOSTS[HOST]["files"][fakes.SSHD]


# -- propose ------------------------------------------------------------------------------
def test_propose_library_fix(make_ctx):
    ctx = make_ctx(auto_propose=False)
    f = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    p = ctx.engine.propose(f)
    assert p.state is ProposalState.PROPOSED and p.fix_ref == "fake:sshd_disable_root_login"
    assert p.fix_preview == fakes.CMD_ROOT_LOGIN
    assert "CAT II" in p.risk and HOST in p.risk and fakes.RULE_ROOT_LOGIN in p.risk
    assert fakes.STIG_ROOT_LOGIN in p.citations and len(p.citations) <= 8
    meta = dict(ctx.gate.get(p.id).history[0]["meta"])
    assert meta.pop("fix_sha256") == fix_digest(ctx.library.get(p.fix_ref))
    assert meta == {"risk_tags": ["disruption:low"], "severity": "medium", "asset_type": "linux"}
    # meta survives a reload of the gate store
    assert make_ctx().gate.get(p.id).history[0]["meta"]["severity"] == "medium"
    # duplicate live proposal refused: the existing one comes back
    assert ctx.engine.propose(f).id == p.id
    assert len(ctx.gate.list()) == 1


def test_propose_uses_explanation_when_present(make_ctx):
    ctx = make_ctx(auto_propose=False)
    f = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    ctx.store.save_explanation(f.id, {"finding_id": f.id, "risk": "Root can log in over SSH.",
                                      "impact": "One stolen password owns the host.", "plan": "Disable it.",
                                      "citations": [fakes.STIG_ROOT_LOGIN]})
    p = ctx.engine.propose(f)
    assert p.risk == "Root can log in over SSH. One stolen password owns the host."


def test_propose_dynamic_ssg_fix(make_ctx):
    ctx = make_ctx(auto_propose=False)
    f = scan(ctx)[fakes.RULE_PASS_MAX]
    p = ctx.engine.propose(f)
    assert p.fix_ref == "ssg:" + fakes.RULE_PASS_MAX
    entry = ctx.library.get(p.fix_ref)
    assert entry.payload.startswith(f"# cyberthunder-fix: {p.fix_ref}\n") and entry.source == "ssg"
    assert entry.payload.endswith(fakes.CMD_PASS_MAX)
    # the files the script names, never the whole /etc directory
    assert entry.before_state == {"files": [fakes.LOGIN_DEFS]} and entry.verify == {"rule_ids": [fakes.RULE_PASS_MAX]}
    assert "CCI-000199" in entry.citations


def test_propose_without_fix_returns_none(make_ctx):
    ctx = make_ctx(auto_propose=False)
    fakes.HOSTS[HOST]["files"][fakes.CRON_BACKDOOR] = "* * * * * root /tmp/x\n"
    run = ctx.scanner.start([HOST], modules=["hunt"], background=False)
    (f,) = ctx.store.load_findings(run.id)
    assert ctx.engine.propose(f) is None


def test_auto_propose_respects_duplicates(make_ctx):
    ctx = make_ctx(auto_propose=False)
    fs = list(scan(ctx).values())
    created = ctx.engine.auto_propose(fs)
    assert len(created) == 2 and all(p.state is ProposalState.PROPOSED for p in created)
    assert ctx.engine.auto_propose(fs) == []
    assert len(ctx.gate.list()) == 2


def _policy(ctx, **rule):
    pol = AutomationPolicy(rules=[PolicyRule(name="low-risk sshd", asset_types=["linux"], **rule)])
    pol.sign("cdr.ops", "standing approval for low-disruption config fixes")
    ctx.save_policy(pol, "cdr.ops")


def test_policy_auto_approval(make_ctx):
    ctx = make_ctx(auto_propose=False)
    _policy(ctx, fix_allowlist=["fake:sshd_disable_root_login"])
    created = {p.fix_ref: p for p in ctx.engine.auto_propose(scan(ctx).values())}
    approved = ctx.gate.get(created["fake:sshd_disable_root_login"].id)
    assert approved.state is ProposalState.APPROVED and approved.decided_by == "policy:cdr.ops"
    other = ctx.gate.get(created["ssg:" + fakes.RULE_PASS_MAX].id)
    assert other.state is ProposalState.PROPOSED
    (rec,) = audit(ctx, "policy.auto_approve")
    assert rec["details"]["decision"]["auto_eligible"] is True and rec["subject"] == approved.id
    assert audit(ctx, "policy.evaluate")[0]["outcome"] == "declined"


def test_policy_skipped_when_kill_switch_engaged(make_ctx):
    ctx = make_ctx(auto_propose=False)
    _policy(ctx)
    found = scan(ctx).values()
    ctx.killswitch.engage(SAILOR, "drill")
    created = ctx.engine.auto_propose(found)
    assert created and all(ctx.gate.get(p.id).state is ProposalState.PROPOSED for p in created)
    assert len(audit(ctx, "policy.skipped")) == len(created)
    assert not audit(ctx, "policy.auto_approve")


# -- execute ------------------------------------------------------------------------------
def test_execute_happy_path_verified(make_ctx):
    ctx = make_ctx(auto_propose=False)
    p = root_login_proposal(ctx)
    out = ctx.engine.execute(p.id, actor=SAILOR)
    assert out.state is ProposalState.VERIFIED
    assert "PermitRootLogin no" in sshd(ctx)
    snap = ctx.store.snapshot_dir(p.id)
    for name in ("before_state.json", "apply.json", "verify.json", "fix.json"):
        assert (snap / name).exists(), name
    assert (snap / "files" / "etc" / "ssh" / "sshd_config").read_text(encoding="utf-8").count("PermitRootLogin yes")
    assert out.before_state_ref == str(snap)
    states = [h["state"] for h in out.history]
    assert states == ["proposed", "approved", "applying", "applied", "verified"]
    assert all(h["note"] for h in out.history[2 + 1:])          # applied/verified edges carry notes
    v = audit(ctx, "remediation.verify", p.id)[0]
    assert v["details"]["simulated"] is False and v["outcome"] == "ok"
    assert all(t.closed for t in ctx.adapters.get("linux").transports_made)


def test_simulated_verify_fail_rolls_back(make_ctx):
    ctx = make_ctx(auto_propose=False)
    seed = sshd(ctx)
    p = root_login_proposal(ctx)
    out = ctx.engine.execute(p.id, actor=SAILOR, simulate_verify_fail=True)
    assert out.state is ProposalState.ROLLED_BACK
    assert [h["state"] for h in out.history][-3:] == ["applied", "failed", "rolled_back"]
    assert sshd(ctx) == seed                                     # fake host restored
    v = audit(ctx, "remediation.verify", p.id)[0]
    assert v["details"]["simulated"] is True and v["outcome"] == "failed"
    assert (ctx.store.snapshot_dir(p.id) / "rollback.json").exists()


def test_apply_exception_rolls_back(make_ctx, fake_adapter):
    ctx = make_ctx(auto_propose=False)
    seed = sshd(ctx)
    p = root_login_proposal(ctx)
    fake_adapter.raise_on_apply = "disk full"
    out = ctx.engine.execute(p.id, actor=SAILOR)
    assert out.state is ProposalState.ROLLED_BACK
    failed = [h for h in out.history if h["state"] == "failed"][0]
    assert "disk full" in failed["note"]
    assert sshd(ctx) == seed


def test_fix_changed_after_approval_is_blocked(make_ctx):
    ctx = make_ctx(auto_propose=False)
    seed = fakes.seed_state()
    p = root_login_proposal(ctx)
    ctx.library.get(p.fix_ref).payload = "fake-break-sshd"     # library entry edited after approval
    with pytest.raises(EngineError):
        ctx.engine.execute(p.id, actor=SAILOR)
    assert ctx.gate.get(p.id).state is ProposalState.APPROVED
    assert audit(ctx, "action.blocked", p.id)
    assert fakes.HOSTS[HOST] == seed


def test_apply_reports_failure_and_rollback_restores(make_ctx):
    ctx = make_ctx(auto_propose=False)
    seed = fakes.seed_state()
    f = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    entry = FixEntry(fix_ref="fake:broken_sshd", title="Broken fix", asset_type="linux",
                     applies_to=[fakes.RULE_ROOT_LOGIN], payload="fake-break-sshd",
                     before_state={"files": [fakes.SSHD]})
    ctx.library.add(entry)
    p = ctx.engine.propose(f, fix=entry)
    ctx.gate.approve(p.id, SAILOR)
    out = ctx.engine.execute(p.id, actor=SAILOR)
    assert out.state is ProposalState.ROLLED_BACK
    assert "apply failed" in [h for h in out.history if h["state"] == "failed"][0]["note"]
    assert fakes.HOSTS[HOST] == seed                           # file and service state restored


def test_rollback_error_leaves_failed(make_ctx, fake_adapter, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    p = root_login_proposal(ctx)

    def bad_rollback(*a, **k):
        raise RuntimeError("backup unreadable")
    monkeypatch.setattr(fake_adapter, "rollback", bad_rollback)
    out = ctx.engine.execute(p.id, actor=SAILOR, simulate_verify_fail=True)
    assert out.state is ProposalState.FAILED
    (rec,) = audit(ctx, "proposal.rollback_error", p.id)
    assert rec["outcome"] == "error" and "backup unreadable" in rec["details"]["error"]


def test_execute_refused_when_not_approved(make_ctx):
    ctx = make_ctx(auto_propose=False)
    p = root_login_proposal(ctx, approve=False)
    with pytest.raises(IllegalTransition):
        ctx.engine.execute(p.id, actor=SAILOR)
    assert ctx.gate.get(p.id).state is ProposalState.PROPOSED
    assert audit(ctx, "proposal.applying", p.id)[0]["outcome"] == "rejected"
    assert "PermitRootLogin yes" in sshd(ctx)


def test_execute_refused_when_kill_switch_engaged(make_ctx, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    p = root_login_proposal(ctx)
    ctx.killswitch.engage(SAILOR, "stop everything")
    with pytest.raises(KillSwitchEngaged):
        ctx.engine.execute(p.id, actor=SAILOR)
    assert ctx.gate.get(p.id).state is ProposalState.APPROVED
    assert audit(ctx, "action.blocked")[-1]["outcome"] == "blocked"
    assert "PermitRootLogin yes" in sshd(ctx)
    ctx.killswitch.release(SAILOR, "drill over")
    monkeypatch.setenv("CT_KILL", "1")
    with pytest.raises(KillSwitchEngaged):
        ctx.engine.execute(p.id, actor=SAILOR)
    assert ctx.gate.get(p.id).state is ProposalState.APPROVED


def test_scope_violation_during_execute(make_ctx):
    ctx = make_ctx(auto_propose=False)
    p = root_login_proposal(ctx)
    ctx.inventory.update(HOST, in_scope=False)
    with pytest.raises(ScopeViolation):
        ctx.engine.execute(p.id, actor=SAILOR)
    rec = audit(ctx, "action.blocked", p.id)[0]
    assert rec["outcome"] == "blocked" and rec["details"]["action"] == "execute"
    assert ctx.gate.get(p.id).state is ProposalState.APPROVED
    assert "PermitRootLogin yes" in sshd(ctx)


def test_execute_dynamic_ssg_fix_in_new_context(make_ctx):
    ctx = make_ctx(auto_propose=False)
    f = scan(ctx)[fakes.RULE_PASS_MAX]
    p = ctx.engine.propose(f)
    ctx.gate.approve(p.id, SAILOR)
    fresh = make_ctx()                                           # like the CLI: library rebuilt from adapters
    assert fresh.library.get(p.fix_ref) is None
    out = fresh.engine.execute(p.id, actor=SAILOR)
    assert out.state is ProposalState.VERIFIED
    assert "PASS_MAX_DAYS 60" in fakes.HOSTS[HOST]["files"][fakes.LOGIN_DEFS]


# -- manual rollback and diff -------------------------------------------------------------
def test_manual_rollback_of_verified(make_ctx):
    ctx = make_ctx(auto_propose=False)
    seed = sshd(ctx)
    p = root_login_proposal(ctx)
    ctx.engine.execute(p.id, actor=SAILOR)
    out = ctx.engine.rollback(p.id, actor=SAILOR)
    assert out.state is ProposalState.ROLLED_BACK and sshd(ctx) == seed
    assert out.history[-1]["actor"] == SAILOR and "manual rollback" in out.history[-1]["note"]
    with pytest.raises(IllegalTransition):
        ctx.engine.rollback(p.id, actor=SAILOR)


def test_manual_rollback_blocked_by_kill_switch(make_ctx):
    ctx = make_ctx(auto_propose=False)
    p = root_login_proposal(ctx)
    ctx.engine.execute(p.id, actor=SAILOR)
    ctx.killswitch.engage(SAILOR, "hold")
    with pytest.raises(KillSwitchEngaged):
        ctx.engine.rollback(p.id, actor=SAILOR)
    assert ctx.gate.get(p.id).state is ProposalState.VERIFIED
    assert "PermitRootLogin no" in sshd(ctx)


def test_diff_shape(make_ctx):
    ctx = make_ctx(auto_propose=False)
    p = root_login_proposal(ctx)
    ctx.engine.execute(p.id, actor=SAILOR)
    d = ctx.engine.diff(p.id)
    assert set(d) == {"proposal", "fix", "before_state", "apply", "verify", "rollback", "files", "rollback_guard"}
    assert d["proposal"]["state"] == "verified" and d["fix"]["fix_ref"] == p.fix_ref
    assert d["apply"]["ok"] is True and d["verify"]["ok"] is True and d["rollback"] is None
    (fd,) = d["files"]
    assert fd["path"] == fakes.SSHD
    assert "PermitRootLogin yes" in fd["before_excerpt"] and "PermitRootLogin no" in fd["after_excerpt"]
    assert "-PermitRootLogin yes" in fd["diff"] and "+PermitRootLogin no" in fd["diff"]
