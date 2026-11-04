"""Kill switch, human-only actions, runbook handling and fix integrity in the scanner and the engine."""
import dataclasses

import pytest

from cyberthunder.control.approvals import IllegalTransition, ProposalState
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.inventory.targets import Target
from cyberthunder.remediation import snapshot
from cyberthunder.remediation.engine import EngineError, RUNBOOK_NOTE, dynamic_ssg_fix
from cyberthunder.remediation.library import FixEntry
from cyberthunder.remediation.models import HealthResult, VerifyResult

from . import fakes
from .conftest import HOST
from .test_engine import SAILOR, audit, root_login_proposal, scan, sshd

HOST2 = "rhel-02"
ROOT_FIX = "fake:sshd_disable_root_login"


def runbook(fix_ref=ROOT_FIX):
    return FixEntry(fix_ref=fix_ref, title="Disable SSH root login (by hand)", asset_type="linux",
                    applies_to=[fakes.RULE_ROOT_LOGIN], kind="runbook",
                    steps=["Set PermitRootLogin no in /etc/ssh/sshd_config", "Restart sshd"],
                    rollback_kind="manual", before_state={"files": [fakes.SSHD]},
                    verify={"rule_ids": [fakes.RULE_ROOT_LOGIN]}, citations=[fakes.STIG_ROOT_LOGIN])


def actions(ctx, subject):
    return [r["action"] for r in audit(ctx, subject=subject)]


# -- scanner and the kill switch ------------------------------------------------------------
def test_scan_refused_while_killed(ctx):
    ctx.killswitch.engage(SAILOR, "incident")
    with pytest.raises(KillSwitchEngaged):
        ctx.scanner.start([HOST], background=False)
    (rec,) = audit(ctx, "action.blocked")
    assert rec["details"]["action"] == "scan.start"
    assert not audit(ctx, "scan.start") and fakes.HOSTS[HOST] == fakes.seed_state()


def test_scan_stops_remaining_targets_when_killed(make_ctx, fake_adapter, monkeypatch):
    ctx = make_ctx(auto_propose=True)
    ctx.inventory.add(Target(id=HOST2, name="RHEL 9 db", asset_type="linux", transport="simulated"))
    fakes.HOSTS[HOST2] = fakes.seed_state()
    real_collect = fake_adapter.collect

    def collect_then_kill(*a, **kw):
        out = real_collect(*a, **kw)
        ctx.killswitch.engage(SAILOR, "incident during scan")
        return out

    monkeypatch.setattr(fake_adapter, "collect", collect_then_kill)
    run = ctx.scanner.start([HOST, HOST2], background=False)
    assert run.status == "stopped"
    assert run.results[HOST].status == "done" and run.results[HOST2].status == "stopped"
    assert [t.calls for t in fake_adapter.transports_made] == [["fake-dump"]]     # nothing ran on rhel-02
    (fin,) = audit(ctx, "scan.finish")
    assert fin["outcome"] == "blocked"
    assert ctx.gate.list() == [] and "proposals_created" not in run.summary


def test_full_scan_rematches_bulletins(make_ctx, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    calls = []

    class Ingest:
        def rematch_all(self, scan_id, **kw):
            calls.append(scan_id)
            return {"scan_id": "scan-b", "bulletins": ["b1"], "findings": 3, "hosts_affected": [HOST]}

    monkeypatch.setattr(ctx, "ingest", Ingest(), raising=False)
    run = ctx.scanner.start([HOST], background=False)
    assert calls == [run.id]
    assert ctx.scanner.get(run.id).summary["bulletins_rematched"] == {"scan_id": "scan-b", "bulletins": 1,
                                                                      "findings": 3}
    ctx.scanner.start([HOST], rule_filter=[fakes.RULE_ROOT_LOGIN], background=False)
    assert len(calls) == 1                       # a targeted rescan is not a full picture


# -- rollback ---------------------------------------------------------------------------------
def test_rollback_after_library_change(make_ctx):
    ctx = make_ctx(auto_propose=False)
    seed = sshd(ctx)
    p = root_login_proposal(ctx)
    assert ctx.engine.execute(p.id, actor=SAILOR).state is ProposalState.VERIFIED
    changed = dataclasses.replace(ctx.library.get(ROOT_FIX), payload="fake-sshd-set PermitRootLogin prohibit-password")
    ctx.library.add(changed)
    out = ctx.engine.rollback(p.id, actor=SAILOR)
    assert out.state is ProposalState.ROLLED_BACK and sshd(ctx) == seed


def test_rollback_recorded_when_kill_switch_engaged_after_host_rollback(make_ctx, fake_adapter, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    seed = sshd(ctx)
    p = root_login_proposal(ctx)
    ctx.engine.execute(p.id, actor=SAILOR)
    real_rollback = fake_adapter.rollback

    def rollback_then_kill(*a, **kw):
        out = real_rollback(*a, **kw)
        ctx.killswitch.engage(SAILOR, "hit mid-rollback")
        return out

    monkeypatch.setattr(fake_adapter, "rollback", rollback_then_kill)
    out = ctx.engine.rollback(p.id, actor=SAILOR)
    assert out.state is ProposalState.ROLLED_BACK and sshd(ctx) == seed
    (rec,) = audit(ctx, "proposal.rolled_back", p.id)
    assert rec["outcome"] != "blocked" and rec["actor"] == SAILOR
    assert not [r for r in audit(ctx, "action.blocked") if p.id in r["details"].get("action", "")]
    # the switch still blocks the next host action
    with pytest.raises(KillSwitchEngaged):
        ctx.engine.execute(root_login_proposal(ctx).id, actor=SAILOR)


def test_manual_rollback_needs_a_named_operator(make_ctx):
    ctx = make_ctx(auto_propose=False)
    p = root_login_proposal(ctx)
    ctx.engine.execute(p.id, actor=SAILOR)
    for actor in ("agent", "llm-1", "", "policy:cdr.ops"):
        with pytest.raises(PermissionError):
            ctx.engine.rollback(p.id, actor=actor)
    assert ctx.gate.get(p.id).state is ProposalState.VERIFIED and "PermitRootLogin no" in sshd(ctx)
    assert len([r for r in audit(ctx, "action.blocked", p.id) if r["details"]["action"] == "rollback"]) == 4


# -- runbooks ---------------------------------------------------------------------------------
def test_runbook_is_issued_not_failed_or_rolled_back(make_ctx, fake_adapter, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    seed = sshd(ctx)
    f = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    p = ctx.engine.propose(f, fix=runbook("fake:runbook:root_login"))
    ctx.gate.approve(p.id, SAILOR)
    monkeypatch.setattr(fake_adapter, "apply", lambda *a, **kw: pytest.fail("a runbook must not be applied"))
    out = ctx.engine.execute(p.id, actor=SAILOR)
    assert out.state is ProposalState.APPLIED and RUNBOOK_NOTE in out.history[-1]["note"]
    assert sshd(ctx) == seed
    snap = ctx.store.snapshot_dir(p.id)
    assert snapshot.load_before_state(snap).files == [fakes.SSHD]
    assert snapshot.load_result(snap, "apply")["changed"] is False
    assert snapshot.load_result(snap, "verify") is None
    acts = actions(ctx, p.id)
    assert "remediation.runbook_issued" in acts
    assert not {"proposal.failed", "proposal.rolled_back", "proposal.verified"} & set(acts)

    # the operator does the steps, then confirms
    fakes.FakeTransport(fakes.HOSTS[HOST]).run(fakes.CMD_ROOT_LOGIN)
    done = ctx.engine.verify(p.id, actor=SAILOR)
    assert done.state is ProposalState.VERIFIED and done.history[-1]["actor"] == SAILOR


def test_runbook_verify_before_steps_fails_without_rollback(make_ctx):
    ctx = make_ctx(auto_propose=False)
    f = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    p = ctx.engine.propose(f, fix=runbook("fake:runbook:root_login"))
    ctx.gate.approve(p.id, SAILOR)
    ctx.engine.execute(p.id, actor=SAILOR)
    with pytest.raises(PermissionError):
        ctx.engine.verify(p.id, actor="agent")
    out = ctx.engine.verify(p.id, actor=SAILOR)
    assert out.state is ProposalState.FAILED
    assert "proposal.rolled_back" not in actions(ctx, p.id)
    with pytest.raises(IllegalTransition):
        ctx.engine.verify(p.id, actor=SAILOR)


def test_auto_propose_skips_runbooks_unless_enabled(make_ctx, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    monkeypatch.delenv("CT_AUTO_PROPOSE_RUNBOOKS", raising=False)
    found = scan(ctx)
    ctx.library.add(runbook())
    created = ctx.engine.auto_propose(found.values())
    assert [p.fix_ref for p in created] == ["ssg:" + fakes.RULE_PASS_MAX]
    monkeypatch.setenv("CT_AUTO_PROPOSE_RUNBOOKS", "true")
    assert [p.fix_ref for p in ctx.engine.auto_propose(found.values())] == [ROOT_FIX]


def test_no_rule_recheck_is_not_verified(make_ctx, fake_adapter, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    p = root_login_proposal(ctx)
    monkeypatch.setattr(fake_adapter, "verify", lambda *a, **kw: VerifyResult(
        ok=True, rule_passed=None, health=HealthResult(ok=True), evidence="no automated rule re-check"))
    out = ctx.engine.execute(p.id, actor=SAILOR)
    assert out.state is ProposalState.APPLIED
    (rec,) = audit(ctx, "remediation.verify", p.id)
    assert rec["outcome"] == "manual" and rec["details"]["note"] == "needs manual verification"
    assert "proposal.verified" not in actions(ctx, p.id)


# -- fix integrity and records ----------------------------------------------------------------
def test_dynamic_fix_not_offered_for_simulated_target(make_ctx):
    ctx = make_ctx(auto_propose=False)
    f = scan(ctx)[fakes.RULE_PASS_MAX]
    ctx.inventory.update(HOST, simulated=True)
    assert ctx.engine.propose(f) is None


def test_dynamic_fix_never_captures_etc_directory():
    from cyberthunder.findings.schema import Finding
    f = Finding(host="h", source="openscap", rule_id="xccdf_org.ssgproject.content_rule_sshd_set_idle",
                title="Set idle timeout", severity="medium", status="open")
    f.fix_script = "if [ -e /etc/ssh/ ]; then\n  sed -i 's/^ClientAlive.*//' /etc/ssh/sshd_config.d/00.conf\nfi\n"
    entry = dynamic_ssg_fix(f)
    assert "/etc" not in entry.before_state["files"]
    assert entry.before_state["files"] == ["/etc/ssh", "/etc/ssh/sshd_config.d/00.conf", "/etc/ssh/sshd_config"]
    assert entry.payload.splitlines()[0] == "# cyberthunder-fix: ssg:xccdf_org.ssgproject.content_rule_sshd_set_idle"


def test_blast_radius_change_after_approval_is_blocked(make_ctx):
    ctx = make_ctx(auto_propose=False)
    p = root_login_proposal(ctx)
    ctx.library.add(dataclasses.replace(ctx.library.get(ROOT_FIX), reboot=True))      # same payload, now reboots
    with pytest.raises(EngineError, match="changed since it was approved"):
        ctx.engine.execute(p.id, actor=SAILOR)
    assert ctx.gate.get(p.id).state is ProposalState.APPROVED and "PermitRootLogin yes" in sshd(ctx)


def test_apply_and_verify_errors_are_saved(make_ctx, fake_adapter, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    p = root_login_proposal(ctx)
    fake_adapter.raise_on_apply = "connection dropped mid-apply"
    ctx.engine.execute(p.id, actor=SAILOR)
    ar = ctx.engine.diff(p.id)["apply"]
    assert ar["ok"] is False and "connection dropped mid-apply" in ar["output"]

    fake_adapter.raise_on_apply = None
    fakes.reset_hosts(HOST)
    q = root_login_proposal(ctx)

    def boom(*a, **kw):
        raise RuntimeError("verify collector crashed")

    monkeypatch.setattr(fake_adapter, "verify", boom)
    ctx.engine.execute(q.id, actor=SAILOR)
    d = ctx.engine.diff(q.id)
    assert d["apply"]["ok"] is True
    assert d["verify"]["ok"] is False and "verify collector crashed" in d["verify"]["evidence"]
