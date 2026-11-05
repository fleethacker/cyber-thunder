"""Static previews must never enter remediation or transport code, on either backend."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

import pytest

from cyberthunder.cli import main
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.control.policy import AutomationPolicy, PolicyRule
from cyberthunder.findings.review import ReviewService
from cyberthunder.findings.schema import Finding
from cyberthunder.inventory.targets import Target
from cyberthunder.remediation import cli, snapshot
from cyberthunder.remediation.engine import EngineError, RemediationEngine, dynamic_ssg_fix, fix_digest
from cyberthunder.remediation.library import FixEntry, FixLibrary

ACTOR = "ITC Rivera"
HOST = "rhel-01"


def persist(ctx, findings, sid="plan-scan", offset=0):
    started = (datetime.now(timezone.utc) + timedelta(seconds=offset)).isoformat()
    ctx.store.save_scan_run({"id": sid, "started_at": started, "status": "done"})
    ctx.store.save_findings(sid, findings)


def seed(ctx, *, approved=False, kind="script", dynamic=False):
    ctx.engine = RemediationEngine(ctx)
    ctx.inventory.add(Target(id=HOST, name="Test host", asset_type="linux", transport="fixture",
                             address="192.0.2.37", username="private-user", credential_ref="private-key",
                             options={"credential": "private-option"}))
    ctx.inventory.save()
    now = datetime.now(timezone.utc).isoformat()
    finding = Finding(host=HOST, source="openscap", rule_id="plan_rule", title="Static test finding",
                      severity="medium", status="open", asset_type="linux", evidence="Setting enabled",
                      collected_at=now, collection_provenance={"simulated": False, "observed_at": now})
    if dynamic:
        finding.fix_script = "printf vetted > /etc/static-test\n"
        fix = dynamic_ssg_fix(finding)
    else:
        fix = FixEntry(fix_ref="test:static", title="Static test fix", asset_type="linux",
                       applies_to=[finding.rule_id], kind=kind,
                       payload="" if kind == "runbook" else "printf vetted > /etc/static-test\n",
                       steps=["Review the configuration with its owner."] if kind == "runbook" else [],
                       before_state={"files": ["/etc/static-test"], "commands": {"state": "capture-must-not-run"}},
                       verify={"commands": {"check": "verify-must-not-run"}}, reboot=True,
                       restarts_services=["test-service"], rollback_steps=["Restore captured configuration."])
    ctx.library.add(fix)
    persist(ctx, [finding])
    proposal = ctx.engine.propose(finding, actor=ACTOR)
    if approved:
        ctx.gate.approve(proposal.id, ACTOR)
    ctx.store.write_json(ctx.store.root / "demo.json", {"simulate_verify_fail_next": True})
    return finding, proposal, fix


def forbid_side_effects(monkeypatch, ctx):
    """Tripwires, including API background/demo entry points and all registered adapters."""
    from cyberthunder.api import util
    from cyberthunder.api.routes import proposals
    from cyberthunder import demo

    def forbidden(*args, **kwargs):
        pytest.fail("static preview attempted execution, collection, generation or a state write")

    for obj, names in (
        (ctx, ("transport_for", "adapter_for")),
        (ctx.engine, ("execute", "verify", "rollback", "_fix_for", "_applied_fix", "_resolve", "_dynamic", "_adapter")),
        (ctx.scanner, ("start", "run")),
        (ctx.explain, ("get", "explain", "precompute")),
        (ctx.store, ("snapshot_dir", "scan_dir", "write_json", "delete_json", "save_scan_run", "save_findings")),
        (ctx.store.docs, ("put", "delete")),
        (ctx.library, ("add", "extend")),
        (ctx.gate, ("_save", "propose", "approve", "approve_by_policy", "start_apply", "applied", "verified", "failed", "rolled_back")),
        (snapshot, ("save_result", "save_before_state", "_write")),
        (util, ("run_background", "demo_module")),
        (proposals, ("_demo_forces_failure",)),
        (demo, ("consume_simulate_verify_fail",)),
    ):
        for name in names:
            monkeypatch.setattr(obj, name, forbidden)
    for adapter in ctx.adapters.all():
        for name in ("make_transport", "collect", "capture_before_state", "apply", "verify", "rollback", "health_check"):
            monkeypatch.setattr(adapter, name, forbidden)


def stored_state(ctx):
    return {
        "proposals": ctx.store.proposals.read_bytes(),
        "snapshots": {str(p.relative_to(ctx.store.snapshots_dir)): p.read_bytes() if p.is_file() else None
                      for p in ctx.store.snapshots_dir.rglob("*")},
        "library": deepcopy([f.to_dict() for f in ctx.library.all()]),
        "findings": [f.to_dict() for f in ctx.store.current_findings()],
        "demo": ctx.store.read_json(ctx.store.root / "demo.json"),
        "inventory": ctx.store.targets.read_bytes(),
    }


def statuses(plan):
    return {c["code"]: c["status"] for c in plan["checks"]}


def policy_approve(ctx, proposal):
    policy = AutomationPolicy(rules=[PolicyRule("test")])
    policy.sign(ACTOR, "Fixture standing approval")
    ctx.save_policy(policy, ACTOR)
    ctx.gate.approve_by_policy(proposal.id, policy)


@pytest.mark.parametrize("approved", [False, True])
@pytest.mark.parametrize("kind", ["script", "runbook"])
def test_static_contract_and_only_one_redacted_audit(ctx, monkeypatch, approved, kind):
    finding, p, fix = seed(ctx, approved=approved, kind=kind)
    before, seq = stored_state(ctx), len(ctx.audit)
    forbid_side_effects(monkeypatch, ctx)
    plan = ctx.engine.plan(p.id, actor=f" {ACTOR} ")
    assert set(plan) == {"version", "mode", "generated_at", "proposal_id", "proposal_state", "target",
                         "fix", "fix_sha256", "approved_fix_sha256", "checks", "limitations"}
    assert plan["version"] == 1 and plan["mode"] == "static"
    assert datetime.fromisoformat(plan["generated_at"]).utcoffset() == timedelta(0)
    assert plan["proposal_id"] == p.id and plan["proposal_state"] == ("approved" if approved else "proposed")
    assert plan["target"] == {"id": HOST, "name": "Test host", "asset_type": "linux", "simulated": False, "in_scope": True}
    assert plan["fix"] == fix.to_dict()
    assert plan["fix_sha256"] == plan["approved_fix_sha256"] == fix_digest(fix)
    assert statuses(plan) == {"scope": "pass", "approval": "pass" if approved else "blocked",
                              "fix_binding": "pass", "current_finding": "pass", "suppression": "pass",
                              "policy_evidence": "unknown"}
    assert all(set(c) == {"code", "status", "detail"} and c["detail"] for c in plan["checks"])
    text = json.dumps(plan)
    for secret in ("192.0.2.37", "private-user", "private-key", "private-option", "credential_ref", '"options"'):
        assert secret not in text
    limitations = " ".join(plan["limitations"])
    for phrase in ("Static metadata", "access", "applicability", "lockout safety", "NOT an exhaustive", "Maintenance windows"):
        assert phrase in limitations
    records = list(ctx.audit.records())[seq:]
    assert len(records) == 1
    record = records[0]
    assert record["action"] == "remediation.plan" and record["actor"] == ACTOR and record["subject"] == p.id
    assert record["details"] == {"proposal_id": p.id, "finding_id": finding.id, "target_id": HOST,
                                  "fix_ref": fix.fix_ref, "fix_sha256": fix_digest(fix),
                                  "approved_fix_sha256": fix_digest(fix), "checks": statuses(plan)}
    assert stored_state(ctx) == before


@pytest.mark.parametrize("actor", [None, "", "  ", "agent", "AGENT:planner", "system2", "policy:Rivera"])
def test_plan_requires_named_human(ctx, monkeypatch, actor):
    _, p, _ = seed(ctx)
    forbid_side_effects(monkeypatch, ctx)
    with pytest.raises(PermissionError):
        ctx.engine.plan(p.id, actor=actor)
    with pytest.raises(TypeError):
        ctx.engine.plan(p.id)


@pytest.mark.parametrize("via", ["env", "sentinel", "state"])
def test_kill_blocks_before_content_lookup(ctx, monkeypatch, via):
    _, p, _ = seed(ctx)
    if via == "env":
        monkeypatch.setenv("CT_KILL", "1")
    elif via == "sentinel":
        ctx.killswitch.sentinel.touch()
    else:
        ctx.killswitch.engage(ACTOR)
    forbid_side_effects(monkeypatch, ctx)
    monkeypatch.setattr(ctx.library, "get", lambda *a: pytest.fail("read fix despite kill"))
    with pytest.raises(KillSwitchEngaged):
        ctx.engine.plan(p.id, actor=ACTOR)


@pytest.mark.parametrize("scope", ["missing", "out"])
def test_scope_is_metadata_and_does_not_authorize(ctx, monkeypatch, scope):
    _, p, _ = seed(ctx, approved=True)
    if scope == "missing":
        ctx.inventory.remove(HOST)
    else:
        ctx.inventory.update(HOST, in_scope=False)
    forbid_side_effects(monkeypatch, ctx)
    result = ctx.engine.plan(p.id, actor=ACTOR)
    assert statuses(result)["scope"] == ("unknown" if scope == "missing" else "blocked")
    if scope == "missing":
        assert result["target"] == {"id": HOST, "name": None, "asset_type": None, "simulated": None, "in_scope": None}
    else:
        assert result["target"]["in_scope"] is False


@pytest.mark.parametrize("change", ["payload", "before_state", "verify", "reboot", "steps", "fix_ref"])
def test_changed_fix_refused_even_when_original_snapshot_exists(ctx, monkeypatch, change):
    _, p, fix = seed(ctx, approved=True)
    values = {"payload": "different", "before_state": {"files": ["/etc/other"]}, "verify": {},
              "reboot": False, "steps": ["different"], "fix_ref": "other:fix"}
    setattr(fix, change, values[change])
    before = stored_state(ctx)
    forbid_side_effects(monkeypatch, ctx)
    with pytest.raises(EngineError):
        ctx.engine.plan(p.id, actor=ACTOR)
    assert stored_state(ctx) == before


@pytest.mark.parametrize("saved", ["valid", "missing", "wrong_ref", "invalid"])
def test_saved_fix_lookup_never_creates_or_updates_snapshot(ctx, monkeypatch, saved):
    _, p, fix = seed(ctx, approved=True)
    ctx.library = FixLibrary()
    path = ctx.store.snapshots_dir / p.id / "fix.json"
    if saved == "missing":
        path.unlink()
        path.parent.rmdir()
    elif saved == "wrong_ref":
        snapshot.save_result(path.parent, "fix", replace(fix, fix_ref="wrong"))
    elif saved == "invalid":
        path.write_text("{bad-json", encoding="utf-8")
    before = stored_state(ctx)
    forbid_side_effects(monkeypatch, ctx)
    if saved == "valid":
        assert ctx.engine.plan(p.id, actor=ACTOR)["fix"] == fix.to_dict()
    else:
        with pytest.raises(EngineError):
            ctx.engine.plan(p.id, actor=ACTOR)
    assert stored_state(ctx) == before


@pytest.mark.parametrize("historical", [False, True])
def test_dynamic_stored_content_can_be_reconstructed_without_library_write(ctx, monkeypatch, historical):
    finding, p, fix = seed(ctx, dynamic=True)
    path = ctx.store.snapshots_dir / p.id / "fix.json"
    path.unlink()
    path.parent.rmdir()
    ctx.library = FixLibrary()
    if historical:
        policy_approve(ctx, p)
        persist(ctx, [], "new-scan", offset=10)
        assert ctx.store.get_finding(finding.id) is not None
    before = stored_state(ctx)
    forbid_side_effects(monkeypatch, ctx)
    result = ctx.engine.plan(p.id, actor=ACTOR)
    assert result["fix"] == fix.to_dict()
    assert statuses(result)["current_finding"] == ("unknown" if historical else "pass")
    if historical:
        assert statuses(result)["suppression"] == "unknown"
        assert statuses(result)["policy_evidence"] == "blocked"
    assert stored_state(ctx) == before


def test_legacy_preview_binding_is_explicitly_unknown(ctx, monkeypatch):
    finding, old, fix = seed(ctx)
    ctx.gate.cancel(old.id, ACTOR)
    p = ctx.gate.propose(actor=ACTOR, finding_id=finding.id, host=HOST, title=fix.title,
                         fix_ref=fix.fix_ref, fix_preview=fix.preview_text(), rollback_plan=fix.rollback_plan_text(), risk="")
    forbid_side_effects(monkeypatch, ctx)
    result = ctx.engine.plan(p.id, actor=ACTOR)
    assert result["approved_fix_sha256"] is None
    assert statuses(result)["fix_binding"] == "unknown"
    assert not (ctx.store.snapshots_dir / p.id).exists()


@pytest.mark.parametrize("current", ["missing", "wrong_host", "closed", "stale", "fresh"])
def test_readiness_uses_current_matching_finding_only(ctx, monkeypatch, current):
    finding, p, _ = seed(ctx)
    policy_approve(ctx, p)
    if current == "missing":
        findings = []
    elif current == "wrong_host":
        findings = [replace(finding, host="different-host")]
    elif current == "closed":
        findings = [replace(finding, status="not_a_finding")]
    elif current == "stale":
        old = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
        findings = [replace(finding, collection_provenance={"simulated": False, "observed_at": old})]
    else:
        findings = [finding]
    persist(ctx, findings, "current-scan", offset=10)
    # Both the historical store fallback and engine cache would otherwise return the old good observation.
    assert ctx.engine._findings[finding.id].host == HOST
    forbid_side_effects(monkeypatch, ctx)
    monkeypatch.setattr(ctx.store, "get_finding", lambda *a: pytest.fail("readiness used historical lookup"))
    result = ctx.engine.plan(p.id, actor=ACTOR)
    checks = statuses(result)
    assert checks["policy_evidence"] == ("pass" if current == "fresh" else "blocked")
    if current in ("missing", "wrong_host"):
        assert checks["suppression"] == "unknown"
        assert checks["current_finding"] == ("unknown" if current == "missing" else "blocked")
    if current == "stale":
        assert "seven-day" in next(c["detail"] for c in result["checks"] if c["code"] == "policy_evidence")


@pytest.mark.parametrize("disposition", ["false_positive", "not_applicable", "needs_investigation"])
def test_current_review_and_policy_evidence_are_reported_without_mutating(ctx, monkeypatch, disposition):
    finding, p, _ = seed(ctx)
    policy_approve(ctx, p)
    service = ReviewService(ctx)
    summary = service.summary(finding)
    service.save(finding, actor=ACTOR, disposition=disposition, reason="Fixture review",
                 expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                 expected_revision=summary["revision"], evidence_fingerprint=summary["evidence_fingerprint"])
    before = service.history(finding)
    forbid_side_effects(monkeypatch, ctx)
    checks = statuses(ctx.engine.plan(p.id, actor=ACTOR))
    assert checks["suppression"] == ("pass" if disposition == "needs_investigation" else "blocked")
    assert checks["policy_evidence"] == "blocked"
    assert service.history(finding) == before


@pytest.mark.parametrize("approved", [False, True])
def test_cli_plan_outputs_only_json_and_never_executes(ctx, monkeypatch, capsys, approved):
    _, p, _ = seed(ctx, approved=approved)
    before = stored_state(ctx)
    forbid_side_effects(monkeypatch, ctx)
    monkeypatch.setattr(cli, "_ctx", lambda a: ctx)
    assert main(["--actor", ACTOR, "apply", p.id, "--plan"]) == 0
    output = capsys.readouterr()
    assert not output.err
    assert json.loads(output.out)["mode"] == "static"
    assert stored_state(ctx) == before


@pytest.mark.parametrize("direct", [False, True])
def test_cli_rejects_contradictory_flags_before_context_creation(monkeypatch, capsys, direct):
    monkeypatch.setattr(cli, "_ctx", lambda a: pytest.fail("contradictory flags opened context"))
    if direct:
        code = cli.cmd_apply(SimpleNamespace(plan=True, simulate_verify_fail=True, proposal_id="p", actor=ACTOR))
    else:
        code = main(["apply", "p", "--simulate-verify-fail", "--plan"])
    assert code == 2
    output = capsys.readouterr()
    assert not output.out and "cannot be combined" in output.err


@pytest.mark.parametrize("problem", ["actor", "kill", "binding"])
def test_cli_plan_refusals_never_fall_through_to_execute(ctx, monkeypatch, capsys, problem):
    _, p, fix = seed(ctx)
    if problem == "kill":
        monkeypatch.setenv("CT_KILL", "1")
    if problem == "binding":
        fix.payload = "changed"
    forbid_side_effects(monkeypatch, ctx)
    monkeypatch.setattr(cli, "_ctx", lambda a: ctx)
    assert main(["--actor", "agent" if problem == "actor" else ACTOR, "apply", p.id, "--plan"]) == 2
    output = capsys.readouterr()
    assert not output.out and "refused" in output.err
