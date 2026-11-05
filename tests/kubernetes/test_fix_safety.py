"""Safety and saved-proposal compatibility, using only isolated simulated clusters."""
import copy
import json
from dataclasses import replace

import pytest

from cyberthunder.adapters.kubernetes import fixes
from cyberthunder.adapters.kubernetes.checks import CIS_RULES, finding as make_finding, stig
from cyberthunder.adapters.kubernetes.hunt import HUNT_RULES
from cyberthunder.adapters.kubernetes.kubectl import ObjRef, strip_server_fields
from cyberthunder.adapters.kubernetes.simulated import SimulatedCluster
from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.control.approvals import ProposalState
from cyberthunder.remediation import snapshot
from cyberthunder.remediation.engine import EngineError
from cyberthunder.remediation.library import FixLibrary
from cyberthunder.remediation.models import BeforeState

ACTOR = "ITC Rivera"


@pytest.fixture
def cluster(state_dir, tmp_path):
    ctx = AppContext(Settings.from_env(state_dir=state_dir, auto_propose=False, explain_precompute=False,
                                        bootstrap_cluster_target=False, llm_backend="template"))
    adapter = ctx.adapters.get("kubernetes")
    target = adapter.demo_targets()[0]
    adapter.reset_simulated(target, ctx.settings)
    ctx.inventory.add(target)
    ctx.inventory.save()
    transport = ctx.transport_for(target)
    collected = adapter.collect(target, transport, tmp_path / "scan")
    assert not collected.errors
    findings = adapter.run_detection(target, collected)
    return ctx, adapter, target, transport, findings


def _finding(findings, rule):
    return next(f for f in findings if f.rule_version == rule)


def _state(ctx, adapter, target):
    return adapter.simulated_state_path(target, ctx.settings).read_bytes()


def _legacy(ctx, ref="k8s:fix:delete-cronjob"):
    # Historical shape: an approved executable deletion, with the old low-risk declaration.
    current = ctx.library.get(ref)
    return replace(current, title="Delete the malicious CronJob", payload="kubectl delete cronjob <name> -n <namespace>",
                   applies_to=["k8s:hunt:cronjob-download"], disruption="low", reversible=True,
                   notes="Historical removal proposal", rollback_steps=[])


@pytest.mark.parametrize("key,ref", [
    ("escape", ObjRef("apps", "deployment", "worker")),
    ("escape", ObjRef("apps", "pod", "worker")),
    ("cronjob", ObjRef("apps", "cronjob", "worker")),
    ("admin_default", ObjRef(None, "clusterrolebinding", "shared")),
    ("system_pod", ObjRef("kube-system", "pod", "custom-addon")),
    ("masquerade", ObjRef("apps", "pod", "kube-proxy-helper")),
    ("dashboard", ObjRef("apps", "service", "business-dashboard")),
    ("registry", ObjRef("apps", "deployment", "worker")),
    ("listener", ObjRef("apps", "pod", "worker")),
])
def test_all_hunt_signals_select_review_not_deletion(key, ref):
    from cyberthunder.adapters.kubernetes import KubernetesAdapter
    target = KubernetesAdapter().demo_targets()[0]
    f = make_finding(target, HUNT_RULES[key], ref, "configuration indicator", source="hunt")
    fixes.point_at_applicable_fix([f])
    fix = FixLibrary(fixes.kubernetes_fixes()).resolve(f)
    assert fix.fix_ref in fixes.REVIEW_FIXES
    assert fix.kind == "runbook" and not fix.payload
    assert "does not establish malicious activity" in f.description


def test_retired_entries_cannot_be_selected_by_rule_or_stale_finding(cluster):
    ctx, _, _, _, findings = cluster
    for ref, replacement in fixes.RETIRED_FIXES.items():
        old = ctx.library.get(ref)
        assert not old.applies_to and not old.payload
        assert old.disruption == "high" and not old.reversible
        for rule in old.verify["rule_ids"]:
            f = copy.deepcopy(findings[0])
            f.rule_version, f.fix_ref, f.rule_id, f.group_id = rule, None, rule, None
            f.references = []
            assert ctx.library.resolve(f).fix_ref not in fixes.RETIRED_FIXES
        f.fix_ref = ref
        fixes.point_at_applicable_fix([f])
        assert ctx.library.resolve(f).fix_ref == replacement


@pytest.mark.parametrize("retired_ref", list(fixes.RETIRED_FIXES))
def test_retired_snapshot_cannot_capture_apply_or_verify(cluster, tmp_path, retired_ref):
    ctx, adapter, target, _, findings = cluster
    old = replace(ctx.library.get(retired_ref), payload="kubectl delete namespace apps",
                  steps=["Historical destructive instructions"])

    class NoCalls:
        def run(self, *args, **kwargs):
            pytest.fail("retired execution/verification must not run a command")

    with pytest.raises(ValueError, match="Retired destructive fix"):
        adapter.capture_before_state(target, NoCalls(), old, findings[0], tmp_path / "blocked")
    assert not (tmp_path / "blocked").exists()
    applied = adapter.apply(target, NoCalls(), old, findings[0], None)
    assert not applied.ok and not applied.changed
    verified = adapter.verify(target, NoCalls(), old, findings[0])
    assert verified.rule_passed is None and not verified.ok


@pytest.mark.parametrize("snapshot_fallback", [False, True])
def test_engine_refuses_approved_legacy_deletion_without_mutation(cluster, snapshot_fallback):
    ctx, adapter, target, _, findings = cluster
    f = _finding(findings, "k8s:hunt:cronjob-download")
    old = _legacy(ctx)
    p = ctx.engine.propose(f, fix=old)
    ctx.gate.approve(p.id, ACTOR, "historical approval")
    original = _state(ctx, adapter, target)
    if snapshot_fallback:
        # Even if the current library entry is absent, _fix_for can load the saved payload.
        ctx.library = FixLibrary(e for e in ctx.library.all() if e.fix_ref != old.fix_ref)
        assert ctx.engine.execute(p.id, actor=ACTOR).state is ProposalState.FAILED
    else:
        with pytest.raises(EngineError, match="changed since it was approved"):
            ctx.engine.execute(p.id, actor=ACTOR)
        assert ctx.gate.get(p.id).state is ProposalState.APPROVED
    assert _state(ctx, adapter, target) == original
    snap = ctx.store.snapshot_dir(p.id)
    assert snapshot.load_fix(snap).payload == old.payload
    assert not (snap / "before_state.json").exists()
    assert not (snap / "apply.json").exists()
    assert not (snap / "rollback.json").exists()


def test_saved_historical_fix_and_manifest_still_roll_back(cluster):
    ctx, adapter, target, transport, findings = cluster
    f = _finding(findings, "k8s:hunt:cronjob-download")
    old = _legacy(ctx)
    p = ctx.engine.propose(f, fix=old)
    ctx.gate.approve(p.id, ACTOR, "historical approval")
    snap = ctx.store.snapshot_dir(p.id)
    ref = ObjRef("apps", "cronjob", "cache-warmer")
    original = json.loads(transport.run(ref.get_command()).stdout)
    before = BeforeState(target_id=target.id, fix_ref=old.fix_ref, dir=str(snap),
                         extra={"restore_ref": ref.to_str(), "object_ref": ref.to_str(), "existed": True,
                                "object": strip_server_fields(original)})
    snapshot.save_before_state(snap, before)
    ctx.gate.start_apply(p.id, ACTOR, before_state_ref=str(snap))
    # Reconstruct an already applied historical change in the simulator, not through current execution.
    assert transport.run("kubectl delete cronjob cache-warmer -n apps").ok
    ctx.gate.applied(p.id, ACTOR, "historical simulated deletion")
    assert ctx.engine._applied_fix(p).payload == old.payload
    assert ctx.library.get(old.fix_ref).payload == ""
    assert ctx.engine.rollback(p.id, actor=ACTOR).state is ProposalState.ROLLED_BACK
    restored = json.loads(transport.run(ref.get_command()).stdout)
    assert strip_server_fields(restored) == strip_server_fields(original)
    assert restored["metadata"]["uid"] != original["metadata"]["uid"]
    result = snapshot.load_result(snap, "rollback")
    assert "configuration only" in result["output"]
    assert result["details"]["application_health"] == "not assessed"
    assert snapshot.load_fix(snap).payload == old.payload


def test_retired_rollback_cannot_delete_without_a_prior_object(cluster):
    ctx, adapter, target, transport, _ = cluster
    original = _state(ctx, adapter, target)
    before = BeforeState(target_id=target.id, fix_ref="k8s:fix:delete-cronjob", dir="unused",
                         extra={"restore_ref": "apps/cronjob/cache-warmer", "existed": False})
    result = adapter.rollback(target, transport, ctx.library.get(before.fix_ref), before)
    assert not result.ok and "will not delete" in result.output
    assert _state(ctx, adapter, target) == original


def test_cronjob_review_and_suspension_do_not_claim_remediation(cluster, tmp_path):
    ctx, adapter, target, transport, findings = cluster
    f = _finding(findings, "k8s:hunt:cronjob-download")
    p = ctx.engine.propose(f)
    ctx.gate.approve(p.id, ACTOR, "review only")
    original = _state(ctx, adapter, target)
    assert ctx.engine.execute(p.id, actor=ACTOR).state is ProposalState.APPLIED
    assert _state(ctx, adapter, target) == original
    assert snapshot.load_result(ctx.store.snapshot_dir(p.id), "apply")["changed"] is False
    # Explicit fixture-only containment does not clear the template indicator or alter existing pods.
    pods = transport.run("kubectl get pods -A -o json").stdout
    assert transport.run('kubectl patch cronjob cache-warmer -n apps --type=merge -p \'{"spec":{"suspend":true}}\'').ok
    assert transport.run("kubectl get pods -A -o json").stdout == pods
    col = adapter.collect(target, transport, tmp_path / "suspended")
    current = _finding(adapter.run_detection(target, col), "k8s:hunt:cronjob-download")
    assert current.is_open and "suspend=True" in current.evidence
    fix = ctx.library.resolve(current)
    assert "does not stop existing Jobs or Pods" in fix.preview_text()
    assert ctx.engine.verify(p.id, actor=ACTOR).state is ProposalState.APPLIED
    assert transport.run("kubectl delete cronjob cache-warmer -n apps").ok
    assert ctx.engine.verify(p.id, actor=ACTOR).state is ProposalState.APPLIED


def test_shared_rbac_subjects_preserved_by_review(cluster, tmp_path):
    ctx, adapter, target, transport, _ = cluster
    sim = SimulatedCluster(adapter.simulated_state_path(target, ctx.settings))
    sim.load()
    binding = sim.get("clusterrolebindings", None, "system-monitor-binding")
    binding["subjects"].append({"kind": "Group", "name": "legitimate-operators", "apiGroup": "rbac.authorization.k8s.io"})
    sim.save()
    col = adapter.collect(target, transport, tmp_path / "shared-binding")
    f = _finding(adapter.run_detection(target, col), "k8s:hunt:admin-to-default")
    fix = ctx.library.resolve(f)
    assert "targeted correction" in fix.preview_text() and "Preserve legitimate" in fix.preview_text()
    original = _state(ctx, adapter, target)
    before = adapter.capture_before_state(target, transport, fix, f, tmp_path / "review")
    result = adapter.apply(target, transport, fix, f, before)
    assert not result.changed and result.details["runbook"]
    assert _state(ctx, adapter, target) == original
    for rule in (CIS_RULES["cluster_admin"],):
        other = make_finding(target, rule, ObjRef(None, "clusterrolebinding", "shared"), "review")
        assert ctx.library.resolve(other).fix_ref == fix.fix_ref


def test_absent_deployment_and_partial_scan_are_not_verified(cluster, monkeypatch):
    ctx, adapter, target, transport, findings = cluster
    f = next(f for f in findings if f.rule_version == "k8s:cis:5.2.2" and "/deployment/" in f.rule_id)
    fix = ctx.library.resolve(f)
    monkeypatch.setattr(adapter, "_redetect", lambda *_: ([findings[-1]], ["deployment collection denied"]))
    result = adapter.verify(target, transport, fix, f)
    assert not result.ok and result.rule_passed is None and "could not re-collect" in result.evidence
    assert transport.run("kubectl delete deployment web-frontend -n apps").ok
    result = adapter.verify(target, transport, fix, f)
    assert result.rule_passed is None and not result.ok and "absent or unreadable" in result.evidence


@pytest.mark.parametrize("missing", ["object", "container"])
def test_original_object_must_be_present_in_the_verification_collection(cluster, missing):
    ctx, adapter, target, transport, findings = cluster
    f = next(f for f in findings if f.rule_version == "k8s:cis:5.2.2" and "/deployment/" in f.rule_id)
    fix = ctx.library.resolve(f)

    class DisappearsDuringCollection:
        def run(self, command, **kwargs):
            result = transport.run(command, **kwargs)
            if command == "kubectl get deployments -A -o json":
                data = json.loads(result.stdout)
                # The single-object read succeeded earlier, but this object is no longer in the scan.
                if missing == "object":
                    data["items"] = [item for item in data["items"] if item["metadata"]["name"] != "web-frontend"]
                else:
                    original = next(item for item in data["items"] if item["metadata"]["name"] == "web-frontend")
                    original["spec"]["template"]["spec"]["containers"] = []
                return replace(result, stdout=json.dumps(data))
            return result

    result = adapter.verify(target, DisappearsDuringCollection(), fix, f)
    assert not result.ok and result.rule_passed is None, result.evidence


@pytest.mark.parametrize("payload", [
    {},
    {"kind": "Status", "status": "Failure", "message": "list unavailable"},
    {"items": [], "metadata": {"continue": "next-page"}},
])
def test_incomplete_object_lists_cannot_verify_a_fix(cluster, payload):
    ctx, adapter, target, transport, findings = cluster
    f = next(f for f in findings if f.rule_version == "k8s:cis:5.2.2" and "/deployment/" in f.rule_id)
    fix = ctx.library.resolve(f)

    class IncompleteCollection:
        def run(self, command, **kwargs):
            result = transport.run(command, **kwargs)
            return replace(result, stdout=json.dumps(payload)) if command == "kubectl get deployments -A -o json" else result

    result = adapter.verify(target, IncompleteCollection(), fix, f)
    assert not result.ok and result.rule_passed is None, result.evidence


def test_dashboard_and_migration_guidance_preserves_service_and_data():
    lib = FixLibrary(fixes.kubernetes_fixes())
    dashboard = lib.get("k8s:runbook:review-dashboard-exposure").preview_text()
    assert "ClusterIP" in dashboard and "does not satisfy a benchmark" in dashboard
    assert "Delete" not in stig("CNTR-K8-000420").fix_text
    migration = lib.get("k8s:runbook:move-from-default-namespace").preview_text()
    assert migration.index("Prepare with") < migration.index("Test the replacement") < migration.index("traffic cutover")
    for required in ("data consistency", "readiness", "rollback", "observation period", "PVCs"):
        assert required in migration
    for fix in lib.all():
        assert "kubectl delete ns" not in fix.preview_text()
        assert "kubectl delete namespace" not in fix.preview_text()
        assert "kubectl delete pvc" not in fix.preview_text()
        assert "kubectl delete pv " not in fix.preview_text()
