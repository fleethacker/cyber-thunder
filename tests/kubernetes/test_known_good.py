from cyberthunder.adapters.kubernetes.known_good import KubernetesKnownGoodState
from cyberthunder.adapters.kubernetes.simulated import SimulatedCluster
from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.findings.schema import Status


def _ctx(state_dir):
    return AppContext(Settings.from_env(state_dir=state_dir, auto_propose=False, explain_precompute=False,
                                        llm_backend="template"))


def _add_demo_target(ctx):
    adapter = ctx.adapters.get("kubernetes")
    target = adapter.demo_targets()[0]
    adapter.reset_simulated(target, ctx.settings)
    ctx.inventory.add(target)
    ctx.inventory.save()
    return adapter, target


def _unexpected_system_pod(ctx, scan_id):
    return next(f for f in ctx.store.load_findings(scan_id)
                if f.rule_version == "k8s:hunt:unexpected-system-pod")


def test_known_good_exception_closes_future_kubernetes_scan_findings(state_dir):
    ctx = _ctx(state_dir)
    _, target = _add_demo_target(ctx)
    first = ctx.scanner.start([target.id], modules=["hunt"], requested_by="ITC Rivera", background=False)
    finding = _unexpected_system_pod(ctx, first.id)
    assert finding.status == Status.OPEN

    item = KubernetesKnownGoodState(ctx.store).add_from_finding(
        finding, actor="ITC Rivera", reason="metrics collector is part of the approved enclave build",
        scope="object")

    second = ctx.scanner.start([target.id], modules=["hunt"], requested_by="ITC Rivera", background=False)
    accepted = _unexpected_system_pod(ctx, second.id)
    assert accepted.status == Status.NOT_APPLICABLE
    assert not accepted.is_open
    assert f"known-good:{item.id}" in accepted.tags
    assert second.summary["by_status"]["not_applicable"] >= 1

    saved = KubernetesKnownGoodState(ctx.store).list()[0]
    assert saved.match_count == 1
    assert saved.last_matched_at is not None
    assert any(r["action"] == "known_good.apply" and r["subject"] == target.id for r in ctx.audit.records())


def test_known_good_object_prefix_survives_generated_pod_name_change(state_dir):
    ctx = _ctx(state_dir)
    adapter, target = _add_demo_target(ctx)
    first = ctx.scanner.start([target.id], modules=["hunt"], requested_by="ITC Rivera", background=False)
    finding = _unexpected_system_pod(ctx, first.id)
    item = KubernetesKnownGoodState(ctx.store).add_from_finding(
        finding, actor="ITC Rivera", reason="approved metrics collector deployment", scope="object_prefix")

    cluster = SimulatedCluster(adapter.simulated_state_path(target, ctx.settings))
    cluster.load()
    pod = cluster.state["objects"]["pods"].pop("kube-system/metrics-collector-7d9f4")
    pod["metadata"]["name"] = "metrics-collector-a1b2c3"
    cluster.state["objects"]["pods"]["kube-system/metrics-collector-a1b2c3"] = pod
    cluster.save()

    second = ctx.scanner.start([target.id], modules=["hunt"], requested_by="ITC Rivera", background=False)
    accepted = _unexpected_system_pod(ctx, second.id)
    assert "kube-system/pod/metrics-collector-a1b2c3" in accepted.rule_id
    assert accepted.status == Status.NOT_APPLICABLE
    assert f"known-good:{item.id}" in accepted.tags
