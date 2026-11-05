"""Kubernetes adapter: detection against the seeded simulated cluster, fix/verify/rollback as real state
transitions, fixture replay, and the guard rails on what reaches kubectl."""
import json
from pathlib import Path

import pytest

from cyberthunder.adapters.base import Collected
from cyberthunder.adapters.kubernetes import KubernetesAdapter
from cyberthunder.adapters.kubernetes import checks as k8s_checks
from cyberthunder.adapters.kubernetes.kubectl import (OBJ_TAG, KubectlTransport, ObjRef, parse_command, render,
                                                      split_commands, strip_server_fields)
from cyberthunder.adapters.kubernetes.simulated import SimulatedCluster
from cyberthunder.config import Settings
from cyberthunder.inventory.targets import Target
from cyberthunder.remediation.library import FixLibrary
from cyberthunder.transport.base import make_transport
from cyberthunder.transport.fixture import FixtureTransport

ROOT = Path(__file__).resolve().parents[2]
ANSWER_KEY = json.loads((ROOT / "range" / "answer_key" / "kubernetes.json").read_text(encoding="utf-8"))
ITEMS = {i["id"]: i for i in ANSWER_KEY["items"]}
CITABLE = {"stig_id", "group", "cci", "attack", "cve", "iavm"}


@pytest.fixture
def adapter():
    return KubernetesAdapter()


@pytest.fixture
def settings(state_dir):
    return Settings.from_env(state_dir=state_dir)


@pytest.fixture
def target(adapter):
    return adapter.demo_targets()[0]


@pytest.fixture
def transport(adapter, target, settings):
    adapter.reset_simulated(target, settings)
    return adapter.make_transport(target, settings)


def detect(adapter, target, transport, tmp_path, sub="scan"):
    col = adapter.collect(target, transport, tmp_path / sub)
    assert not col.errors, col.errors
    return adapter.run_detection(target, col)


def find_item(findings, item):
    for f in findings:
        if f.rule_version == item["rule"] and OBJ_TAG + item["object"] in f.tags:
            return f
    return None


def get_obj(transport, ref: ObjRef):
    r = transport.run(ref.get_command())
    return json.loads(r.stdout) if r.ok else None


# -- detection ------------------------------------------------------------------------------------
def test_every_answer_key_item_is_found(adapter, target, transport, tmp_path):
    findings = detect(adapter, target, transport, tmp_path)
    missing = [i["id"] for i in ANSWER_KEY["items"] if find_item(findings, i) is None]
    assert not missing, f"answer-key items not detected: {missing}"
    assert len(ANSWER_KEY["items"]) == 10


def test_every_finding_cites_an_identifier(adapter, target, transport, tmp_path):
    findings = detect(adapter, target, transport, tmp_path)
    assert findings
    for f in findings:
        ids = [r.id for r in f.references]
        ok = any(r.system in CITABLE for r in f.references) or any(i.startswith(("CNTR-K8-", "CIS-K8s-")) for i in ids)
        assert ok, (f.rule_id, ids)
        assert f.host == target.id and f.asset_type == "kubernetes"
        if f.source == "hunt":
            assert f.ref_ids("attack"), f.rule_id


def test_answer_key_citations_present(adapter, target, transport, tmp_path):
    findings = detect(adapter, target, transport, tmp_path)
    for item in ANSWER_KEY["items"]:
        f = find_item(findings, item)
        assert item["citations"][0] in f.citations, (item["id"], f.citations)


def test_fix_library_resolves_answer_key_fixes(adapter, target, transport, tmp_path):
    findings = detect(adapter, target, transport, tmp_path)
    lib = FixLibrary(adapter.fixes())
    for item in ANSWER_KEY["items"]:
        fix = lib.resolve(find_item(findings, item))
        assert fix is not None and fix.fix_ref == item["fix_ref"], (item["id"], fix and fix.fix_ref)


def test_fix_entries_are_complete(adapter):
    for fx in adapter.fixes():
        assert fx.asset_type == "kubernetes"
        assert fx.verify.get("rule_ids"), fx.fix_ref
        assert fx.citations, fx.fix_ref
        if fx.kind == "manifest":
            assert fx.before_state.get("commands"), fx.fix_ref
            assert fx.rollback_kind == "manifest"
            assert all(c.startswith("kubectl ") for c in split_commands(fx.payload)), fx.fix_ref
        else:
            assert fx.kind == "runbook" and fx.steps and not fx.payload, fx.fix_ref


def test_collect_facts(adapter, target, transport, tmp_path):
    col = adapter.collect(target, transport, tmp_path)
    assert col.facts.os_version == "v1.30.6+k3s1"
    assert col.facts.extra["node_count"] == 2
    assert {"pods", "deployments", "clusterrolebindings", "cronjobs"} <= set(col.artifacts)


# -- remediation ----------------------------------------------------------------------------------
@pytest.mark.parametrize("item_id", ["M1", "M4"])
def test_apply_verify_rollback(adapter, target, transport, tmp_path, item_id):
    item = ITEMS[item_id]
    lib = FixLibrary(adapter.fixes())
    finding = find_item(detect(adapter, target, transport, tmp_path, "before"), item)
    fix = lib.resolve(finding)
    ref = ObjRef.parse(item["object"])
    obj_ref = ObjRef(ref.namespace, ref.kind, ref.name)
    original = strip_server_fields(get_obj(transport, obj_ref))

    before = adapter.capture_before_state(target, transport, fix, finding, tmp_path / "snap")
    assert before.extra["existed"] is True
    assert (Path(before.dir) / before.commands["object"]).exists()

    res = adapter.apply(target, transport, fix, finding, before)
    assert res.ok, res.output
    v = adapter.verify(target, transport, fix, finding)
    assert v.rule_passed is True, v.evidence
    assert v.ok and v.health.ok

    rb = adapter.rollback(target, transport, fix, before)
    assert rb.ok, rb.output
    restored = get_obj(transport, obj_ref)
    assert restored is not None
    assert strip_server_fields(restored) == original
    # the misconfiguration is back, so the rollback really restored the old state
    assert find_item(detect(adapter, target, transport, tmp_path, "after"), item) is not None


def test_privileged_patch_rolls_pods(adapter, target, transport, tmp_path):
    item = ITEMS["M1"]
    finding = find_item(detect(adapter, target, transport, tmp_path), item)
    fix = FixLibrary(adapter.fixes()).resolve(finding)
    before = adapter.capture_before_state(target, transport, fix, finding, tmp_path / "snap")
    assert adapter.apply(target, transport, fix, finding, before).ok
    pods = json.loads(transport.run("kubectl get pods -n apps -o json").stdout)["items"]
    web = [p for p in pods if p["metadata"]["name"].startswith("web-frontend-")]
    assert len(web) == 2
    for p in web:
        sc = p["spec"]["containers"][0]["securityContext"]
        assert sc["privileged"] is False and sc["allowPrivilegeEscalation"] is False


def test_verify_fails_when_nothing_changed(adapter, target, transport, tmp_path):
    item = ITEMS["M1"]
    finding = find_item(detect(adapter, target, transport, tmp_path), item)
    fix = FixLibrary(adapter.fixes()).resolve(finding)
    v = adapter.verify(target, transport, fix, finding)
    assert v.rule_passed is False and not v.ok


def test_runbook_changes_nothing(adapter, target, transport, settings, tmp_path):
    item = ITEMS["M2"]
    finding = find_item(detect(adapter, target, transport, tmp_path), item)
    fix = FixLibrary(adapter.fixes()).resolve(finding)
    assert fix.kind == "runbook"
    state = adapter.simulated_state_path(target, settings).read_text(encoding="utf-8")
    before = adapter.capture_before_state(target, transport, fix, finding, tmp_path / "snap")
    res = adapter.apply(target, transport, fix, finding, before)
    assert not res.ok and not res.changed and res.details["runbook"]
    assert "anonymous-auth=false" in res.output
    assert adapter.rollback(target, transport, fix, before).ok
    assert adapter.simulated_state_path(target, settings).read_text(encoding="utf-8") == state


def test_wrong_object_kind_is_refused(adapter, target, transport, tmp_path):
    findings = detect(adapter, target, transport, tmp_path)
    # privileged container in a bare pod: the deployment patch must not be used on it
    f = next(x for x in findings if x.rule_version == "k8s:cis:5.2.2" and "apps/pod/kube-proxy-helper" in x.rule_id)
    fix = FixLibrary(adapter.fixes()).get("k8s:fix:deployment-drop-privileged")
    res = adapter.apply(target, transport, fix, f, None)
    assert not res.ok and "runbook" in res.output


def test_netpol_fix_rollback_deletes_created_policy(adapter, target, transport, tmp_path):
    from cyberthunder.adapters.kubernetes.checks import CIS_RULES, finding as mk
    ref = ObjRef(None, "namespace", "default")
    f = mk(target, CIS_RULES["netpol"], ref, "namespace default: no NetworkPolicy")
    fix = FixLibrary(adapter.fixes()).get("k8s:fix:namespace-default-deny")
    before = adapter.capture_before_state(target, transport, fix, f, tmp_path / "snap")
    assert before.extra["existed"] is False
    assert adapter.apply(target, transport, fix, f, before).ok
    pol = ObjRef("default", "networkpolicy", "ct-default-deny-ingress")
    assert get_obj(transport, pol) is not None
    assert adapter.rollback(target, transport, fix, before).ok
    assert get_obj(transport, pol) is None


def test_health_check_flags_crashloop(adapter, target, transport, settings):
    assert adapter.health_check(target, transport).ok
    c = SimulatedCluster(adapter.simulated_state_path(target, settings))
    c.load()
    pod = next(p for k, p in c.state["objects"]["pods"].items() if k.startswith("kube-system/coredns-"))
    pod["status"]["containerStatuses"][0]["state"] = {"waiting": {"reason": "CrashLoopBackOff"}}
    c.save()
    h = adapter.health_check(target, transport)
    assert not h.ok
    assert any(ch.name == "kube_system_pods" and not ch.ok for ch in h.checks)


# -- transports and guard rails -------------------------------------------------------------------
def test_fixture_replay_finds_answer_key(adapter, fixtures_dir, tmp_path):
    t = Target(id="sim-k8s-01", name="replay", asset_type="kubernetes", transport="fixture",
               options={"fixture_dir": str(fixtures_dir / "kubernetes" / "sim_session"),
                        "allowed_registries": ["registry.local", "docker.io/library"]})
    tr = make_transport(t)
    assert isinstance(tr, FixtureTransport)
    col = adapter.collect(t, tr, tmp_path)
    findings = adapter.run_detection(t, col)
    missing = [i["id"] for i in ANSWER_KEY["items"] if find_item(findings, i) is None]
    assert not missing


def test_generic_factory_builds_simulated_transport(target, settings):
    from cyberthunder.adapters.kubernetes.simulated import SimulatedClusterTransport
    assert isinstance(make_transport(target, settings), SimulatedClusterTransport)


def test_unknown_commands_exit_127(transport):
    assert transport.run("kubectl frobnicate pods").exit_code == 127
    assert transport.run("rm -rf /").exit_code == 127


def test_kubectl_transport_never_uses_a_shell(tmp_path):
    kt = KubectlTransport(tmp_path / "kubeconfig", context="range")
    argv, stdin = kt.build_argv("kubectl apply -f - <<'CT_EOF'\n{\"kind\": \"List\"}\nCT_EOF")
    assert argv[:5] == ["kubectl", "--kubeconfig", str(tmp_path / "kubeconfig"), "--context", "range"]
    assert argv[5:] == ["apply", "-f", "-"] and stdin == '{"kind": "List"}'
    argv, _ = kt.build_argv("kubectl get pods; rm -rf /")
    assert argv[-4:] == ["pods;", "rm", "-rf", "/"]  # literal arguments to kubectl, never interpreted by a shell
    r = kt.run("bash -c id")
    assert r.exit_code == 126


def test_kubeconfig_target_requires_path(adapter):
    t = Target(id="k3s-live", name="k3s", asset_type="kubernetes", transport="kubeconfig", options={"kubeconfig": "kc.yaml"})
    assert isinstance(adapter.make_transport(t), KubectlTransport)
    with pytest.raises(ValueError):
        adapter.make_transport(Target(id="x", name="x", asset_type="kubernetes", transport="kubeconfig"))


@pytest.mark.parametrize("bad", ["apps;rm -rf /", "Apps", "a b", "$(id)", "../etc"])
def test_object_refs_reject_unsafe_names(bad):
    with pytest.raises(ValueError):
        ObjRef(bad, "pod", "x")
    with pytest.raises(ValueError):
        ObjRef("apps", "pod", bad)


def test_render_and_parse_heredoc():
    ref = ObjRef(None, "clusterrolebinding", "system-monitor-binding")
    assert render("kubectl delete <kind> <name> -n <namespace>", ref) == "kubectl delete clusterrolebinding system-monitor-binding"
    cmds = split_commands("kubectl apply -f - <<'CT_EOF'\n{\"a\": 1}\nCT_EOF\nkubectl get pods")
    assert len(cmds) == 2
    argv, stdin = parse_command(cmds[0])
    assert argv == ["kubectl", "apply", "-f", "-"] and stdin == '{"a": 1}'


def test_kubelet_configz_checks(target, tmp_path):
    p = tmp_path / "configz_node-a.json"
    p.write_text(json.dumps({"kubeletconfig": {"readOnlyPort": 10255, "authentication": {"anonymous": {"enabled": True}},
                                               "authorization": {"mode": "AlwaysAllow"}, "protectKernelDefaults": True}}),
                 encoding="utf-8")
    col = Collected(target_id=target.id, asset_type="kubernetes", workdir=str(tmp_path), artifacts={"configz_node-a": str(p)})
    rules = {f.rule_version for f in k8s_checks.run_checks(target, col)}
    assert {"CNTR-K8-000330", "CNTR-K8-000370", "CNTR-K8-000380"} <= rules
    assert "CNTR-K8-001620" not in rules


def test_reset_restores_seed(adapter, target, transport, settings, tmp_path):
    transport.run("kubectl delete cronjob cache-warmer -n apps")
    assert find_item(detect(adapter, target, transport, tmp_path, "a"), ITEMS["I2"]) is None
    assert adapter.reset_simulated(target, settings)
    assert find_item(detect(adapter, target, transport, tmp_path, "b"), ITEMS["I2"]) is not None
