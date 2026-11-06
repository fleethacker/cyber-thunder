"""Bounded collection and mutation refusal, including privileged backing credentials."""
import copy
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from cyberthunder.adapters.kubernetes import KubernetesAdapter
from cyberthunder.adapters.kubernetes import checks, scope
from cyberthunder.adapters.kubernetes.kubectl import KIND_INFO, KubectlTransport, ObjRef
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.control.principal import principal_scope, operation_scope
from cyberthunder.inventory.targets import Target, ScopeViolation
from cyberthunder.remediation.library import FixLibrary
from cyberthunder.remediation.models import BeforeState
from cyberthunder.transport.base import CommandResult
from tests.security.test_kube_credentials import cert_material, document, write, TOKEN  # noqa: F401
from tests.security.test_kubernetes_account_integration import selected_cluster, assert_selected  # noqa: F401


def target_for(namespaces=("work",)):
    return Target("cluster-a", "Cluster A", "kubernetes", "kubeconfig", sudo=False,
                  options={"kubeconfig": "unused-config", "namespaces": list(namespaces)})


def object_for(resource, namespace, name="fixture"):
    _, kind, api = KIND_INFO[resource]
    item = {"apiVersion": api, "kind": kind, "metadata": {"name": name, "namespace": namespace}, "spec": {}}
    if resource in {"deployments", "pods", "cronjobs"}:
        pod = {"containers": [{"name": "app", "image": "registry.local/app:1",
                              "securityContext": {"privileged": True}}]}
        item["spec"] = (pod if resource == "pods" else {"template": {"spec": pod}} if resource == "deployments"
                        else {"jobTemplate": {"spec": {"template": {"spec": pod}}}})
    if resource == "rolebindings":
        item["roleRef"] = {"kind": "ClusterRole", "name": "cluster-admin", "apiGroup": "rbac.authorization.k8s.io"}
        item["subjects"] = [{"kind": "ServiceAccount", "name": "default", "namespace": namespace}]
    return item


def list_for(resource, namespace, items=None):
    _, kind, api = KIND_INFO[resource]
    return {"apiVersion": api, "kind": kind + "List", "metadata": {}, "items": [] if items is None else items}


class Fixture:
    def __init__(self, changes=None):
        self.calls = []
        self.changes = changes or {}

    def run(self, command, **kwargs):
        self.calls.append(command)
        words = command.split()
        assert len(words) == 7 and words[0:2] == ["kubectl", "get"] and words[3] == "-n"
        resource, ns = words[2], words[4]
        assert resource in scope.NAMESPACED_RESOURCES
        items = [object_for(resource, ns)] if resource in {"deployments", "rolebindings"} else []
        result = self.changes.get((resource, ns), list_for(resource, ns, items))
        if isinstance(result, CommandResult):
            return result
        return CommandResult(command, 0, json.dumps(result))


def collect(tmp_path, namespaces=("work",), changes=None):
    adapter, target, transport = KubernetesAdapter(), target_for(namespaces), Fixture(changes)
    return adapter, target, transport, adapter.collect(target, transport, tmp_path / "raw")


@pytest.mark.parametrize("value", [None, [], "work", "*", ["*"], [""], ["-n"], ["Work"], ["a.b"],
                                      [" work"], ["work\n"], ["work", "work"], ["x" * 64], [1], [True],
                                      ["a/../../b"], ["a,b"], {"work": True}, [f"ns-{i}" for i in range(17)]])
def test_invalid_selector_fails_before_transport_or_artifact(tmp_path, value):
    target = target_for()
    target.options["namespaces"] = value
    adapter, transport = KubernetesAdapter(), Fixture()
    with pytest.raises(ValueError):
        adapter.make_transport(target)
    with pytest.raises(ValueError):
        adapter.collect(target, transport, tmp_path / "raw")
    with pytest.raises(ValueError):
        adapter.discover(target, transport)
    assert not transport.calls and not (tmp_path / "raw").exists()


def test_scope_bounds_and_deterministic_complete_merge(tmp_path):
    changes = {("pods", ns): list_for("pods", ns, [object_for("pods", ns, n) for n in ("z", "a")])
               for ns in ("zeta", "alpha")}
    adapter, target, transport, col = collect(tmp_path, ("zeta", "alpha"), changes)
    assert transport.calls == [scope.list_command(r, ns) for r in scope.NAMESPACED_RESOURCES for ns in ("alpha", "zeta")]
    items = checks.KubeData(col).items("pods")
    assert [(x["metadata"]["namespace"], x["metadata"]["name"]) for x in items] == [
        ("alpha", "a"), ("alpha", "z"), ("zeta", "a"), ("zeta", "z")]
    assert col.raw[scope.SCOPE_KEY]["namespace_lists_complete"] is True
    assert col.raw[scope.SCOPE_KEY]["cluster_complete"] is False
    before = list(transport.calls)
    facts = adapter.discover(target, transport)
    assert not adapter.health_check(target, transport).ok
    assert transport.calls == before
    assert facts.extra["node_count"] is None and col.facts.extra["nodes"] is None
    assert "0 node" not in json.dumps(col.to_dict())
    findings = adapter.run_detection(target, col)
    assert any(f.rule_version == "k8s:cis:5.2.2" and f.is_open for f in findings)
    assert any(f.rule_version == "k8s:hunt:admin-to-default" and f.is_open for f in findings)
    assert not any(f.status == "not_a_finding" for f in findings)
    for finding in findings:
        assert finding.collection_provenance[scope.SCOPE_KEY]["namespaces"] == ["alpha", "zeta"]
        assert "cluster coverage incomplete" in finding.evidence
        assert FixLibrary(adapter.fixes()).resolve(finding).kind == "runbook"


@pytest.mark.parametrize("bad", [None, [], {}, {"items": []},
    {"apiVersion": "v1", "kind": "NetworkPolicyList", "metadata": {}, "items": []},
    {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicyList", "metadata": [], "items": []},
    *[dict(list_for("networkpolicies", "work"), metadata=value) for value in (
        {"continue": "next"}, {"continue": None}, {"continue": False}, {"remainingItemCount": 1},
        {"remainingItemCount": "0"}, {"remainingItemCount": False}, {"remainingItemCount": -1})],
    dict(list_for("networkpolicies", "work"), items=[None]),
    list_for("networkpolicies", "work", [object_for("networkpolicies", "outside")]),
    list_for("networkpolicies", "work", [object_for("pods", "work")]),
    list_for("networkpolicies", "work", [object_for("networkpolicies", "work")] * 2),
])
def test_unavailable_policy_list_is_not_absence_or_clean_cluster(tmp_path, bad):
    adapter, target, _, col = collect(tmp_path, changes={("networkpolicies", "work"): bad})
    assert "networkpolicies" not in col.artifacts
    assert col.raw[scope.SCOPE_KEY]["resources"]["networkpolicies"]["work"]["status"] == "unavailable"
    assert col.raw[scope.SCOPE_KEY]["namespace_lists_complete"] is False
    findings = adapter.run_detection(target, col)
    netpol = [f for f in findings if f.rule_version == "k8s:cis:5.3.2"]
    assert len(netpol) == 1 and netpol[0].status == "not_reviewed"
    assert any(f.rule_version == "k8s:cis:5.2.2" for f in findings)


def test_one_denied_namespace_does_not_erase_complete_namespace(tmp_path):
    denied = CommandResult("", 403, "", "sensitive response content")
    adapter, target, _, col = collect(tmp_path, ("work", "other"), {("networkpolicies", "other"): denied})
    findings = adapter.run_detection(target, col)
    policies = {f.rule_id.split("/")[-1]: f.status for f in findings if f.rule_version == "k8s:cis:5.3.2"}
    assert policies == {"work": "open", "other": "not_reviewed"}
    assert "sensitive response content" not in json.dumps(col.to_dict())


def test_all_denied_is_unavailable_and_empty_success_is_explicit(tmp_path):
    denied = {(r, "work"): CommandResult("", 403) for r in scope.NAMESPACED_RESOURCES}
    adapter, target, _, col = collect(tmp_path, changes=denied)
    assert col.raw[scope.SCOPE_KEY]["status"] == "unavailable"
    assert not col.artifacts and col.errors
    assert all(f.status == "not_reviewed" for f in adapter.run_detection(target, col))
    empty = {key: list_for(key[0], "work") for key in denied}
    _, _, _, col = collect(tmp_path, changes=empty)
    assert col.raw[scope.SCOPE_KEY]["status"] == "partial"
    assert col.raw[scope.SCOPE_KEY]["namespace_lists_complete"] is True


def test_cross_namespace_items_discard_entire_response(tmp_path):
    bad = list_for("deployments", "work", [object_for("deployments", "work"), object_for("deployments", "other")])
    adapter, target, _, col = collect(tmp_path, changes={("deployments", "work"): bad})
    assert "deployments" not in col.artifacts
    assert not any(f.rule_version == "k8s:cis:5.2.2" for f in adapter.run_detection(target, col))


def test_cluster_fallbacks_and_static_flags_are_never_used(tmp_path, monkeypatch):
    adapter, target, transport, col = collect(tmp_path, ("kube-system",))
    target.options.update(node_target="node", k3d_cluster="range")
    monkeypatch.setattr(adapter, "_collect_k3s_node", lambda *a, **k: pytest.fail("node fallback"))
    monkeypatch.setattr("cyberthunder.adapters.kubernetes.k3d.collect", lambda *a, **k: pytest.fail("docker fallback"))
    col = adapter.collect(target, transport, tmp_path / "new")
    col.raw[checks.K3S_FLAGS] = {"servers": [{"node": "server", "apiserver": {"anonymous-auth": "false"}}]}
    assert not any(f.status == "not_a_finding" for f in adapter.run_detection(target, col))
    assert len(transport.calls) == 14


FORBIDDEN = [
    "kubectl get pods -A -o json", "kubectl get pods --all-namespaces -o json",
    "kubectl get pods -n outside -o json", "kubectl get pods -n work --all-namespaces=false -o json",
    "kubectl get nodes -n work -o json", "kubectl get namespaces -n work -o json",
    "kubectl get clusterroles -n work -o json", "kubectl get clusterrolebindings -n work -o json",
    "kubectl get secrets -n work -o json", "kubectl get roles -n work -o json",
    "kubectl get --raw /api/v1/nodes/node/proxy/configz", "kubectl version -o json",
    "kubectl get pods -n work -o json --context admin", "kubectl --context admin get pods -n work -o json",
    "kubectl get pods -n work -o json --kubeconfig admin", "kubectl get pods -n work -o json --as admin",
    "kubectl get pods -n work -o json --user admin", "kubectl get pods -n work -o json --server https://elsewhere",
    "kubectl get pods -n work -o json --namespace outside", "kubectl get pods,secret -n work -o json",
    "kubectl get pods/name -n work -o json", "kubectl get pods -n work -o json\nkubectl delete namespace other",
    "kubectl get pods -n work -o json <<'CT_EOF'\n{}\nCT_EOF",
    "kubectl delete deployment fixture -n work", "kubectl apply -f -", "kubectl replace -f -",
    "kubectl patch deployment fixture -n work -p '{}'", "kubectl rollout status deployment/fixture -n work",
]


@pytest.mark.parametrize("command", FORBIDDEN)
def test_transport_refuses_non_collection_commands_before_subprocess(monkeypatch, command):
    monkeypatch.setattr("subprocess.run", lambda *a, **k: pytest.fail("unexpected subprocess"))
    transport = KubernetesAdapter().make_transport(target_for())
    with pytest.raises(PermissionError):
        transport.run(command)


def test_transport_refuses_sudo_and_target_drift(tmp_path):
    adapter, target = KubernetesAdapter(), target_for()
    transport = adapter.make_transport(target)
    with pytest.raises(PermissionError):
        transport.run(scope.list_command("pods", "work"), sudo=True)
    target.options["namespaces"] = ["outside"]
    with pytest.raises(PermissionError):
        transport.build_argv(scope.list_command("pods", "work"))
    with pytest.raises(PermissionError):
        adapter.collect(target, transport, tmp_path / "raw")
    assert not (tmp_path / "raw").exists()


@pytest.mark.parametrize("ref", ["work/deployment/fixture/app", "outside/deployment/fixture/app", "-/node/server",
                                  "-/namespace/outside", "-/clusterrolebinding/admin", "-/clusterrole/admin"])
def test_adapter_refuses_crafted_fix_capture_verify_and_recovery_before_io(tmp_path, ref):
    adapter, target = KubernetesAdapter(), target_for()
    fix = next(f for f in adapter.fixes() if f.kind == "manifest")
    fix = replace(fix, payload="kubectl delete namespace outside")
    finding = checks.finding(target, checks.CIS_RULES["privileged"], ObjRef.parse(ref), "fixture")
    before = BeforeState(target.id, fix.fix_ref, str(tmp_path / "never-read"),
                         extra={"existed": True, "restore_ref": ref})
    transport = SimpleNamespace(run=lambda *a, **k: pytest.fail("unexpected transport operation"))
    for call in (
        lambda: adapter.capture_before_state(target, transport, fix, finding, tmp_path / "before"),
        lambda: adapter.apply(target, transport, fix, finding, before),
        lambda: adapter.verify(target, transport, fix, finding),
        lambda: adapter.rollback(target, transport, fix, before),
    ):
        with pytest.raises(PermissionError, match="read-only"):
            call()
    assert not (tmp_path / "before").exists()


def test_namespace_evidence_stays_read_only_after_target_option_removed(tmp_path):
    adapter, target, transport, col = collect(tmp_path)
    finding = next(f for f in adapter.run_detection(target, col) if f.is_open)
    target.options.pop("namespaces")
    fix = next(f for f in adapter.fixes() if f.kind == "manifest")
    with pytest.raises(PermissionError, match="read-only"):
        adapter.capture_before_state(target, transport, fix, finding, tmp_path / "before")


@pytest.mark.parametrize("bad", ["not JSON", '{"items":[],"items":[]}', 'NaN', '{"kind":"List"'])
def test_malformed_json_never_becomes_empty_success(tmp_path, bad):
    _, _, _, col = collect(tmp_path, changes={("pods", "work"): CommandResult("", 0, bad)})
    assert "pods" not in col.artifacts
    assert col.raw[scope.SCOPE_KEY]["resources"]["pods"]["work"]["status"] == "unavailable"


@pytest.mark.parametrize("field,value", [("containers", None), ("containers", []), ("containers", [None]),
                                            ("securityContext", []), ("hostNetwork", "false")])
def test_malformed_workload_is_unavailable(tmp_path, field, value):
    item = object_for("pods", "work")
    item["spec"][field] = value
    _, _, _, col = collect(tmp_path, changes={("pods", "work"): list_for("pods", "work", [item])})
    assert "pods" not in col.artifacts
    assert col.raw[scope.SCOPE_KEY]["resources"]["pods"]["work"]["status"] == "unavailable"


def test_list_limits_are_unavailable_not_truncated(tmp_path, monkeypatch):
    monkeypatch.setattr(scope, "MAX_LIST_ITEMS", 1)
    rows = [object_for("pods", "work", name) for name in ("a", "b")]
    _, _, _, col = collect(tmp_path, changes={("pods", "work"): list_for("pods", "work", rows)})
    assert "pods" not in col.artifacts
    monkeypatch.setattr(scope, "MAX_LIST_BYTES", 1)
    _, _, _, col = collect(tmp_path)
    assert col.raw[scope.SCOPE_KEY]["status"] == "unavailable"


def test_other_declared_namespace_is_still_wrong_for_this_response(tmp_path):
    bad = list_for("deployments", "work", [object_for("deployments", "other")])
    _, _, _, col = collect(tmp_path, ("work", "other"), {("deployments", "work"): bad})
    rows = col.raw[scope.SCOPE_KEY]["resources"]["deployments"]
    assert rows["work"]["status"] == "unavailable" and rows["other"]["status"] == "collected"
    assert len(checks.KubeData(col).items("deployments")) == 1


@pytest.fixture
def scoped_account(selected_cluster, monkeypatch):
    ctx, target, person, config, policy, calls = selected_cluster
    target.options["namespaces"] = ["work"]
    ctx.inventory.save()

    def process(argv, **kwargs):
        calls.append((argv, kwargs))
        operation = argv[argv.index("get"):]
        assert operation[2:] == ["-n", "work", "-o", "json"]
        resource = operation[1]
        items = [object_for(resource, "work")] if resource == "deployments" else []
        return SimpleNamespace(returncode=0, stdout=json.dumps(list_for(resource, "work", items)), stderr="")

    monkeypatch.setattr("subprocess.run", process)
    return selected_cluster


def test_verified_account_collector_uses_selected_credential_and_namespace(scoped_account, tmp_path):
    ctx, target, person, config, _, calls = scoped_account
    with principal_scope(person), operation_scope("scan"):
        transport = ctx.transport_for(target)
        col = ctx.adapters.get("kubernetes").collect(target, transport, tmp_path / "raw")
    assert col.raw[scope.SCOPE_KEY]["namespace_lists_complete"] is True
    assert len(calls) == 7
    assert_selected(calls, config)
    assert TOKEN not in json.dumps(col.to_dict()) + ctx.audit.path.read_text()


def test_verified_scan_persists_scope_and_checklist_evidence(scoped_account):
    from cyberthunder.report.checklist import build_checklist

    ctx, target, person, config, policy_path, calls = scoped_account
    policy = json.loads(policy_path.read_text())
    policy["entries"][0]["grants"][0]["actions"].append("export")
    policy["entries"][0]["node_actions"] = ["audit", "export"]
    write(policy_path, json.dumps(policy).encode())
    person = replace(person, roles=(*person.roles, "auditor"))
    with principal_scope(person):
        run = ctx.scanner.start([target.id], modules=["check", "hunt"], requested_by=person.actor, background=False)
        assert run.status == "done" and run.results[target.id].status == "done"
        assert run.coverage_incomplete is True
        findings = ctx.store.load_findings(run.id)
        checklist = build_checklist(ctx, run.id, target.id)
        collected = ctx.store.read_json(ctx.store.scan_dir(run.id) / "raw" / target.id / "collected.json")
    assert len(calls) == 7
    assert_selected(calls, config)
    assert collected["raw"][scope.SCOPE_KEY]["namespaces"] == ["work"]
    assert run.results[target.id].facts["extra"]["node_count"] is None
    assert findings and all(f.collection_provenance[scope.SCOPE_KEY]["read_only"] for f in findings)
    assert "Namespace coverage: work; cluster coverage incomplete" in json.dumps(checklist)
    assert '"status": "not_a_finding"' not in json.dumps(checklist)
    assert any(f.is_open and f.rule_version == "k8s:cis:5.2.2" for f in findings)


def test_two_accounts_keep_unequal_api_permissions(scoped_account, cert_material, monkeypatch, tmp_path):
    ctx, target, alice, _, policy_path, calls = scoped_account
    bob = replace(alice, subject="bob")
    config = document(cert_material)
    config["current-context"] = config["contexts"][0]["name"] = "bob-A"
    config["contexts"][0]["context"]["user"] = config["users"][0]["name"] = "bob"
    config_path = write(policy_path.parent / "bob.yaml", config)
    policy = json.loads(policy_path.read_text())
    entry = copy.deepcopy(policy["entries"][0])
    entry["subject"] = "bob"
    entry["grants"][0]["actions"] = ["read", "scan"]
    entry["grants"][0]["credential"]["options"] = {"kubeconfig": str(config_path), "context": "bob-A"}
    policy["entries"].append(entry)
    write(policy_path, json.dumps(policy).encode())
    original = __import__("subprocess").run

    def process(argv, **kwargs):
        if argv[argv.index("--user") + 1] == "bob" and argv[argv.index("get") + 1] == "deployments":
            calls.append((argv, kwargs))
            return SimpleNamespace(returncode=1, stdout="", stderr="Forbidden")
        return original(argv, **kwargs)

    monkeypatch.setattr("subprocess.run", process)
    results = []
    for person in (alice, bob):
        with principal_scope(person), operation_scope("scan"):
            results.append(ctx.adapters.get("kubernetes").collect(
                target, ctx.transport_for(target), tmp_path / person.subject))
    assert results[0].raw[scope.SCOPE_KEY]["namespace_lists_complete"] is True
    assert results[1].raw[scope.SCOPE_KEY]["resources"]["deployments"]["work"]["status"] == "unavailable"
    assert [argv[argv.index("--user") + 1] for argv, _ in calls] == ["alice"] * 7 + ["bob"] * 7
    assert all("admin" not in argv for argv, _ in calls)


def test_revocation_during_first_list_prevents_publishing(scoped_account, monkeypatch, tmp_path):
    ctx, target, person, _, policy, calls = scoped_account
    original = __import__("subprocess").run

    def revoke(argv, **kwargs):
        result = original(argv, **kwargs)
        policy.write_text('{"version":1,"entries":[]}')
        return result

    monkeypatch.setattr("subprocess.run", revoke)
    with principal_scope(person), operation_scope("scan"), pytest.raises(PermissionError):
        ctx.adapters.get("kubernetes").collect(target, ctx.transport_for(target), tmp_path / "raw")
    assert len(calls) == 1 and not list((tmp_path / "raw").glob("*.json"))


@pytest.mark.parametrize("drift", ["namespace", "remove_namespace", "context", "credential", "policy", "scope", "kill", "actor"])
def test_verified_session_drift_blocks_next_read(scoped_account, tmp_path, monkeypatch, drift):
    ctx, target, person, config, policy, calls = scoped_account
    with principal_scope(person), operation_scope("scan"):
        transport = ctx.transport_for(target)
        if drift == "namespace":
            target.options["namespaces"] = ["other"]
        elif drift == "remove_namespace":
            target.options.pop("namespaces")
        elif drift == "context":
            target.options["context"] = "changed"
        elif drift == "credential":
            config.write_text("credential changed")
        elif drift == "policy":
            policy.write_text('{"version":1,"entries":[]}')
        elif drift == "scope":
            target.in_scope = False
        elif drift == "kill":
            monkeypatch.setenv("CT_KILL", "1")
        ctx.inventory.save()
        if drift == "actor":
            with principal_scope(replace(person, subject="other")), pytest.raises(PermissionError):
                transport.run(scope.list_command("pods", "work"))
        else:
            with pytest.raises((PermissionError, ScopeViolation, KillSwitchEngaged)):
                transport.run(scope.list_command("pods", "work"))
    assert not calls


def test_ungranted_person_cannot_borrow_workload_account(scoped_account):
    ctx, target, person, _, _, calls = scoped_account
    with principal_scope(replace(person, subject="other")), operation_scope("scan"), pytest.raises(PermissionError):
        ctx.transport_for(target)
    assert not calls


def test_default_cluster_transport_keeps_existing_commands():
    target = target_for()
    target.options.pop("namespaces")
    transport = KubernetesAdapter().make_transport(target)
    for command in checks.ARTIFACTS.values():
        argv, stdin = transport.build_argv(command)
        assert argv[3:] == command.split()[1:] and stdin is None
