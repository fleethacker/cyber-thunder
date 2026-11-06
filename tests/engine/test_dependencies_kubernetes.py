"""Sanitized Kubernetes relationships, pagination, missing evidence and scope drift."""
from copy import deepcopy
import json

import pytest

from cyberthunder.adapters.kubernetes.fixes import kubernetes_fixes
from cyberthunder.remediation import dependencies as dep, dependencies_io as io
from cyberthunder.remediation.engine import EngineError

from .test_dependencies import ACTOR, HOST, seed, wire
from .test_plan import persist, stored_state

BASE = "kubectl --request-timeout=8s get --raw "
OBJECT_PATH = "/apis/apps/v1/namespaces/team/deployments/web"
PODS_PATH = "/api/v1/namespaces/team/pods?limit=33"
SERVICES_PATH = "/api/v1/namespaces/team/services?limit=33"
PDBS_PATH = "/apis/policy/v1/namespaces/team/poddisruptionbudgets?limit=33"


def object_doc(kind, name, spec, *, status=None, ns="team", labels=None, api="v1"):
    return {"apiVersion": api, "kind": kind,
            "metadata": {"name": name, "namespace": ns, "labels": labels or {"app": "web"},
                         "annotations": {"credential": "annotation-private"}},
            "spec": spec, "status": status or {}}


def list_doc(*items, continuation=""):
    return {"kind": "List", "metadata": {"continue": continuation}, "items": list(items)}


def documents():
    pod_spec = {"serviceAccountName": "web-identity", "containers": [{"name": "web", "image": "web",
                "env": [{"name": "PASSWORD", "value": "env-private"}], "command": ["command-private"]}],
                "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "web-data"}},
                            {"name": "host", "hostPath": {"path": "/sensitive-host-private"}},
                            {"name": "credential", "secret": {"secretName": "web-credentials"}}]}
    workload = object_doc("Deployment", "web", {"replicas": 1, "selector": {"matchLabels": {"app": "web"}},
                          "template": {"metadata": {"labels": {"app": "web"}}, "spec": pod_spec}},
                          status={"readyReplicas": 1, "availableReplicas": 1}, api="apps/v1")
    pod = object_doc("Pod", "web-one", pod_spec, status={"conditions": [{"type": "Ready", "status": "True"}]})
    svc = object_doc("Service", "web-http", {"selector": {"app": "web"}, "ports": [{"port": 80}]})
    unrelated = object_doc("Service", "other", {"selector": {"app": "other"}})
    pdb = object_doc("PodDisruptionBudget", "web-budget", {"selector": {"matchLabels": {"app": "web"}}},
                     status={"disruptionsAllowed": 0}, api="policy/v1")
    return {OBJECT_PATH: workload, PODS_PATH: list_doc(pod), SERVICES_PATH: list_doc(svc, unrelated),
            PDBS_PATH: list_doc(pdb)}


def kube_seed(ctx, tmp_path, docs=None, tags=None):
    fix = next(e for e in kubernetes_fixes() if e.fix_ref == "k8s:fix:deployment-drop-privileged")
    proposal, fix, root, finding = seed(ctx, tmp_path, asset="kubernetes", fix=fix,
                                      tags=tags if tags is not None else ["k8s-object:team/deployment/web/web"])
    docs = documents() if docs is None else docs
    entries = [{"match": BASE + path, "stdout": json.dumps(doc)} for path, doc in docs.items()]
    (root / "commands.json").write_text(json.dumps(entries), encoding="utf-8")
    return proposal, fix, root, finding


def test_kubernetes_concrete_relationships_and_no_config_disclosure(ctx, tmp_path, monkeypatch):
    proposal, _, root, _ = kube_seed(ctx, tmp_path)
    before = stored_state(ctx)
    calls, transport = wire(ctx, monkeypatch, root)
    result = dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)
    assert stored_state(ctx) == before and transport.closed
    assert calls == [BASE + path for path in (OBJECT_PATH, PODS_PATH, SERVICES_PATH, PDBS_PATH)]
    assert all("/namespaces/team/" in c for c in calls)
    assert all("secrets" not in c and " -A" not in c and "configz" not in c for c in calls)
    edges = {(e["from"], e["to"], e["relation"]) for e in result["dependencies"]}
    assert ("team/service/web-http", "team/deployment/web", "selector-matches") in edges
    assert ("team/deployment/web", "team/pod/web-one", "selector-matches") in edges
    assert ("team/deployment/web", "team/serviceaccount/web-identity", "references") in edges
    assert ("team/deployment/web", "team/persistentvolumeclaim/web-data", "references") in edges
    assert ("team/deployment/web", "team/poddisruptionbudget/web-budget", "matched-by-budget") in edges
    assert not any("other" in e["from"] for e in result["dependencies"])
    for category in ("limited-redundancy", "pdb-no-disruptions", "host-volume", "persistent-volume"):
        assert any(r["id"].startswith(category + "-") for r in result["risks"])
    text = json.dumps(result)
    for private in ("annotation-private", "env-private", "command-private", "/sensitive-host-private", "containers", '"env"'):
        assert private not in text
    assert not result["complete"]
    again = dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)
    for key in ("evidence", "dependencies", "risks"):
        assert [x["id"] for x in again[key]] == [x["id"] for x in result[key]]
        assert len({x["id"] for x in result[key]}) == len(result[key])


@pytest.mark.parametrize("case", ["partial", "empty", "denied", "bad_json", "wrong_namespace", "oversized", "invalid_selector", "missing_replicas"])
def test_kubernetes_unknowns_do_not_fabricate_absence(ctx, tmp_path, monkeypatch, case):
    docs = documents()
    if case == "partial":
        docs[PDBS_PATH] = list_doc(continuation="next-private-token")
    elif case == "empty":
        docs[PDBS_PATH] = list_doc()
    elif case == "denied":
        docs.pop(PDBS_PATH)
    elif case == "bad_json":
        docs[PDBS_PATH] = "raw-error-private"
    elif case == "wrong_namespace":
        docs[PDBS_PATH]["items"][0]["metadata"]["namespace"] = "other-team"
    elif case == "oversized":
        row = docs[PDBS_PATH]["items"][0]
        docs[PDBS_PATH]["items"] = []
        for index in range(33):
            item = deepcopy(row)
            item["metadata"]["name"] = "budget-" + str(index)
            docs[PDBS_PATH]["items"].append(item)
    elif case == "invalid_selector":
        docs[PDBS_PATH]["items"][0]["spec"]["selector"] = {"matchExpressions": [{"key": "app", "operator": "Unknown"}]}
    else:
        docs[OBJECT_PATH]["spec"].pop("replicas")
        docs[OBJECT_PATH]["status"] = {}
    proposal, _, root, _ = kube_seed(ctx, tmp_path, docs)
    calls, _ = wire(ctx, monkeypatch, root)
    result = dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)
    assert len(calls) == 4 and not result["complete"]
    assert any(r["id"].startswith("no-matching-pdb-") for r in result["risks"]) == (case == "empty")
    if case == "missing_replicas":
        assert not any(r["id"].startswith("limited-redundancy-") for r in result["risks"])
        assert any("missing counts" in s for s in result["unknowns"])
    if case not in {"empty", "missing_replicas"}:
        assert any("not be resolved completely" in s for s in result["unknowns"])
    assert "private-token" not in json.dumps(result) and "raw-error-private" not in json.dumps(result)


@pytest.mark.parametrize("tags", [["k8s-object:team/deployment/web;evil/web"],
                                 ["k8s-object:team/deployment/web\n/web"],
                                 ["k8s-object:team/secret/credential"],
                                 ["k8s-object:team/deployment/web/web", "k8s-object:team/deployment/other/web"],
                                 ["k8s-object:-/node/worker"], []])
def test_unsupported_or_injected_manifest_reference_never_queries(ctx, tmp_path, monkeypatch, tags):
    proposal, _, root, _ = kube_seed(ctx, tmp_path, tags=tags)
    wire(ctx, monkeypatch, root)
    monkeypatch.setattr(ctx, "transport_for", lambda t: pytest.fail("unsupported binding opened transport"))
    result = dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)
    assert len(result["evidence"]) == 1 and not result["dependencies"]
    assert any("no supported exact workload binding" in s for s in result["unknowns"])


def test_object_reference_drift_discards_evidence(ctx, tmp_path, monkeypatch):
    proposal, _, _, finding = kube_seed(ctx, tmp_path)
    original = io.read_command

    def read(*args, **kwargs):
        text = original(*args, **kwargs)
        finding.tags = ["k8s-object:team/deployment/other/web"]
        persist(ctx, [finding], "changed-binding", offset=10)
        return text

    monkeypatch.setattr(io, "read_command", read)
    with pytest.raises(EngineError, match="object binding changed"):
        dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)


@pytest.mark.parametrize("selector,matched", [({}, True), ({"matchLabels": {"app": "other"}}, False),
    ({"matchExpressions": [{"key": "app", "operator": "In", "values": ["web"]}]}, True),
    ({"matchExpressions": [{"key": "app", "operator": "NotIn", "values": ["web"]}]}, False),
    ({"matchExpressions": [{"key": "missing", "operator": "NotIn", "values": ["web"]}]}, True),
    ({"matchExpressions": [{"key": "app", "operator": "Exists"}]}, True),
    ({"matchExpressions": [{"key": "app", "operator": "DoesNotExist"}]}, False)])
def test_pdb_selector_semantics(ctx, tmp_path, monkeypatch, selector, matched):
    docs = documents()
    docs[PDBS_PATH]["items"][0]["spec"]["selector"] = selector
    proposal, _, root, _ = kube_seed(ctx, tmp_path, docs)
    wire(ctx, monkeypatch, root)
    result = dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)
    assert any(e["relation"] == "matched-by-budget" for e in result["dependencies"]) == matched


def test_kubernetes_missing_current_finding_never_uses_historical_object(ctx, tmp_path, monkeypatch):
    proposal, _, root, _ = kube_seed(ctx, tmp_path)
    persist(ctx, [], "removed-finding", offset=10, targets=[proposal.host])
    wire(ctx, monkeypatch, root)
    monkeypatch.setattr(ctx, "transport_for", lambda t: pytest.fail("historical object queried"))
    result = dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)
    assert not result["dependencies"] and len(result["evidence"]) == 1
