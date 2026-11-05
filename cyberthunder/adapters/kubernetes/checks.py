"""Deterministic Kubernetes checks: DISA Kubernetes STIG (CNTR-K8-*) plus CIS Kubernetes Benchmark items.

Every check is a pure function of the collected JSON. Each finding:
  rule_id      k8s:<base>:<namespace>/<kind>/<name>[/<container>]   (or k8s:<base> for cluster-wide flags)
  rule_version <base>  e.g. CNTR-K8-000360 or k8s:cis:5.2.2   (the fix library keys on this)
  tags         k8s-object:<ref>  names the object the fix will touch

STIG titles, severities, V-ids and CCIs come from stig_rules.json (Kubernetes STIG V2R4). CIS items cite
the CIS Kubernetes Benchmark v1.8 section as "CIS-K8s-<n>" plus CCI-000366 (configuration settings)
because the STIG has no rule for that exact pod field; the description says so.
"""
from __future__ import annotations

import logging

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Iterator

from cyberthunder.adapters.base import Collected, make_finding
from cyberthunder.adapters.containers.images import uses_latest_or_untagged
from cyberthunder.findings.schema import Finding

from .kubectl import OBJ_TAG, ObjRef

SOURCE = "kubernetes"
SYSTEM_NAMESPACES = ("kube-system", "kube-public", "kube-node-lease")
STIG_FILE = Path(__file__).with_name("stig_rules.json")

ARTIFACTS = {
    "version": "kubectl version -o json",
    "nodes": "kubectl get nodes -o json",
    "namespaces": "kubectl get namespaces -o json",
    "pods": "kubectl get pods -A -o json",
    "deployments": "kubectl get deployments -A -o json",
    "serviceaccounts": "kubectl get serviceaccounts -A -o json",
    "clusterrolebindings": "kubectl get clusterrolebindings -o json",
    "rolebindings": "kubectl get rolebindings -A -o json",
    "networkpolicies": "kubectl get networkpolicies -A -o json",
    "cronjobs": "kubectl get cronjobs -A -o json",
    "services": "kubectl get services -A -o json",
}


@lru_cache(maxsize=1)
def stig_rules() -> dict[str, dict]:
    data = json.loads(STIG_FILE.read_text(encoding="utf-8"))
    return {r["stig_id"]: r for r in data}


@dataclass
class Rule:
    base: str                 # rule_version / fix-library key
    title: str
    severity: str
    refs: list[str]
    description: str
    benchmark: str = "Kubernetes STIG V2R4"
    group_id: str | None = None
    fix_text: str | None = None
    check_text: str | None = None


def stig(stig_id: str) -> Rule:
    r = stig_rules()[stig_id]
    return Rule(base=stig_id, title=r["title"], severity=r["severity"],
                refs=[stig_id, r["group_id"], *r.get("cci", [])],
                description=f"DISA Kubernetes STIG {stig_id} ({r['group_id']}). {r.get('check_summary', '')}",
                group_id=r["group_id"], fix_text=r.get("fix_summary"), check_text=r.get("check_summary"))


def cis(section: str, title: str, severity: str, why: str, extra_refs: Iterable[str] = ()) -> Rule:
    return Rule(base=f"k8s:cis:{section}", title=title, severity=severity,
                refs=[f"CIS-K8s-{section}", "CCI-000366", *extra_refs],
                description=(f"CIS Kubernetes Benchmark v1.8 control {section}. {why} The DISA Kubernetes STIG has "
                             "no rule for this exact field (it is covered by the pod security admission requirement, "
                             "CNTR-K8-002010), so the finding cites the CIS control and CCI-000366."),
                benchmark="CIS Kubernetes Benchmark v1.8")


CIS_RULES = {
    "privileged": cis("5.2.2", "Privileged container", "high",
                      "A privileged container has every capability and full access to the node's devices."),
    "hostPID": cis("5.2.3", "Pod shares the host PID namespace", "high",
                   "hostPID lets the pod see and signal every process on the node."),
    "hostIPC": cis("5.2.4", "Pod shares the host IPC namespace", "medium",
                   "hostIPC lets the pod read shared memory of host processes."),
    "hostNetwork": cis("5.2.5", "Pod shares the host network namespace", "medium",
                       "hostNetwork bypasses network policy and exposes node-local services."),
    "escalation": cis("5.2.6", "allowPrivilegeEscalation is not set to false", "medium",
                      "Without allowPrivilegeEscalation: false a process can gain more privileges than its parent (setuid)."),
    "root": cis("5.2.7", "Container may run as root", "medium",
                "runAsNonRoot is not true or runAsUser is 0, so a container breakout lands as root."),
    "hostPath": cis("5.2.12", "Pod mounts a hostPath volume", "medium",
                    "hostPath volumes give the pod direct access to the node filesystem."),
    "automount": cis("5.1.5", "Default service account token is automounted", "medium",
                     "Pods that do not name a service account get the namespace default one; its token should not be mounted."),
    "cluster_admin": cis("5.1.1", "cluster-admin bound to a service account", "high",
                         "cluster-admin should only be bound where strictly required, never to workload identities."),
    "netpol": cis("5.3.2", "Namespace has no NetworkPolicy", "medium",
                  "Without a NetworkPolicy every pod in the namespace accepts traffic from anywhere in the cluster."),
}
LOCAL_RULES = {
    "anonymous_rbac": Rule(base="k8s:ct:anonymous-binding", title="RBAC binding grants rights to anonymous users",
                           severity="high", refs=["CCI-000213", "CNTR-K8-000360", "V-242390"],
                           description=("A RoleBinding or ClusterRoleBinding names system:anonymous or "
                                        "system:unauthenticated, so requests without credentials gain those rights. "
                                        "Cites the STIG access-enforcement CCI and the related anonymous-auth rule."),
                           benchmark="Cyber Thunder Kubernetes checks"),
    "limits": Rule(base="k8s:ct:resource-limits", title="Container has no CPU or memory limit", severity="low",
                   refs=["CCI-002385"],
                   description=("No resources.limits for cpu and memory: one runaway or hostile pod can starve the node. "
                                "No STIG or CIS item covers this directly; cited against CCI-002385 (denial-of-service protection)."),
                   benchmark="Cyber Thunder Kubernetes checks"),
    "latest": Rule(base="k8s:ct:image-latest", title="Image uses :latest or no tag", severity="low",
                   refs=["CCI-000366"],
                   description=("A mutable tag means the running code can change on the next pull without review. "
                                "No STIG or CIS item covers this directly; cited against CCI-000366."),
                   benchmark="Cyber Thunder Kubernetes checks"),
}


# -- data access ------------------------------------------------------------------------------
class KubeData:
    """Lazy view over the JSON artifacts saved by collect()."""

    def __init__(self, collected: Collected):
        self.c = collected
        self._cache: dict[str, object] = {}

    def doc(self, name: str):
        if name not in self._cache:
            p = self.c.path(name)
            val = None
            if p and p.exists():
                try:
                    val = json.loads(p.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    self.c.errors.append(f"{name}: not JSON")
            elif name in self.c.raw:
                val = self.c.raw[name]
            self._cache[name] = val
        return self._cache[name]

    def items(self, name: str) -> list[dict]:
        d = self.doc(name)
        return list(d.get("items", [])) if isinstance(d, dict) else []

    def configz(self) -> dict[str, dict]:
        out = {}
        for k in self.c.artifacts:
            if k.startswith("configz_"):
                d = self.doc(k)
                if isinstance(d, dict):
                    out[k[len("configz_"):]] = d.get("kubeletconfig", d)
        return out


@dataclass
class Workload:
    ref: ObjRef            # owner object (deployment / cronjob / bare pod)
    pod_spec: dict
    labels: dict = field(default_factory=dict)
    meta: dict = field(default_factory=dict)   # the object's metadata (owner references, annotations)

    @property
    def namespace(self) -> str:
        return self.ref.namespace or ""


def workloads(data: KubeData) -> Iterator[Workload]:
    """Deployments, CronJobs and pods not created by a ReplicaSet or Job (those are covered by their owner)."""
    for d in data.items("deployments"):
        md = d["metadata"]
        yield Workload(ObjRef(md["namespace"], "deployment", md["name"]),
                       d.get("spec", {}).get("template", {}).get("spec", {}), md.get("labels", {}), md)
    for cj in data.items("cronjobs"):
        md = cj["metadata"]
        spec = cj.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
        yield Workload(ObjRef(md["namespace"], "cronjob", md["name"]), spec, md.get("labels", {}))
    for p in data.items("pods"):
        md = p["metadata"]
        owners = {o.get("kind") for o in md.get("ownerReferences", [])}
        if owners & {"ReplicaSet", "Job"}:
            continue
        yield Workload(ObjRef(md["namespace"], "pod", md["name"]), p.get("spec", {}), md.get("labels", {}), md)


def containers_of(spec: dict) -> list[dict]:
    return list(spec.get("initContainers", []) or []) + list(spec.get("containers", []) or [])


def parse_flags(command: list[str]) -> dict[str, str]:
    """--flag=value / --flag value / --flag (true) from a container command+args array."""
    flags: dict[str, str] = {}
    i = 0
    while i < len(command):
        a = str(command[i])
        if a.startswith("--"):
            if "=" in a:
                k, v = a[2:].split("=", 1)
            elif i + 1 < len(command) and not str(command[i + 1]).startswith("-"):
                k, v = a[2:], str(command[i + 1])
                i += 1
            else:
                k, v = a[2:], "true"
            flags[k] = v
        i += 1
    return flags


def component_pods(data: KubeData, component: str) -> list[tuple[ObjRef, dict[str, str]]]:
    """kube-system pods whose container runs `component` (kube-apiserver, kubelet, ...), with parsed flags."""
    out = []
    for p in data.items("pods"):
        md = p["metadata"]
        if md.get("namespace") != "kube-system":
            continue
        for c in p.get("spec", {}).get("containers", []):
            cmd = [str(x) for x in (c.get("command") or []) + (c.get("args") or [])]
            if cmd and Path(cmd[0]).name == component:
                out.append((ObjRef("kube-system", "pod", md["name"], c.get("name")), parse_flags(cmd)))
    return out


K3S_FLAGS = "k3s_flags"   # Collected.raw key written by the adapter when options.node_target is set


def component_sources(data: KubeData, component: str) -> list[tuple[ObjRef, str, dict[str, str]]]:
    """(object, evidence prefix, flags) for every place `component` flags were read: kube-system pods
    (kubeadm-style static pods) and, on k3s, the server node's config file and unit command line."""
    out = [(ObjRef(ref.namespace, "pod", ref.name), f"kube-system/{ref.name} container {ref.container}: ", f)
           for ref, f in component_pods(data, component)]
    k3s = data.doc(K3S_FLAGS)
    if isinstance(k3s, dict) and isinstance(k3s.get(component), dict):
        node = str(k3s.get("node") or "")
        try:
            node_ref = ObjRef(None, "node", node)
        except ValueError:
            return out
        src = " + ".join(k3s.get("sources") or []) or "k3s defaults"
        out.append((node_ref, f"node {node} k3s {component} ({src}): ", dict(k3s[component])))
    return out


# -- finding builder --------------------------------------------------------------------------
def finding(target, rule: Rule, ref: ObjRef | None, evidence: str, *, extra: str = "",
            source: str = SOURCE, tags: Iterable[str] = (), severity: str | None = None,
            collected_at: str | None = None, raw_ref: str | None = None, status: str = "open") -> Finding:
    rule_id = f"k8s:{rule.base}" if not rule.base.startswith("k8s:") else rule.base
    t = list(tags)
    if ref is not None:
        rule_id += f":{ref.to_str()}"
        t.append(OBJ_TAG + ref.to_str())
    return make_finding(target=target, source=source, rule_id=rule_id, title=rule.title,
                        severity=severity or rule.severity, description=(rule.description + (" " + extra if extra else "")).strip(),
                        evidence=evidence, references=rule.refs, rule_version=rule.base, group_id=rule.group_id,
                        benchmark=rule.benchmark, check_text=rule.check_text, fix_text=rule.fix_text,
                        tags=["kubernetes", *t], collected_at=collected_at, raw_ref=raw_ref, status=status)


# -- checks -----------------------------------------------------------------------------------
APISERVER_RULES = ("CNTR-K8-000360", "CNTR-K8-000320", "CNTR-K8-000340", "CNTR-K8-000270", "CNTR-K8-000610",
                   "CNTR-K8-003280")


def check_apiserver(target, data: KubeData) -> list[Finding]:
    out: list[Finding] = []
    sources = component_sources(data, "kube-apiserver")
    if not sources and data.doc("pods") is not None:
        # k3s, RKE2 and managed clusters keep the API server out of the API; say so instead of passing silently
        why = ("No kube-apiserver flags were collected: no kube-apiserver pod in kube-system and no k3s server node "
               "(target option node_target) to read them from. Review this rule on the control-plane node by hand.")
        for sid in APISERVER_RULES:
            out.append(finding(target, stig(sid), None, why, status="not_reviewed"))
        return out
    for pod_ref, ev, f in sources:
        if f.get("anonymous-auth", "").lower() == "true":
            out.append(finding(target, stig("CNTR-K8-000360"), pod_ref, ev + "--anonymous-auth=true"))
        if "insecure-port" in f and f["insecure-port"] != "0":
            out.append(finding(target, stig("CNTR-K8-000320"), pod_ref, ev + f"--insecure-port={f['insecure-port']}"))
        if "insecure-bind-address" in f:
            out.append(finding(target, stig("CNTR-K8-000340"), pod_ref, ev + f"--insecure-bind-address={f['insecure-bind-address']}"))
        modes = [m.strip() for m in f.get("authorization-mode", "").split(",") if m.strip()]
        if not modes or "AlwaysAllow" in modes or "RBAC" not in modes or "Node" not in modes:
            out.append(finding(target, stig("CNTR-K8-000270"), pod_ref,
                               ev + (f"--authorization-mode={f['authorization-mode']}" if modes else "--authorization-mode not set")))
        if not f.get("audit-log-path"):
            out.append(finding(target, stig("CNTR-K8-000610"), pod_ref, ev + "--audit-log-path not set"))
        if not f.get("audit-policy-file"):
            out.append(finding(target, stig("CNTR-K8-003280"), pod_ref, ev + "--audit-policy-file not set"))
    return out


def check_controller_manager(target, data: KubeData) -> list[Finding]:
    out: list[Finding] = []
    for pod_ref, ev, f in component_sources(data, "kube-controller-manager"):
        if f.get("use-service-account-credentials", "false").lower() != "true":
            out.append(finding(target, stig("CNTR-K8-000220"), pod_ref, ev + "--use-service-account-credentials not true"))
        if f.get("profiling", "true").lower() != "false":
            out.append(finding(target, stig("CNTR-K8-000910"), pod_ref, ev + "--profiling not false"))
    return out


def check_kubelet(target, data: KubeData) -> list[Finding]:
    """Kubelet flags from a kube-system pod running kubelet, and kubelet config from the node configz endpoint."""
    out: list[Finding] = []
    configz = data.configz()
    for pod_ref, ev, f in component_sources(data, "kubelet"):
        if pod_ref.kind == "node" and pod_ref.name in configz:
            continue   # the node's configz is the effective kubelet configuration; prefer it over k3s flags
        if f.get("anonymous-auth", "").lower() == "true":
            out.append(finding(target, stig("CNTR-K8-000370"), pod_ref, ev + "--anonymous-auth=true"))
        if "read-only-port" in f and f["read-only-port"] != "0":
            out.append(finding(target, stig("CNTR-K8-000330"), pod_ref, ev + f"--read-only-port={f['read-only-port']}"))
        if "authorization-mode" in f and f["authorization-mode"] != "Webhook":
            out.append(finding(target, stig("CNTR-K8-000380"), pod_ref, ev + f"--authorization-mode={f['authorization-mode']}"))
    for node, cfg in configz.items():
        try:
            node_ref = ObjRef(None, "node", node)
        except ValueError:
            continue
        ev = f"node {node} kubelet configz: "
        if cfg.get("authentication", {}).get("anonymous", {}).get("enabled") is True:
            out.append(finding(target, stig("CNTR-K8-000370"), node_ref, ev + "authentication.anonymous.enabled=true"))
        rop = cfg.get("readOnlyPort")
        if rop not in (None, 0, "0"):
            out.append(finding(target, stig("CNTR-K8-000330"), node_ref, ev + f"readOnlyPort={rop}"))
        mode = cfg.get("authorization", {}).get("mode")
        if mode is not None and mode != "Webhook":
            out.append(finding(target, stig("CNTR-K8-000380"), node_ref, ev + f"authorization.mode={mode}"))
        if cfg.get("staticPodPath"):
            out.append(finding(target, stig("CNTR-K8-000440"), node_ref, ev + f"staticPodPath={cfg['staticPodPath']}"))
        if cfg.get("protectKernelDefaults") is not True:
            out.append(finding(target, stig("CNTR-K8-001620"), node_ref, ev + "protectKernelDefaults is not true"))
    return out


def check_pod_security(target, data: KubeData) -> list[Finding]:
    out: list[Finding] = []
    for w in workloads(data):
        if w.namespace in SYSTEM_NAMESPACES:
            continue
        spec, base = w.pod_spec, w.ref
        where = f"{w.namespace}/{base.kind}/{base.name}"
        for ns_field in ("hostPID", "hostIPC", "hostNetwork"):
            if spec.get(ns_field):
                out.append(finding(target, CIS_RULES[ns_field], base, f"{where}: spec.{ns_field}=true"))
        for v in spec.get("volumes", []) or []:
            hp = (v.get("hostPath") or {}).get("path")
            if hp:
                sensitive = hp in ("/", "/etc", "/root", "/var/run/docker.sock", "/run/containerd/containerd.sock",
                                   "/var/run/containerd/containerd.sock", "/var/lib/kubelet")
                out.append(_hostpath_finding(target, base, where, v, hp, sensitive))
        pod_sc = spec.get("securityContext") or {}
        for c in containers_of(spec):
            cref = ObjRef(base.namespace, base.kind, base.name, c.get("name"))
            sc = c.get("securityContext") or {}
            cw = f"{where} container {c.get('name')}"
            if sc.get("privileged"):
                out.append(finding(target, CIS_RULES["privileged"], cref, f"{cw}: securityContext.privileged=true"))
            if sc.get("allowPrivilegeEscalation") is not False:
                out.append(finding(target, CIS_RULES["escalation"], cref,
                                   f"{cw}: allowPrivilegeEscalation={sc.get('allowPrivilegeEscalation', 'unset')}"))
            run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
            non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
            if run_as_user == 0 or (non_root is not True and not run_as_user):
                out.append(finding(target, CIS_RULES["root"], cref,
                                   f"{cw}: runAsNonRoot={non_root if non_root is not None else 'unset'}, "
                                   f"runAsUser={run_as_user if run_as_user is not None else 'unset'}"))
            limits = (c.get("resources") or {}).get("limits") or {}
            if not ("cpu" in limits and "memory" in limits):
                out.append(finding(target, LOCAL_RULES["limits"], cref, f"{cw}: limits={limits or 'none'}"))
            image = c.get("image", "")
            if image and uses_latest_or_untagged(image):
                out.append(finding(target, LOCAL_RULES["latest"], cref, f"{cw}: image {image}"))
            for e in c.get("env", []) or []:
                skr = (e.get("valueFrom") or {}).get("secretKeyRef")
                if skr:
                    out.append(finding(target, stig("CNTR-K8-001160"), cref,
                                       f"{cw}: env {e.get('name')} from secret {skr.get('name')}/{skr.get('key')}"))
                    break
            else:
                for e in c.get("envFrom", []) or []:
                    sr = e.get("secretRef")
                    if sr:
                        out.append(finding(target, stig("CNTR-K8-001160"), cref,
                                           f"{cw}: envFrom secret {sr.get('name')} (all keys)"))
                        break
            for port in c.get("ports", []) or []:
                hp = port.get("hostPort")
                if hp and int(hp) < 1024:
                    out.append(finding(target, stig("CNTR-K8-000960"), cref, f"{cw}: hostPort {hp}"))
                    break
    return out


def _hostpath_finding(target, base: ObjRef, where: str, vol: dict, path: str, sensitive: bool) -> Finding:
    # one finding per workload and volume, so the volume name is appended to the rule id
    f = finding(target, CIS_RULES["hostPath"], base, f"{where}: volume {vol.get('name')} hostPath {path}",
                severity="high" if sensitive else None, tags=[f"k8s-volume:{vol.get('name')}"])
    f.rule_id = f"{f.rule_id}#{vol.get('name')}"
    f.id = f.make_id(f.host, f.source, f.rule_id)
    return f


def check_namespaces(target, data: KubeData) -> list[Finding]:
    out: list[Finding] = []
    # STIG CNTR-K8-000290: user workloads in default / kube-public / kube-node-lease
    for w in workloads(data):
        if w.namespace in ("default", "kube-public", "kube-node-lease"):
            out.append(finding(target, stig("CNTR-K8-000290"), w.ref, f"{w.ref.key()} runs in namespace {w.namespace}"))
    # CIS 5.3.2: user namespaces with workloads but no NetworkPolicy
    with_policy = {p["metadata"]["namespace"] for p in data.items("networkpolicies")}
    with_workloads = {w.namespace for w in workloads(data)}
    for ns in sorted(with_workloads - with_policy - set(SYSTEM_NAMESPACES)):
        out.append(finding(target, CIS_RULES["netpol"], ObjRef(None, "namespace", ns), f"namespace {ns}: no NetworkPolicy"))
    # CNTR-K8-000420: dashboard deployed
    for p in data.items("pods"):
        md = p["metadata"]
        if md.get("labels", {}).get("k8s-app") == "kubernetes-dashboard":
            out.append(finding(target, stig("CNTR-K8-000420"), ObjRef(md["namespace"], "pod", md["name"]),
                               f"{md['namespace']}/{md['name']} labeled k8s-app=kubernetes-dashboard"))
    return out


def check_service_accounts(target, data: KubeData) -> list[Finding]:
    out: list[Finding] = []
    for sa in data.items("serviceaccounts"):
        md = sa["metadata"]
        if md["name"] != "default" or md.get("namespace") in SYSTEM_NAMESPACES:
            continue
        if sa.get("automountServiceAccountToken") is not False:
            out.append(finding(target, CIS_RULES["automount"], ObjRef(md["namespace"], "serviceaccount", "default"),
                               f"{md['namespace']}/serviceaccount/default: automountServiceAccountToken="
                               f"{sa.get('automountServiceAccountToken', 'unset')}"))
    return out


log = logging.getLogger(__name__)

ANON_SUBJECTS = {"system:anonymous", "system:unauthenticated"}


def is_default_sa(subj: dict) -> bool:
    return subj.get("kind") == "ServiceAccount" and subj.get("name") == "default"


def bindings(data: KubeData) -> Iterator[tuple[ObjRef, dict]]:
    """Every binding as an addressable reference; one unaddressable object is skipped, not fatal."""
    for b in data.items("clusterrolebindings"):
        try:
            yield ObjRef(None, "clusterrolebinding", b["metadata"]["name"]), b
        except (ValueError, KeyError) as e:
            log.warning("skipping clusterrolebinding: %s", e)
    for b in data.items("rolebindings"):
        try:
            yield ObjRef(b["metadata"]["namespace"], "rolebinding", b["metadata"]["name"]), b
        except (ValueError, KeyError) as e:
            log.warning("skipping rolebinding: %s", e)


def check_rbac(target, data: KubeData) -> list[Finding]:
    """cluster-admin to a (non-default) service account, and anonymous subjects bound to anything but cluster-admin.
    The cluster-admin-to-default / anonymous case is an ownership/privilege review indicator in the hunt module."""
    out: list[Finding] = []
    for ref, b in bindings(data):
        role = (b.get("roleRef") or {}).get("name")
        for s in b.get("subjects", []) or []:
            if role == "cluster-admin" and s.get("kind") == "ServiceAccount" and not is_default_sa(s):
                out.append(finding(target, CIS_RULES["cluster_admin"], ref,
                                   f"{ref.kind} {ref.name}: cluster-admin -> ServiceAccount {s.get('namespace')}/{s.get('name')}"))
            if s.get("name") in ANON_SUBJECTS and role != "cluster-admin":
                out.append(finding(target, LOCAL_RULES["anonymous_rbac"], ref,
                                   f"{ref.kind} {ref.name}: {role} -> {s.get('kind')} {s.get('name')}"))
    return out


ALL_CHECKS = (check_apiserver, check_controller_manager, check_kubelet, check_pod_security, check_namespaces,
              check_service_accounts, check_rbac)


def run_checks(target, collected: Collected) -> list[Finding]:
    data = KubeData(collected)
    out: list[Finding] = []
    for fn in ALL_CHECKS:
        try:
            out.extend(fn(target, data))
        except Exception as e:  # noqa: BLE001  one broken check must not hide the rest
            collected.errors.append(f"check {fn.__name__}: {e}")
    for f in out:
        f.collected_at = collected.collected_at
    return dedupe(out)


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    res = []
    for f in findings:
        if f.id not in seen:
            seen.add(f.id)
            res.append(f)
    return res
