"""Kubernetes intrusion and persistence indicators. Every finding cites a MITRE ATT&CK technique.

  k8s:hunt:host-escape          privileged pod with a sensitive hostPath (/, runtime socket), any namespace except
                                known kube-system components                                                     T1611
  k8s:hunt:untrusted-registry   image from a registry not in target.options.allowed_registries                    T1525
  k8s:hunt:cronjob-download     CronJob that downloads or opens a shell to the network                            T1053.007
  k8s:hunt:admin-to-default     cluster-admin bound to a default service account or to anonymous users            T1078.004
  k8s:hunt:unexpected-system-pod  kube-system pod that is not a known control-plane / add-on component            T1610
  k8s:hunt:masquerade           pod named like a system daemon in a user namespace                               T1036.005
  k8s:hunt:dashboard-exposed    kubernetes-dashboard reachable through a NodePort / LoadBalancer service         T1133
  k8s:hunt:host-listener        hostNetwork pod with listening ports outside kube-system                          T1571
"""
from __future__ import annotations

import re

from cyberthunder.adapters.base import Collected
from cyberthunder.adapters.containers.images import registry_allowed
from cyberthunder.findings.schema import Finding

from .checks import (ANON_SUBJECTS, SYSTEM_NAMESPACES, KubeData, Rule, bindings, containers_of, dedupe, finding,
                     is_default_sa, workloads)
from .kubectl import ObjRef

SOURCE = "hunt"

SENSITIVE_HOST_PATHS = ("/", "/etc", "/root", "/var/run/docker.sock", "/run/containerd/containerd.sock",
                        "/var/run/containerd/containerd.sock", "/var/run/crio/crio.sock", "/var/lib/kubelet", "/proc")

# Pod name prefixes expected in kube-system on kubeadm, k3s, RKE2 and the common CNIs. Extend per site with
# target.options.known_kube_system. A name match alone is not enough: the pod must also be created by a
# controller (ReplicaSet, DaemonSet, StatefulSet, Job) or be a static pod, so a hand-made pod named
# "kube-proxy-helper" or "coredns-x" is still unexpected.
KNOWN_KUBE_SYSTEM = ("coredns", "kube-apiserver", "kube-controller-manager", "kube-scheduler", "kube-proxy", "etcd",
                     "kubelet", "metrics-server", "local-path-provisioner", "traefik", "svclb-", "helm-install-",
                     "calico", "cilium", "kube-flannel", "flannel", "canal", "weave-net", "kube-dns", "konnectivity",
                     "cloud-controller-manager", "csi-", "snapshot-controller", "rke2-", "kube-vip")
SYSTEM_DAEMON_NAMES = ("kube-proxy", "kube-apiserver", "kube-controller", "kube-scheduler", "kubelet", "etcd",
                       "coredns", "calico-node", "cilium", "kube-flannel", "systemd", "containerd", "dockerd", "kworker")

CONTROLLER_KINDS = {"ReplicaSet", "DaemonSet", "StatefulSet", "Job", "Node"}
STATIC_POD_SOURCES = {"file", "http"}

RE_DOWNLOAD = re.compile(r"\b(curl|wget|nc|ncat|socat|tftp)\b")
RE_SHELL_C = re.compile(r"\b(sh|bash|ash|dash|zsh)\s+-c\b")
RE_NETWORK = re.compile(r"(https?://|\b\d{1,3}(?:\.\d{1,3}){3}\b|/dev/tcp/)")


def _rule(base: str, title: str, severity: str, technique: str, why: str, extra: tuple[str, ...] = ()) -> Rule:
    return Rule(base=f"k8s:hunt:{base}", title=title, severity=severity, refs=[technique, *extra],
                description=f"ATT&CK {technique}. {why}", benchmark="Cyber Thunder hunt")


HUNT_RULES = {
    "escape": _rule("host-escape", "Privileged pod mounts the host filesystem", "high", "T1611",
                    "A privileged container with the node root or the container runtime socket mounted can take "
                    "over the node (escape to host)."),
    "registry": _rule("untrusted-registry", "Image pulled from an unapproved registry", "high", "T1525",
                      "Workloads should only run images from the enclave's approved registries; an outside image "
                      "may be implanted (implant internal image)."),
    "cronjob": _rule("cronjob-download", "CronJob downloads and runs code from the network", "high", "T1053.007",
                     "A scheduled job that fetches and pipes remote content into a shell is a classic container "
                     "orchestration persistence mechanism (scheduled task/job: container orchestration job)."),
    "admin_default": _rule("admin-to-default", "cluster-admin granted to a default service account or anonymous users",
                           "high", "T1078.004",
                           "Any pod in that namespace (or any unauthenticated client) now holds full cluster control "
                           "(valid accounts: cloud accounts).", ("CIS-K8s-5.1.1",)),
    "system_pod": _rule("unexpected-system-pod", "Unexpected pod in kube-system", "high", "T1610",
                        "kube-system should only hold control-plane and add-on components; an unknown pod there is a "
                        "deployed container hiding among system workloads (deploy container). Also STIG CNTR-K8-001360.",
                        ("CNTR-K8-001360", "V-242417", "CCI-001082")),
    "masquerade": _rule("masquerade", "Pod named like a system daemon in a user namespace", "medium", "T1036.005",
                        "System component names outside kube-system are used to blend in "
                        "(masquerading: match legitimate name or location)."),
    "dashboard": _rule("dashboard-exposed", "Kubernetes dashboard exposed outside the cluster", "high", "T1133",
                       "A dashboard on a NodePort or LoadBalancer is an external remote service into the cluster.",
                       ("CNTR-K8-000420", "V-242395")),
    "listener": _rule("host-listener", "Host-network pod listening on node ports", "medium", "T1571",
                      "A pod on the host network that declares ports listens directly on the node, outside network "
                      "policy (non-standard port)."),
}


def _cmdline(c: dict) -> str:
    return " ".join(str(x) for x in (c.get("command") or []) + (c.get("args") or []))


def known_system_pod(md: dict, known: tuple[str, ...]) -> bool:
    """A kube-system pod whose name matches a known component AND that a controller or the kubelet created."""
    name = md.get("name", "")
    if not any(name.startswith(k) for k in known):
        return False
    owned = any(o.get("kind") in CONTROLLER_KINDS for o in md.get("ownerReferences", []) or [])
    ann = md.get("annotations") or {}
    static = "kubernetes.io/config.mirror" in ann or ann.get("kubernetes.io/config.source") in STATIC_POD_SOURCES
    return owned or static


def _known_system_workload(w, known: tuple[str, ...]) -> bool:
    if w.namespace not in SYSTEM_NAMESPACES:
        return False
    if w.ref.kind == "pod":
        return known_system_pod(w.meta, known)
    return w.ref.kind == "deployment" and any(w.ref.name.startswith(k) for k in known)


def hunt_escape(target, data: KubeData, known: tuple[str, ...] = KNOWN_KUBE_SYSTEM) -> list[Finding]:
    out = []
    for w in workloads(data):
        if _known_system_workload(w, known):
            continue
        paths = [(v.get("hostPath") or {}).get("path") for v in w.pod_spec.get("volumes", []) or []]
        sensitive = [p for p in paths if p and p.rstrip("/") in {s.rstrip("/") for s in SENSITIVE_HOST_PATHS}]
        privileged = [c.get("name") for c in containers_of(w.pod_spec) if (c.get("securityContext") or {}).get("privileged")]
        if sensitive and privileged:
            out.append(finding(target, HUNT_RULES["escape"], w.ref,
                               f"{w.ref.key()}: privileged container(s) {', '.join(privileged)} with hostPath "
                               f"{', '.join(sensitive)}{'; hostPID=true' if w.pod_spec.get('hostPID') else ''}",
                               source=SOURCE, tags=["attack:T1611"]))
    return out


def hunt_registry(target, data: KubeData, allowed: list[str]) -> list[Finding]:
    if not allowed:
        return []
    out = []
    for w in workloads(data):
        bad = sorted({c.get("image", "") for c in containers_of(w.pod_spec)
                      if c.get("image") and not registry_allowed(c["image"], allowed)})
        if bad:
            out.append(finding(target, HUNT_RULES["registry"], w.ref,
                               f"{w.ref.key()}: image(s) {', '.join(bad)} not from {', '.join(allowed)}",
                               source=SOURCE, tags=["attack:T1525"]))
    return out


def hunt_cronjobs(target, data: KubeData) -> list[Finding]:
    out = []
    for cj in data.items("cronjobs"):
        md = cj["metadata"]
        spec = cj.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
        for c in containers_of(spec):
            cmd = _cmdline(c)
            if RE_DOWNLOAD.search(cmd) or (RE_SHELL_C.search(cmd) and RE_NETWORK.search(cmd)):
                out.append(finding(target, HUNT_RULES["cronjob"], ObjRef(md["namespace"], "cronjob", md["name"]),
                                   f"{md['namespace']}/cronjob/{md['name']} schedule '{cj['spec'].get('schedule')}' "
                                   f"container {c.get('name')}: {cmd[:300]}",
                                   source=SOURCE, tags=["attack:T1053.007"]))
                break
    return out


def hunt_admin_bindings(target, data: KubeData) -> list[Finding]:
    out = []
    for ref, b in bindings(data):
        if (b.get("roleRef") or {}).get("name") != "cluster-admin":
            continue
        bad = [s for s in b.get("subjects", []) or [] if is_default_sa(s) or s.get("name") in ANON_SUBJECTS]
        if bad:
            who = ", ".join(f"{s.get('kind')} {(s.get('namespace') + '/') if s.get('namespace') else ''}{s.get('name')}" for s in bad)
            out.append(finding(target, HUNT_RULES["admin_default"], ref,
                               f"{ref.kind} {ref.name}: cluster-admin -> {who}", source=SOURCE, tags=["attack:T1078.004"]))
    return out


def hunt_system_pods(target, data: KubeData, known: tuple[str, ...]) -> list[Finding]:
    out = []
    for p in data.items("pods"):
        md = p["metadata"]
        if md.get("namespace") != "kube-system":
            continue
        name = md["name"]
        if known_system_pod(md, known):
            continue
        images = ", ".join(c.get("image", "") for c in p.get("spec", {}).get("containers", []))
        out.append(finding(target, HUNT_RULES["system_pod"], ObjRef("kube-system", "pod", name),
                           f"kube-system/{name} (images: {images}) does not match a known system component",
                           source=SOURCE, tags=["attack:T1610"]))
    return out


def hunt_masquerade(target, data: KubeData) -> list[Finding]:
    out = []
    for w in workloads(data):
        if w.namespace in SYSTEM_NAMESPACES:
            continue
        if any(w.ref.name.startswith(n) for n in SYSTEM_DAEMON_NAMES):
            out.append(finding(target, HUNT_RULES["masquerade"], w.ref,
                               f"{w.ref.key()} uses a system component name outside kube-system",
                               source=SOURCE, tags=["attack:T1036.005"]))
    return out


def hunt_dashboard(target, data: KubeData) -> list[Finding]:
    out = []
    for s in data.items("services"):
        md, spec = s["metadata"], s.get("spec", {})
        looks = "dashboard" in md["name"] or "kubernetes-dashboard" in (spec.get("selector") or {}).values()
        if looks and spec.get("type") in ("NodePort", "LoadBalancer"):
            ports = ", ".join(str(p.get("nodePort") or p.get("port")) for p in spec.get("ports", []))
            out.append(finding(target, HUNT_RULES["dashboard"], ObjRef(md["namespace"], "service", md["name"]),
                               f"{md['namespace']}/service/{md['name']} type {spec.get('type')} ports {ports}",
                               source=SOURCE, tags=["attack:T1133"]))
    return out


def hunt_host_listeners(target, data: KubeData) -> list[Finding]:
    out = []
    for w in workloads(data):
        if w.namespace in SYSTEM_NAMESPACES or not w.pod_spec.get("hostNetwork"):
            continue
        ports = [str(p.get("containerPort")) for c in containers_of(w.pod_spec) for p in c.get("ports", []) or []]
        if ports:
            out.append(finding(target, HUNT_RULES["listener"], w.ref,
                               f"{w.ref.key()}: hostNetwork=true, listening on {', '.join(ports)}",
                               source=SOURCE, tags=["attack:T1571"]))
    return out


def run_hunt(target, collected: Collected) -> list[Finding]:
    data = KubeData(collected)
    opts = target.options or {}
    allowed = list(opts.get("allowed_registries") or [])
    known = KNOWN_KUBE_SYSTEM + tuple(opts.get("known_kube_system") or ())
    out: list[Finding] = []
    for fn, args in ((hunt_escape, (known,)), (hunt_registry, (allowed,)), (hunt_cronjobs, ()), (hunt_admin_bindings, ()),
                     (hunt_system_pods, (known,)), (hunt_masquerade, ()), (hunt_dashboard, ()), (hunt_host_listeners, ())):
        try:
            out.extend(fn(target, data, *args))
        except Exception as e:  # noqa: BLE001
            collected.errors.append(f"hunt {fn.__name__}: {e}")
    for f in out:
        f.collected_at = collected.collected_at
    return dedupe(out)
