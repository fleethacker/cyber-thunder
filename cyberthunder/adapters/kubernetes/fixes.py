"""Vetted Kubernetes remediations.

Manifest fixes are kubectl command templates. The adapter fills <namespace>, <kind>, <name> and <container>
from the finding's validated object reference (see kubectl.render); nothing else is substituted and nothing
from a finding description is ever used. Before applying, the adapter saves the object it will touch
(`kubectl get ... -o json`); rollback re-applies that saved object with server-owned fields removed
(kubectl replace when the object still exists, kubectl apply when the fix deleted it), or deletes the
object when the fix created it.

Control-plane flags (API server, kubelet, controller manager) live in files on the node, not in the API,
so those fixes are runbooks: exact steps for the operator, no payload.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from cyberthunder.remediation.library import FixEntry

from .checks import CIS_RULES, LOCAL_RULES, stig
from .hunt import HUNT_RULES
from .kubectl import ObjRef

ASSET = "kubernetes"
GET_OBJECT = "kubectl get <kind> <name> -n <namespace> -o json"
DEFAULT_DENY = "ct-default-deny-ingress"


@dataclass(frozen=True)
class FixMeta:
    kinds: frozenset[str]                                   # object kinds the template can be applied to
    rollback_object: Callable[[ObjRef], ObjRef] | None = None  # object captured / restored, default: the finding's object
    rollout: bool = False                                    # wait for the deployment rollout after applying


META: dict[str, FixMeta] = {}


def _strategic(container_patch: str) -> str:
    return ("kubectl patch deployment <name> -n <namespace> --type=strategic -p "
            "'{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"<container>\",\"securityContext\":"
            + container_patch + "}]}}}}'\n"
            "kubectl rollout status deployment/<name> -n <namespace> --timeout=180s")


def _manifest_fixes() -> list[FixEntry]:
    out: list[FixEntry] = []

    def add(entry: FixEntry, meta: FixMeta) -> None:
        out.append(entry)
        META[entry.fix_ref] = meta

    pod_restart = ["pods of the patched deployment (rolling restart)"]
    add(FixEntry(
        fix_ref="k8s:fix:deployment-drop-privileged", title="Run the container unprivileged (deployment template)",
        asset_type=ASSET, applies_to=["k8s:cis:5.2.2"], kind="manifest",
        payload=_strategic("{\"privileged\":false,\"allowPrivilegeEscalation\":false}"),
        disruption="medium", restarts_services=pod_restart, rollback_kind="manifest",
        before_state={"commands": {"object": GET_OBJECT}}, verify={"rule_ids": ["k8s:cis:5.2.2"]},
        citations=CIS_RULES["privileged"].refs, source="kubernetes",
        notes="Pods are replaced by a rolling update. If the application needs a device or capability, grant that one "
              "capability instead of privileged mode."),
        FixMeta(frozenset({"deployment"}), rollout=True))
    add(FixEntry(
        fix_ref="k8s:fix:deployment-no-escalation", title="Set allowPrivilegeEscalation: false (deployment template)",
        asset_type=ASSET, applies_to=["k8s:cis:5.2.6"], kind="manifest",
        payload=_strategic("{\"allowPrivilegeEscalation\":false}"),
        disruption="medium", restarts_services=pod_restart, rollback_kind="manifest",
        before_state={"commands": {"object": GET_OBJECT}}, verify={"rule_ids": ["k8s:cis:5.2.6"]},
        citations=CIS_RULES["escalation"].refs, source="kubernetes"),
        FixMeta(frozenset({"deployment"}), rollout=True))
    add(FixEntry(
        fix_ref="k8s:fix:deployment-host-namespaces", title="Stop sharing host PID/IPC/network namespaces (deployment template)",
        asset_type=ASSET, applies_to=["k8s:cis:5.2.3", "k8s:cis:5.2.4", "k8s:cis:5.2.5"], kind="manifest",
        payload=("kubectl patch deployment <name> -n <namespace> --type=strategic -p "
                 "'{\"spec\":{\"template\":{\"spec\":{\"hostPID\":false,\"hostIPC\":false,\"hostNetwork\":false}}}}'\n"
                 "kubectl rollout status deployment/<name> -n <namespace> --timeout=180s"),
        disruption="medium", restarts_services=pod_restart, rollback_kind="manifest",
        before_state={"commands": {"object": GET_OBJECT}},
        verify={"rule_ids": ["k8s:cis:5.2.3", "k8s:cis:5.2.4", "k8s:cis:5.2.5"]},
        citations=CIS_RULES["hostPID"].refs[:1] + CIS_RULES["hostIPC"].refs[:1] + CIS_RULES["hostNetwork"].refs,
        source="kubernetes",
        notes="An application that binds node ports through hostNetwork needs a Service instead; check with the system owner."),
        FixMeta(frozenset({"deployment"}), rollout=True))
    add(FixEntry(
        fix_ref="k8s:fix:sa-disable-automount", title="Stop automounting the default service account token",
        asset_type=ASSET, applies_to=["k8s:cis:5.1.5"], kind="manifest",
        payload="kubectl patch serviceaccount <name> -n <namespace> --type=merge -p '{\"automountServiceAccountToken\":false}'",
        disruption="low", rollback_kind="manifest",
        before_state={"commands": {"object": GET_OBJECT}}, verify={"rule_ids": ["k8s:cis:5.1.5"]},
        citations=CIS_RULES["automount"].refs, source="kubernetes",
        notes="Running pods keep their token until restarted. A pod that really needs the API must set "
              "automountServiceAccountToken: true in its own spec and use a dedicated service account."),
        FixMeta(frozenset({"serviceaccount"})))
    add(FixEntry(
        fix_ref="k8s:fix:namespace-default-deny", title="Add a default-deny ingress NetworkPolicy to the namespace",
        asset_type=ASSET, applies_to=["k8s:cis:5.3.2"], kind="manifest",
        payload=("kubectl apply -f - <<'CT_EOF'\n"
                 "{\"apiVersion\": \"networking.k8s.io/v1\", \"kind\": \"NetworkPolicy\", "
                 "\"metadata\": {\"name\": \"" + DEFAULT_DENY + "\", \"namespace\": \"<name>\"}, "
                 "\"spec\": {\"podSelector\": {}, \"policyTypes\": [\"Ingress\"]}}\n"
                 "CT_EOF"),
        disruption="high", rollback_kind="manifest",
        before_state={"commands": {"object": "kubectl get networkpolicy " + DEFAULT_DENY + " -n <name> -o json"}},
        verify={"rule_ids": ["k8s:cis:5.3.2"]}, citations=CIS_RULES["netpol"].refs, source="kubernetes",
        notes="Blocks all inbound pod traffic in the namespace until allow rules are added. Agree the allow list with "
              "the system owner first. Rollback deletes the policy."),
        FixMeta(frozenset({"namespace"}), rollback_object=lambda r: ObjRef(r.name, "networkpolicy", DEFAULT_DENY)))
    # hunt remediations: remove the rogue object; the saved copy lets rollback recreate it exactly
    add(FixEntry(
        fix_ref="k8s:fix:delete-binding", title="Delete the rogue role binding",
        asset_type=ASSET, applies_to=["k8s:hunt:admin-to-default", "k8s:cis:5.1.1", "k8s:ct:anonymous-binding"],
        kind="manifest", payload="kubectl delete <kind> <name> -n <namespace>",
        disruption="low", rollback_kind="manifest",
        before_state={"commands": {"object": GET_OBJECT}},
        verify={"rule_ids": ["k8s:hunt:admin-to-default", "k8s:cis:5.1.1", "k8s:ct:anonymous-binding"]},
        citations=HUNT_RULES["admin_default"].refs, source="hunt",
        notes="Removes the grant immediately. Anything that relied on it gets 403 Forbidden; rotate the service "
              "account token afterwards (delete its token secret) because it may already have been copied."),
        FixMeta(frozenset({"clusterrolebinding", "rolebinding"})))
    add(FixEntry(
        fix_ref="k8s:fix:delete-cronjob", title="Delete the malicious CronJob",
        asset_type=ASSET, applies_to=["k8s:hunt:cronjob-download"], kind="manifest",
        payload="kubectl delete cronjob <name> -n <namespace>",
        disruption="low", rollback_kind="manifest",
        before_state={"commands": {"object": GET_OBJECT}}, verify={"rule_ids": ["k8s:hunt:cronjob-download"]},
        citations=HUNT_RULES["cronjob"].refs, source="hunt",
        notes="Jobs already spawned by the CronJob are removed with it. Preserve the saved object as evidence."),
        FixMeta(frozenset({"cronjob"})))
    add(FixEntry(
        fix_ref="k8s:fix:delete-pod", title="Delete the rogue stand-alone pod",
        asset_type=ASSET, applies_to=["k8s:hunt:host-escape", "k8s:hunt:unexpected-system-pod", "k8s:hunt:masquerade"],
        kind="manifest", payload="kubectl delete pod <name> -n <namespace>",
        disruption="low", rollback_kind="manifest",
        before_state={"commands": {"object": GET_OBJECT}},
        verify={"rule_ids": ["k8s:hunt:host-escape", "k8s:hunt:unexpected-system-pod", "k8s:hunt:masquerade"]},
        citations=HUNT_RULES["escape"].refs + HUNT_RULES["system_pod"].refs[:1] + HUNT_RULES["masquerade"].refs,
        source="hunt",
        notes="Only for pods with no controller. If a Deployment or DaemonSet owns the pod, remove that owner instead "
              "(the pod would be recreated). The node the pod ran on should be treated as compromised."),
        FixMeta(frozenset({"pod"})))
    add(FixEntry(
        fix_ref="k8s:fix:delete-dashboard-service", title="Remove the external service exposing the dashboard",
        asset_type=ASSET, applies_to=["k8s:hunt:dashboard-exposed"], kind="manifest",
        payload="kubectl delete service <name> -n <namespace>",
        disruption="low", rollback_kind="manifest",
        before_state={"commands": {"object": GET_OBJECT}}, verify={"rule_ids": ["k8s:hunt:dashboard-exposed"]},
        citations=HUNT_RULES["dashboard"].refs, source="hunt"),
        FixMeta(frozenset({"service"})))
    return out


APISERVER_FILE = ("/etc/kubernetes/manifests/kube-apiserver.yaml (kubeadm), or the kube-apiserver-arg list in "
                  "/etc/rancher/k3s/config.yaml (k3s)")
KUBELET_FILE = ("the kubelet config file named by --config (usually /var/lib/kubelet/config.yaml), or the kubelet-arg "
                "list in /etc/rancher/k3s/config.yaml (k3s)")
CM_FILE = ("/etc/kubernetes/manifests/kube-controller-manager.yaml (kubeadm), or kube-controller-manager-arg in "
           "/etc/rancher/k3s/config.yaml (k3s)")


def _runbook(fix_ref: str, title: str, applies: list[str], steps: list[str], citations: list[str], *,
             restarts: list[str] | None = None, disruption: str = "medium", file_hint: str | None = None) -> FixEntry:
    rb = ([f"Before editing, copy {file_hint} to a dated backup in the same directory."] if file_hint else []) + steps
    rollback = ([f"Restore the backup copy of {file_hint}, restart the component, and re-run the scan."]
                if file_hint else ["Reverse the manifest change from version control or the saved copy, then re-run the scan."])
    return FixEntry(fix_ref=fix_ref, title=title, asset_type=ASSET, applies_to=applies, kind="runbook", steps=rb,
                    disruption=disruption, restarts_services=restarts or [], rollback_kind="manual",
                    rollback_steps=rollback, verify={"rule_ids": applies}, citations=citations, source="kubernetes")


def _runbooks() -> list[FixEntry]:
    rbs: list[FixEntry] = []
    api = [("CNTR-K8-000360", "Set --anonymous-auth=false on the API server", "set --anonymous-auth=false"),
           ("CNTR-K8-000320", "Set --insecure-port=0 on the API server", "set --insecure-port=0 (or remove the flag on 1.24+)"),
           ("CNTR-K8-000340", "Remove --insecure-bind-address from the API server", "delete the --insecure-bind-address flag"),
           ("CNTR-K8-000270", "Set --authorization-mode=Node,RBAC on the API server", "set --authorization-mode=Node,RBAC"),
           ("CNTR-K8-000610", "Set --audit-log-path on the API server",
            "add --audit-log-path=/var/log/kubernetes/audit/audit.log plus --audit-log-maxage=30 --audit-log-maxbackup=10; "
            "on kubeadm also add a hostPath volume and mount for /var/log/kubernetes/audit"),
           ("CNTR-K8-003280", "Set --audit-policy-file on the API server",
            "write an audit policy (at least level Metadata for all requests) to /etc/kubernetes/audit-policy.yaml and add "
            "--audit-policy-file=/etc/kubernetes/audit-policy.yaml")]
    for sid, title, change in api:
        r = stig(sid)
        rbs.append(_runbook(f"k8s:runbook:{sid.lower()}", title, [sid],
                            [f"On each control-plane node, edit {APISERVER_FILE} and {change}.",
                             "kubeadm: the kubelet restarts the static pod when the file is saved. k3s: run "
                             "'systemctl restart k3s'.",
                             "Wait until 'kubectl get --raw /readyz' returns ok, then re-run the Cyber Thunder scan."],
                            r.refs, restarts=["kube-apiserver"], file_hint=APISERVER_FILE))
    kubelet = [("CNTR-K8-000370", "Disable kubelet anonymous authentication",
                "set authentication.anonymous.enabled: false and remove any --anonymous-auth flag"),
               ("CNTR-K8-000330", "Disable the kubelet read-only port", "set readOnlyPort: 0 and remove any --read-only-port flag"),
               ("CNTR-K8-000380", "Set kubelet authorization to Webhook", "set authorization.mode: Webhook"),
               ("CNTR-K8-000440", "Disable kubelet static pod path on worker nodes", "remove staticPodPath and --pod-manifest-path"),
               ("CNTR-K8-001620", "Enable kubelet protectKernelDefaults", "set protectKernelDefaults: true")]
    for sid, title, change in kubelet:
        rbs.append(_runbook(f"k8s:runbook:{sid.lower()}", title, [sid],
                            [f"On each node, edit {KUBELET_FILE} and {change}.",
                             "Restart the kubelet: 'systemctl restart kubelet' (kubeadm) or 'systemctl restart k3s' / "
                             "'k3s-agent' (k3s). Running pods keep running.",
                             "Confirm the node is Ready ('kubectl get nodes'), then re-run the scan."],
                            stig(sid).refs, restarts=["kubelet"], file_hint=KUBELET_FILE))
    for sid, title, change in (("CNTR-K8-000220", "Controller manager: use per-controller service account credentials",
                                "set --use-service-account-credentials=true"),
                               ("CNTR-K8-000910", "Controller manager: disable profiling", "set --profiling=false")):
        rbs.append(_runbook(f"k8s:runbook:{sid.lower()}", title, [sid],
                            [f"On each control-plane node, edit {CM_FILE} and {change}.",
                             "kubeadm: the static pod restarts on save. k3s: 'systemctl restart k3s'.",
                             "Re-run the scan."], stig(sid).refs, restarts=["kube-controller-manager"], file_hint=CM_FILE))
    workload = [
        ("k8s:runbook:secret-env", "Mount the secret as a file instead of an environment variable", ["CNTR-K8-001160"],
         ["Replace the env entry that uses valueFrom.secretKeyRef with a secret volume mounted read-only "
          "(volumes: - name: <secret> secret: secretName: <secret>; volumeMounts: mountPath: /run/secrets/<secret>, readOnly: true).",
          "Change the application to read the value from the mounted file.",
          "Apply the updated manifest through the normal change process and re-run the scan."], stig("CNTR-K8-001160").refs),
        ("k8s:runbook:move-from-default-namespace", "Move the workload to a dedicated namespace", ["CNTR-K8-000290"],
         ["Create a namespace for the application, with its own service account and NetworkPolicy.",
          "Re-create the workload there, move its Service and config, then delete the copy in the default namespace."],
         stig("CNTR-K8-000290").refs),
        ("k8s:runbook:host-port", "Stop mapping a privileged host port", ["CNTR-K8-000960"],
         ["Remove hostPort from the container ports and expose the application through a Service "
          "(ClusterIP, or NodePort above 30000 if it must be reached from outside)."], stig("CNTR-K8-000960").refs),
        ("k8s:runbook:run-as-non-root", "Run the container as a non-root user", ["k8s:cis:5.2.7"],
         ["Set securityContext.runAsNonRoot: true and runAsUser to the image's unprivileged UID (for example 10001).",
          "If the image only works as root, rebuild it with a USER instruction; test before rollout."],
         CIS_RULES["root"].refs),
        ("k8s:runbook:remove-hostpath", "Replace the hostPath volume", ["k8s:cis:5.2.12"],
         ["Replace the hostPath volume with a PersistentVolumeClaim, ConfigMap or emptyDir as the application needs.",
          "If node access is genuinely required (log or metrics agent), mount the narrowest path read-only and run it "
          "as a reviewed DaemonSet in a dedicated namespace."], CIS_RULES["hostPath"].refs),
        ("k8s:runbook:resource-limits", "Set CPU and memory limits", ["k8s:ct:resource-limits"],
         ["Add resources.requests and resources.limits for cpu and memory sized from observed usage "
          "('kubectl top pod' if metrics-server is installed)."], LOCAL_RULES["limits"].refs),
        ("k8s:runbook:pin-image", "Pin the image to a version or digest", ["k8s:ct:image-latest"],
         ["Replace the :latest or missing tag with the exact version (or @sha256 digest) mirrored into the enclave registry."],
         LOCAL_RULES["latest"].refs),
        ("k8s:runbook:untrusted-registry", "Replace the image with one from an approved registry", ["k8s:hunt:untrusted-registry"],
         ["Identify who deployed the workload (audit log, owner annotations) before touching it; preserve the manifest.",
          "If it is not authorized, delete the owning object. If it is, mirror the image into the approved registry "
          "after review and update the reference."], HUNT_RULES["registry"].refs),
        ("k8s:runbook:host-listener", "Take the pod off the host network", ["k8s:hunt:host-listener"],
         ["Confirm with the system owner why the pod needs hostNetwork. If it does not, remove hostNetwork and expose "
          "it through a Service; if it is not authorized, delete the owning object."], HUNT_RULES["listener"].refs),
        ("k8s:runbook:remove-dashboard", "Remove the Kubernetes dashboard", ["CNTR-K8-000420"],
         ["Delete the dashboard deployment, service and service account "
          "('kubectl delete ns kubernetes-dashboard' if it was installed in its own namespace)."], stig("CNTR-K8-000420").refs),
    ]
    for ref, title, applies, steps, cites in workload:
        rbs.append(_runbook(ref, title, applies, steps, cites, restarts=["pods of the workload"]))
    return rbs


def kubernetes_fixes() -> list[FixEntry]:
    return _manifest_fixes() + _runbooks()
