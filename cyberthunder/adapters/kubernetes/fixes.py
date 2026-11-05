"""Vetted Kubernetes remediations.

Manifest fixes are kubectl command templates. The adapter fills <namespace>, <kind>, <name> and <container>
from the finding's validated object reference (see kubectl.render); nothing else is substituted and nothing
from a finding description is ever used. Before applying, the adapter saves the object it will touch
(`kubectl get ... -o json`); rollback re-applies that saved object with server-owned fields removed
(kubectl replace when the object still exists, kubectl apply when the fix deleted it), or deletes the
object when the fix created it. This restores configuration, not runtime state, data, UIDs or service health.

Control-plane flags (API server, kubelet, controller manager) live in files on the node, not in the API,
so those fixes are runbooks: exact steps for the operator, no payload.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from cyberthunder.remediation.library import FixEntry

from .checks import CIS_RULES, LOCAL_RULES, stig
from .hunt import HUNT_RULES
from .kubectl import ObjRef, ref_from_finding

ASSET = "kubernetes"
GET_OBJECT = "kubectl get <kind> <name> -n <namespace> -o json"
DEFAULT_DENY = "ct-default-deny-ingress"


@dataclass(frozen=True)
class FixMeta:
    kinds: frozenset[str]                                   # object kinds the template can be applied to
    rollback_object: Callable[[ObjRef], ObjRef] | None = None  # object captured / restored, default: the finding's object
    rollout: bool = False                                    # wait for the deployment rollout after applying


META: dict[str, FixMeta] = {}

# Keep stable references for historical proposals and saved-manifest rollback. Neither the library nor
# an old proposal snapshot may use these entries to execute another destructive change.
RETIRED_FIXES = {
    "k8s:fix:delete-binding": "k8s:runbook:review-rbac-grant",
    "k8s:fix:delete-cronjob": "k8s:runbook:investigate-cronjob",
    "k8s:fix:delete-pod": "k8s:runbook:investigate-workload",
    "k8s:fix:delete-dashboard-service": "k8s:runbook:review-dashboard-exposure",
    "k8s:runbook:remove-rogue-workload": "k8s:runbook:investigate-workload",
    "k8s:runbook:remove-dashboard": "k8s:runbook:review-dashboard-exposure",
}
REVIEW_FIXES = frozenset(RETIRED_FIXES.values()) | {
    "k8s:runbook:untrusted-registry", "k8s:runbook:host-listener",
}
RECOVERY_LIMITS = (
    "Saved manifests can restore configuration only. They cannot restore the original UID, running processes, "
    "ephemeral volumes, completed or interrupted work, lost data, or guarantee application availability. "
    "Review current owners and dependencies before recovery; validate data and service health separately."
)


def retired_reason(fix: FixEntry) -> str | None:
    replacement = RETIRED_FIXES.get(fix.fix_ref)
    if replacement:
        return f"Retired destructive fix {fix.fix_ref}: execution disabled; use {replacement} for owner review."
    return None


def _strategic(container_patch: str) -> str:
    return ("kubectl patch deployment <name> -n <namespace> --type=strategic -p "
            "'{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"<container>\",\"securityContext\":"
            + container_patch + "}]}}}}'\n"
            "kubectl rollout status deployment/<name> -n <namespace> --timeout=180s")


def _manifest_fixes() -> list[FixEntry]:
    out: list[FixEntry] = []

    def add(entry: FixEntry, meta: FixMeta) -> None:
        entry.rollback_steps = ["Restore the captured configuration, or remove only a policy created by this fix.",
                                RECOVERY_LIMITS]
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
              "the system owner first. Rollback restores a pre-existing policy, or removes only the newly created policy."),
        FixMeta(frozenset({"namespace"}), rollback_object=lambda r: ObjRef(r.name, "networkpolicy", DEFAULT_DENY)))
    # Historical entries have no executable payload or rule mapping. META remains for saved rollback.
    add(FixEntry(
        fix_ref="k8s:fix:delete-binding", title="Retired: delete an entire role binding",
        asset_type=ASSET, applies_to=[], kind="manifest", payload="",
        disruption="high", reversible=False, rollback_kind="manifest",
        before_state={"commands": {"object": GET_OBJECT}},
        verify={"rule_ids": ["k8s:hunt:admin-to-default", "k8s:cis:5.1.1", "k8s:ct:anonymous-binding"]},
        citations=HUNT_RULES["admin_default"].refs, source="hunt",
        notes="Execution disabled. Removing the entire binding revokes access for every subject, including legitimate "
              "operators and services. Use targeted owner-reviewed RBAC correction. " + RECOVERY_LIMITS),
        FixMeta(frozenset({"clusterrolebinding", "rolebinding"})))
    add(FixEntry(
        fix_ref="k8s:fix:delete-cronjob", title="Retired: delete a CronJob",
        asset_type=ASSET, applies_to=[], kind="manifest", payload="",
        disruption="high", reversible=False, rollback_kind="manifest",
        before_state={"commands": {"object": GET_OBJECT}}, verify={"rule_ids": ["k8s:hunt:cronjob-download"]},
        citations=HUNT_RULES["cronjob"].refs, source="hunt",
        notes="Execution disabled. Deletion stops scheduling and may garbage-collect owned Jobs and Pods depending "
              "on propagation and ownership; their state is not captured by the CronJob manifest. " + RECOVERY_LIMITS),
        FixMeta(frozenset({"cronjob"})))
    add(FixEntry(
        fix_ref="k8s:fix:delete-pod", title="Retired: delete a pod",
        asset_type=ASSET, applies_to=[], kind="manifest", payload="",
        disruption="high", reversible=False, rollback_kind="manifest",
        before_state={"commands": {"object": GET_OBJECT}},
        verify={"rule_ids": ["k8s:hunt:host-escape", "k8s:hunt:unexpected-system-pod", "k8s:hunt:masquerade"]},
        citations=HUNT_RULES["escape"].refs + HUNT_RULES["system_pod"].refs[:1] + HUNT_RULES["masquerade"].refs,
        source="hunt",
        notes="Execution disabled. Deletion interrupts work and loses pod-local state; a controller may replace the "
              "pod without correcting its template. A hunt indicator does not establish compromise. " + RECOVERY_LIMITS),
        FixMeta(frozenset({"pod"})))
    add(FixEntry(
        fix_ref="k8s:fix:delete-dashboard-service", title="Retired: delete a dashboard service",
        asset_type=ASSET, applies_to=[], kind="manifest", payload="",
        disruption="high", reversible=False, rollback_kind="manifest",
        before_state={"commands": {"object": GET_OBJECT}}, verify={"rule_ids": ["k8s:hunt:dashboard-exposed"]},
        citations=HUNT_RULES["dashboard"].refs, source="hunt",
        notes="Execution disabled. Deletion interrupts all clients; restored configuration may not recover allocated "
              "addresses, node ports or load-balancer state. Review exposure without removing the service. " + RECOVERY_LIMITS),
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
         ["Prepare with the application owner: inventory Services, DNS, RBAC, secrets/config, ingress, policies and "
          "storage dependencies; define an approved maintenance window, success checks and rollback triggers.",
          "Back up configuration and application data and test restoration. Namespace-scoped PVCs cannot simply "
          "move with a manifest; plan storage access and data consistency, including prevention of duplicate writers or Jobs.",
          "Prepare the destination namespace and least-privilege identities and policies. Test the replacement with "
          "production-like dependencies before directing traffic to it.",
          "Confirm readiness, application health and data integrity, then perform an owner-approved traffic cutover. "
          "Keep the source configuration and recoverable data through an agreed observation period.",
          "On failure, use the tested rollback plan; switching traffic back alone cannot undo data written after cutover. "
          "Consider cleanup only as a separate approved change after dependency and backup review. This runbook does "
          "not authorize namespace, PVC, PV or application-data deletion."],
         stig("CNTR-K8-000290").refs),
        ("k8s:runbook:host-port", "Stop mapping a privileged host port", ["CNTR-K8-000960"],
         ["Remove hostPort from the container ports and expose the application through a Service "
          "(ClusterIP, or NodePort above 30000 if it must be reached from outside)."], stig("CNTR-K8-000960").refs),
        ("k8s:runbook:run-as-non-root", "Run the container as a non-root user", ["k8s:cis:5.2.7"],
         ["Set securityContext.runAsNonRoot: true and runAsUser to the image's unprivileged UID (for example 10001).",
          "If the image only works as root, rebuild it with a USER instruction; test before rollout."],
         CIS_RULES["root"].refs),
        ("k8s:runbook:remove-hostpath", "Replace the hostPath volume", ["k8s:cis:5.2.12"],
         ["Inventory and back up the data before changing storage. Test restoration and a suitable persistent storage "
          "replacement; ConfigMap is for configuration and emptyDir is only for disposable data. Preserve existing data.",
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
          "Validate image provenance and business purpose with the owner. An unlisted registry does not prove malice. "
          "Review an approved image or mirror, test dependencies and readiness, then roll out with a recovery plan. "
          "Escalate evidence of compromise through separately approved incident response."], HUNT_RULES["registry"].refs),
        ("k8s:runbook:host-listener", "Take the pod off the host network", ["k8s:hunt:host-listener"],
         ["Confirm with the system owner why the pod needs hostNetwork. If it does not, remove hostNetwork and expose "
          "it through an appropriate Service after testing connectivity and readiness. Preserve the current manifest "
          "and a tested recovery path; investigate unauthorized use separately."], HUNT_RULES["listener"].refs),
        # the same changes for objects the deployment patches cannot touch (bare pods, CronJobs)
        ("k8s:runbook:drop-privileged", "Run the container unprivileged (pod or CronJob manifest)", ["k8s:cis:5.2.2"],
         ["Edit the manifest of the pod or CronJob and set securityContext.privileged: false and "
          "allowPrivilegeEscalation: false on the container.",
          _REPLACEMENT_STEPS], CIS_RULES["privileged"].refs),
        ("k8s:runbook:no-escalation", "Set allowPrivilegeEscalation: false (pod or CronJob manifest)", ["k8s:cis:5.2.6"],
         ["Edit the manifest of the pod or CronJob and set securityContext.allowPrivilegeEscalation: false on the container.",
          _REPLACEMENT_STEPS],
         CIS_RULES["escalation"].refs),
        ("k8s:runbook:host-namespaces", "Stop sharing host PID/IPC/network namespaces (pod or CronJob manifest)",
         ["k8s:cis:5.2.3", "k8s:cis:5.2.4", "k8s:cis:5.2.5"],
         ["Edit the manifest of the pod or CronJob and remove hostPID, hostIPC and hostNetwork (or set them false).",
          _REPLACEMENT_STEPS],
         CIS_RULES["hostPID"].refs),
    ]
    for ref, title, applies, steps, cites in workload:
        rbs.append(_runbook(ref, title, applies, steps, cites, restarts=["pods of the workload"]))
    return rbs + _review_runbooks()


_REPLACEMENT_STEPS = (
    "For immutable pod fields, plan an owner-approved replacement: back up configuration and data, check dependencies, "
    "test readiness and application health, and arrange cutover and rollback before retiring the old pod. A standalone "
    "pod may require downtime; a new pod cannot recover the old runtime or ephemeral state. CronJob template changes "
    "affect future Jobs only; inspect existing Jobs and Pods separately. Re-scan after the approved change."
)


def _review_runbooks() -> list[FixEntry]:
    entries = [
        _runbook("k8s:runbook:review-rbac-grant", "Review and narrow the RBAC grant with its owner",
                 ["k8s:hunt:admin-to-default", "k8s:cis:5.1.1", "k8s:ct:anonymous-binding"],
                 ["Preserve the binding and referenced role; identify every subject, namespace scope, application "
                  "dependency and break-glass access path with the owner. A grant is not evidence of account compromise.",
                  "Plan a targeted correction to the unwanted subject or excessive permissions. Preserve legitimate "
                  "subjects; use a dedicated least-privilege role/binding where needed. Do not remove the entire binding "
                  "or alter a shared role without assessing every consumer.",
                  "Obtain approval for the specific RBAC diff and recovery plan, test allowed and denied operations "
                  "and service access, then re-scan. Investigate credential compromise separately."],
                 HUNT_RULES["admin_default"].refs, disruption="high"),
        _runbook("k8s:runbook:investigate-cronjob", "Investigate the CronJob with its owner",
                 ["k8s:hunt:cronjob-download"],
                 ["Preserve the CronJob template and available Job/Pod evidence. Validate ownership, image provenance, "
                  "command purpose, schedule, dependencies and existing Jobs; a network-fetch command can be legitimate.",
                  "If urgent containment is explicitly approved, consider spec.suspend: true to stop future scheduling. "
                  "Suspension does not stop existing Jobs or Pods, correct the template, or prove remediation. Assess "
                  "missed business work and existing activity separately; no containment runs automatically.",
                  "Test an owner-approved template correction and data/recovery plan. Review missed schedules and "
                  "deadlines before resuming because missed work may start. Validate Job outcomes and service health "
                  "before closing the investigation; re-scan configuration separately."],
                 HUNT_RULES["cronjob"].refs, disruption="high"),
        _runbook("k8s:runbook:investigate-workload", "Investigate workload ownership and privileges",
                 ["k8s:hunt:host-escape", "k8s:hunt:unexpected-system-pod", "k8s:hunt:masquerade"],
                 ["Preserve workload/controller configuration and available evidence. Validate the deployment owner, "
                  "image provenance and business purpose; names and privilege combinations do not establish malice.",
                  "Review host access with the owner and plan the narrowest necessary privilege correction in the "
                  "owning template. Back up data, test dependencies and readiness, then use an approved rollout and "
                  "recovery plan. For standalone pods, explicitly plan replacement downtime and state recovery limits.",
                  "Investigate credible compromise through separately approved incident response. Do not infer node "
                  "compromise or authorize workload/controller deletion from this heuristic. Validate application "
                  "health and investigation evidence separately from a fresh configuration scan."],
                 HUNT_RULES["escape"].refs + HUNT_RULES["system_pod"].refs + HUNT_RULES["masquerade"].refs),
        _runbook("k8s:runbook:review-dashboard-exposure", "Review dashboard access and preserve required service",
                 ["k8s:hunt:dashboard-exposed", "CNTR-K8-000420"],
                 ["Confirm the actual application and owner; a dashboard-like name or label is only an indicator. "
                  "Inventory clients, authentication, Service selectors/ports, ingress and external access dependencies.",
                  "With owner approval, prepare and test authenticated private access. Where appropriate, review a "
                  "Service patch to ClusterIP and removal of unneeded externalIPs, nodePort or load-balancer exposure; "
                  "preserve required selectors and ports, validate routing, and plan cutover and recovery first.",
                  "A private Service does not satisfy a benchmark requiring dashboard absence. If that requirement "
                  "applies, use a separately approved retirement plan or documented review/exception, after replacement "
                  "access and dependencies are validated. This runbook authorizes no namespace or data deletion.",
                  "Re-scan configuration and verify authorized access, application health and exposure separately; "
                  "disappearance of an object or finding alone is not proof of safe remediation."],
                 HUNT_RULES["dashboard"].refs + stig("CNTR-K8-000420").refs, disruption="high"),
    ]
    for entry in entries:
        entry.notes = "Owner review required; no automatic mutation or verified resolution."
        entry.rollback_steps = ["No tool mutation. Plan recovery for any separately approved manual change.", RECOVERY_LIMITS]
    for ref, replacement in RETIRED_FIXES.items():
        if not ref.startswith("k8s:runbook:"):
            continue
        active = next(e for e in entries if e.fix_ref == replacement)
        retired = _runbook(ref, "Retired: destructive removal runbook", [],
                           [f"Do not execute saved removal instructions. Use {replacement} for owner review."],
                           active.citations, disruption="high")
        retired.verify = dict(active.verify)
        retired.reversible = False
        retired.notes = "Execution disabled. Controller or namespace removal can interrupt services and lose data. " + RECOVERY_LIMITS
        retired.rollback_steps = ["Review historical manual changes with the owner and recover from tested backups.", RECOVERY_LIMITS]
        entries.append(retired)
    return entries


def kubernetes_fixes() -> list[FixEntry]:
    return _manifest_fixes() + _runbooks()


# When a manifest fix's template cannot be applied to the finding's object kind (a deployment patch for a bare
# pod), the finding points at this runbook instead, so the approver is never
# offered a change that is bound to fail at execute.
KIND_FALLBACK = {
    "k8s:fix:deployment-drop-privileged": "k8s:runbook:drop-privileged",
    "k8s:fix:deployment-no-escalation": "k8s:runbook:no-escalation",
    "k8s:fix:deployment-host-namespaces": "k8s:runbook:host-namespaces",
}


def point_at_applicable_fix(findings: list) -> list:
    """Set fix_ref to the runbook fallback on findings whose first manifest fix does not fit the object kind."""
    manifests = [e for e in kubernetes_fixes() if e.fix_ref in META]
    for f in findings:
        if f.fix_ref in RETIRED_FIXES:
            f.fix_ref = RETIRED_FIXES[f.fix_ref]
        if f.fix_ref or not f.rule_version:
            continue
        entry = next((e for e in manifests if f.rule_version in e.applies_to), None)
        if entry is None:
            continue
        try:
            ref = ref_from_finding(f)
        except ValueError:
            continue
        if ref.kind not in META[entry.fix_ref].kinds:
            f.fix_ref = KIND_FALLBACK.get(entry.fix_ref)
    return findings
