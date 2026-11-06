# Kubernetes namespace collection

The optional `namespaces` target setting enables **read-only collection** for
accounts that can list resources in specific namespaces. Omitting the setting
retains the existing cluster collector. A namespace in a kubeconfig context does
not implicitly enable this mode.

This closes the collector gap recorded in the local acceptance receipt
`.build/local-cluster-acceptance-20261106-040457-311f5dc4/README.md` at source
`c9566db8e58021a7bfa26426cede86d9ef72e969`: the restricted service account could
read seven types in its owned namespace, while the built-in collector's `-A`
requests failed. That earlier acceptance evaluated captured lists directly and
did not demonstrate an end-to-end collector scan.

## Target setting and authorization

For an existing Kubernetes target, have the authorized inventory administrator
review and set:

```json
{
  "namespaces": ["team-a", "team-a-jobs"]
}
```

These are target **options**, alongside the existing connection options. The
selector is an explicit list of 1–16 distinct Kubernetes DNS labels: lowercase
letters, digits and interior hyphens, 1–63 characters each. Empty lists, null,
strings, wildcards, duplicates, whitespace, dots and leading/trailing hyphens
are rejected before collection. Names are sorted for deterministic requests and
output. No namespace enumeration or inference takes place.

The selector narrows collection; it grants no access. Existing verified actor,
operation, target scope, access policy, selected account credential, protected
kubeconfig and kill-switch checks remain authoritative. Each person still uses
their policy-selected kubeconfig and explicit context. The target's credential
options cannot replace that selection. No shared credential, impersonation,
elevation, or new apply permission is introduced.

For different namespace selections on the same cluster, use separate reviewed
target records and existing per-person target grants. This feature does not add
a namespace selector to credential grants. Kubernetes RBAC can also give two
accounts unequal permissions for the same declared namespace; unreadable lists
remain unavailable for that account. Reconnect after changing inventory,
namespace selection, account authorization, context or credential files.

Collection, discovery and health entry points also reject namespace mode on
local, SSH and simulated targets, including transports constructed by the generic
factory. Direct namespace transports recheck the selected namespace, target
identity and connection options before execution and after each response. Verified
sessions retain the existing current-inventory, actor and credential-file guards.

## Requests and completeness

For each declared namespace, collection issues only:

```text
kubectl get pods -n <namespace> -o json
kubectl get deployments -n <namespace> -o json
kubectl get serviceaccounts -n <namespace> -o json
kubectl get rolebindings -n <namespace> -o json
kubectl get networkpolicies -n <namespace> -o json
kubectl get cronjobs -n <namespace> -o json
kubectl get services -n <namespace> -o json
```

The transport accepts this closed command grammar. It rejects other resources,
object reads, raw endpoints, discovery, connection overrides, extra flags,
multiline commands, stdin payloads and all mutation commands before subprocess
execution. Even a more privileged backing account cannot expand these reads.

There are no `-A`/`--all-namespaces`, namespace objects, nodes, roles,
cluster roles/bindings, node proxy/configz, node SSH or local container-runtime
fallbacks. Configuring `node_target` or `k3d_cluster` does not enable those paths
in namespace mode. Discovery records unknown node count/readiness and does not
query cluster metadata. Cluster/application health is not established.

Kubectl normally combines its list pages. A residual continuation token,
nonzero or malformed remaining count, missing/malformed envelope, wrong kind or
API version, duplicate identity/member, or object outside the **requested**
namespace makes that namespace/resource list unavailable. This also rejects an
object returned from a different declared namespace. Nothing from that response
is written into the merged artifact. The adapter never follows a response link
or retries with broader rights. It accepts at most 10,000 objects and 8 MiB of
JSON per namespace/resource response; exceeding a limit is unavailable, not
truncated success. Kubectl captures stdout before that size check, so this is
an acceptance bound, not a streaming process-memory limit.

Complete lists are merged by namespace and object name into the existing
artifact layout. Successful namespaces remain usable when another namespace
fails. The per-resource/per-namespace status records whether an empty list was
successfully collected or input was unavailable. Structural checks cover fields
consumed by native checks; this is not a complete Kubernetes OpenAPI validator.

## Findings and reports

`Collected.raw.kubernetes_scope` and asset facts record the explicit namespaces,
read-only mode, per-list status/counts, unavailable inputs and incomplete cluster
coverage. Findings carry that metadata in `collection_provenance`, namespace
coverage tags and evidence text. Saved scan JSON and checklist finding details
retain the scope statement. Existing collection errors and `not_reviewed`
findings communicate unavailable inputs to coverage/report consumers.

Native workload and binding checks use available namespace evidence. An absent
NetworkPolicy is reported only when that namespace's policy list is complete;
otherwise the control is `not_reviewed`. Binding findings describe declarations,
not effective rights: referenced Role/ClusterRole contents are unavailable.
Malformed binding subjects make the binding list unavailable. Namespace workload
checks evaluate observed Pods even when a ReplicaSet or Job owns them: a readable
Pod must not disappear from detection just because its owner's template cannot
be read. Templates and their Pods can each produce findings for their own observed
configuration; those findings do not represent additional control coverage.
Control-plane and kubelet rules remain `not_reviewed`, including when
`kube-system` was explicitly selected. A successfully collected empty namespace
is never presented as an empty or globally compliant cluster. Targeted rule
filters can omit the overall coverage finding, but retained findings still carry
the scope statement and persisted collection metadata remains complete.

## Remediation limit

Namespace mode does **not** implement automatic remediation. Findings resolve
first to a review-only runbook. The adapter refuses before-state capture, apply,
remediation verification and rollback before reading saved payloads or invoking
the transport, including crafted cross-namespace or cluster-resource references.
The transport independently refuses mutations and `sudo`. Namespace findings
remain read-only if their target is subsequently changed to cluster mode.

An execution engine may construct its guarded transport before calling the
adapter; constructing the kubectl transport opens no connection. No network
request or command payload is executed for a refused mutation. Separate,
explicitly authorized operator changes and a fresh scan are required. Existing
cluster-mode fixes and historical recovery behavior are unchanged. These scope
limits do not establish application health, full STIG coverage, production
clearance or cluster-wide RBAC compliance.

## Focused validation

Run serially with both state backends:

```text
python -m pytest tests/kubernetes tests/security/test_kube_credentials.py tests/security/test_kubernetes_account_integration.py tests/security/test_kubernetes_secondary_transport.py
```

`tests/kubernetes/test_namespace_scope.py` exercises selector validation,
deterministic merging, denied/partial/malformed lists, cross-namespace responses,
mutation and recovery rejection, selected credential use, unequal account rights,
scope/credential/context/policy/actor drift, kill-switch revocation, stored scan
and checklist evidence, and the default cluster command path. Local acceptance
and negative-calibration receipts belong under the ignored `.build` directory;
they are evidence for the tested source, not a deployment authorization.

Independent negative cases are in `tests/kubernetes/test_namespace_scope_review.py`.
They cover denied owner-template reads, malformed subjects, final-response drift,
alternate command spellings, unsupported transports, stop-exception propagation,
and serialized read-only findings presented with a fresh cluster transport.
Review receipts and source hashes are under `.build/namespace-review/`. This
fixture review adds no live-cluster, login or production assurance.
