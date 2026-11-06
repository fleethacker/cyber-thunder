# Namespace-scoped image inventories

The cluster image survey and CVE baseline now honor the Kubernetes target's
existing `options.namespaces` selection. A restricted namespace account no
longer needs permission to list every namespace before the baseline can collect
its workloads. This follows the same explicit target selection described in
[namespace collection](KUBERNETES_NAMESPACE_SCOPE.md).

The selection is one to sixteen unique namespace DNS labels in the persisted
inventory. An absent selection preserves the existing cluster-wide path; a
present invalid selection refuses the operation. No request parameter or user
display name supplies a different selection. In verified mode, existing exact
account/action/target grants still select that account's protected kubeconfig.
An administrator role or a stronger backing credential cannot expand these
namespace reads. The inventory's namespace option is a target collection limit,
not a new per-user grant selector; use separately reviewed targets and grants
when accounts need different namespace selections.

## Reads and coverage

For each selected namespace, the service lists Deployments, StatefulSets,
DaemonSets, CronJobs, Jobs and Pods. The command boundary accepts only the exact
`get RESOURCE -n NAMESPACE` form for those six resources. It refuses global
namespace lists, `-A`, secrets, other namespaces, mutation verbs and extra
connection overrides. Current authorization, account credentials, scope and
the kill switch are checked before and after each external call. Changing the
namespace selection during collection stops the run before publication.

Namespace names in the survey come from configured scope. Their labels and phase
are unknown, with `metadata_collected=false`; no namespace metadata is invented.
The returned `collection_scope` and each finding's `kubernetes_scope` provenance
identify the selected namespaces and `cluster_complete=false`. A successful
scoped run describes its selected image inventory, not cluster-wide coverage.

Every list must carry a valid resource envelope, complete pagination metadata,
unique object names/UIDs, matching namespace/kind/API version and usable container
identities. Duplicate JSON fields, incomplete pages and missing or foreign
objects make that resource unavailable. Limits are 8 MiB per response and 10,000
items. The byte check occurs after subprocess capture and is not a hard streaming
memory limit. Denied or malformed resource reads remain visible as partial
coverage; the service does not retry with a broader account or a cluster-wide
command. Valid observed images can still yield findings. Unobserved image scopes
do not clear earlier findings.

Local scanner execution or workspace file denials are unavailable coverage,
with sanitized errors. They are distinct from current account authorization
failures, which stop the operation before publication. Fatal namespace baseline
errors retain the selected namespaces in their error-finding provenance.

## Image availability remains separate

This change does not import images, enable a Docker socket, choose a local archive,
or loosen verified scanner environment handling. Verified image scans retain
`--image-src remote`: an approved local registry can supply content in a
disconnected enclave, but a Docker image cached on the development laptop alone
is not accessible through this path. Database availability and workload inventory
are separate from actual image availability. Missing images remain unavailable,
never clean. [Vulnerability data](VULNERABILITY_DATA.md) and MVP-03/06 in the
[backlog](BACKLOG.md) retain those provisioning and remediation requirements.

## Validation limits

Focused JSON/SQLite fixtures exercise restricted collection, current account
selection, other-account denial, mid-run revocation/scope changes, command
boundaries, malformed/denied lists, image findings and retained old observations.
Negative calibration reproduces the original global-list failure. Fixtures
replace external tools and do not establish a live OIDC login or a disconnected
image CVE scan. The earlier real restricted-service-account attempt against
`a2a33c6` stopped at the global namespace list with Forbidden, before any image
scan. Its owned resources were removed and the existing cluster was preserved.
A real run of this corrected path remains required before closing MVP-03.
