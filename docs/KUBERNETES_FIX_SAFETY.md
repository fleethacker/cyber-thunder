# Kubernetes fix safety

Kubernetes hunt findings describe configuration indicators, not confirmed malicious workloads. A system-like
name, a registry outside the configured list, a network-fetch command, or broad privileges requires ownership
and purpose review. Removing the matching object is not evidence that an application is healthy or an incident
is resolved.

## Current recommendations

| Finding | Recommended handling |
| --- | --- |
| Broad/default/anonymous RBAC grant | Review the binding, role and every subject. Approve a targeted subject or permission correction, preserve legitimate and break-glass access, and test service access. |
| CronJob network-fetch/shell indicator | Investigate purpose, provenance and existing activity. Optional suspension is explicit, separately approved containment; no automatic change runs. |
| Privileged host access, unfamiliar system pod, system-like name | Validate the owner and controller, preserve evidence, and plan a tested privilege correction with recovery. Escalate credible compromise through incident response. |
| Dashboard-like external Service or dashboard benchmark finding | Confirm application identity and dependencies. Review a private authenticated access path and a Service exposure patch where appropriate. If absence is required, use a separate retirement plan or documented exception. |
| Unapproved image registry or host-network port declaration | Review ownership and connectivity, then test an approved image or networking change with a recovery plan. |

These are manual review runbooks. They contain no executable payload and their proposal verification remains
unresolved pending owner investigation and separate service validation. A fresh scan can describe the new
configuration; it does not certify completion of the investigation. Existing deployment security patches,
service-account token configuration and the high-disruption NetworkPolicy change remain available.

CronJob suspension affects future scheduling, not Jobs already started. Template changes affect future Jobs;
existing Jobs and Pods need separate assessment. Review missed schedules and deadlines before resuming.
Suspension alone neither fixes the template nor establishes resolution. These limits follow the
[Kubernetes CronJob documentation](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/).

Dashboard name/label matches do not establish application identity or external reachability. Changing a Service
to private access does not satisfy a benchmark that requires dashboard absence. The bundled dashboard fix
summary is local operational guidance; the benchmark's absence requirement remains visible.

## Replacement and migration

Namespace migration proceeds through preparation, dependency and storage review, tested backups/restoration,
destination testing, readiness and application checks, and an approved traffic cutover. Preserve source
configuration and recoverable data through an observation period. Prevent duplicate writers/scheduled work;
moving a manifest does not move namespace-scoped storage or undo writes after cutover. Cleanup requires a
separate approved change. No recommendation authorizes namespace, PVC, PV or application-data deletion.

Immutable pod changes require a planned replacement and may require downtime. A replacement has a new UID;
reapplying a manifest does not recover processes or ephemeral pod storage. Application data and service
availability require separate recovery and validation, as described by the
[Kubernetes Pod lifecycle documentation](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/).

## Historical proposals and rollback

The four `k8s:fix:delete-*` references for bindings, CronJobs, pods and dashboard Services remain in the library,
with their original `META` object mappings, no payload or rule applicability, high disruption and incomplete
reversibility declared. The old `remove-rogue-workload` and `remove-dashboard` runbook references also remain
as retired entries pointing to review guidance. Newly detected findings select the review runbooks.

The existing engine rejects an approved proposal when its current library digest/preview differs. Adapter
guards additionally reject retired references before capture and at apply, even if a saved historical payload
is loaded as a fallback. Blocking before capture prevents rollback of an operation that never ran. Historical
records are preserved; an old snapshot may still display its original, inaccurate low-disruption label.
Re-scan and propose current guidance rather than executing that record.

Already applied historical changes retain saved-fix and saved-manifest rollback. This restores configuration
only; it cannot promise the original UID, runtime, data, allocated addresses, Job outcomes or application health.
Review the current environment and dependencies before rollback. A retired deletion with no previously existing
object is refused rather than allowing rollback to delete a current object. The default-deny policy rollback
still restores a captured existing policy or removes only the policy newly created by that fix.

Verification returns unknown for absent/unreadable original objects, incomplete recollection, or an unevaluated
matching finding. The infrastructure health check covers API availability, node readiness and system-pod status;
it is not an application health check. It does not validate storage integrity, downstream consumers or user traffic.

## Validation boundary

`tests/kubernetes/test_fix_safety.py` exercises JSON and SQLite proposal persistence, legacy execution refusal,
saved rollback, unchanged shared RBAC subjects, manual CronJob review, suspended-template detection, and absent
objects/partial collection. Existing Kubernetes tests cover ordinary patch/verify/rollback and fixture replay.
All operations use isolated simulated state. The simulator does not implement CronJob scheduling, Job garbage
collection, real traffic, storage durability or application health; those semantics are not claimed as tested.
No automatic containment, targeted RBAC patch generator, dashboard patch generator or migration executor is added.
