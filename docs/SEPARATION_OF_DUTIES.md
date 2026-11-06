# Separation of duties and CAT I approvals

Verified changes require a proposer and independent human approval. CAT I
(`high`) requires two distinct human approvers; medium, low and informational
findings require one. Unknown severity conservatively requires two. The proposer
cannot count toward either requirement. Identity means the exact verified issuer
and subject, independent of display name, role changes, session ID or login method.
An application administrator has no implicit approval authority or target grant.

The server reads severity from the persisted finding and binds the requirement to
the current vetted fix, finding contents and target generation. Caller metadata,
request bodies and typed actor headers cannot choose the count or severity.
Internal proposal workers record the initiating principal even when using a
service label. Workload principals can propose when authorized, but cannot approve.

## Records and decisions

New protected proposals contain:

| Field | Meaning |
| --- | --- |
| `proposed_by` | Server-derived stable actor identifier |
| `proposed_principal` | Identity evidence captured at creation |
| `required_approvals` | Server-derived count, also bound in the requirements |
| `approval_requirements` | Version, ruleset, verified/development mode, original source facts and payload digest |
| `approvals` | Individual approval records, each with principal, timestamp, note and payload/requirements/assessment digests |

The requirements and proposal payload are anchored in the existing hash-chained
`proposal.create` audit record. Each decision re-reads persisted proposal state
under the cross-process lock, verifies the audit chain/checkpoint, compares the
creation record, and reads current server facts. Changing the source finding,
target generation, fix, approved payload or requirements requires cancellation
and a new proposal. A later lower severity never reduces an existing requirement.

For CAT I, the first approval appends `proposal.approval_recorded` and leaves the
proposal `PROPOSED`, with `decided_by` unset. A duplicate issuer/subject is refused.
The second distinct qualified approval appends `proposal.approved` and changes
the state to `APPROVED`. `decided_by` and `decided_principal` describe the final
approver for older consumers; `approvals` is the complete decision evidence.
Every actual approval retains its immutable principal and the exact payload and
assessment association in the audit log. Rejections are audited as rejections.

All counted approvals must review the same assessment association. Individual
acknowledgement notes can differ. An explicit `not_assessed` association remains
supported; it does not claim dependency evidence exists. Reviewed receipts are
validated again before subsequent approval and before apply. A new, expired or
changed assessment cannot be substituted through a single-person re-review:
cancel, create a new proposal, and collect fresh approvals for the new receipt.

`start_apply` rechecks the complete distinct-human quorum and all associations
before entering `APPLYING`. Receipt validation is followed by a fresh source and
operation-authorization check. After before-state capture, the engine re-reads
the persisted proposal and validates the quorum, audited lifecycle, current
finding/fix, receipts and apply permission immediately before mutation or runbook
issuance. A policy or direct state transition cannot substitute
for a human approval in protected mode, including the second CAT I approval.
Policy signing and step-up authentication are separate work.

## Integration contract

`RemediationEngine.__init__` installs:

```python
gate.separation_source = lambda proposal: source_for(ctx, proposal)
```

`source_for` is in `control/separation.py` and reads the persisted finding, current
inventory scope and current library entry. The callback takes a `Proposal` and
returns exactly `finding_id`, `finding_sha256`, `severity`, `fix_sha256` and
`target_scope`. It is an internal server callback, not an API capability. A gate
used outside `AppContext` needs this callback plus the existing `authorizer`,
`resource_scope` and `artifact_authorizer` hooks. Verified use without the source
or target authorizer fails closed. Keep `assessment_validator` wired for receipt
validation. Ordinary application context construction already installs these
hooks; no configuration or UI changes are required for enforcement.

The existing approval API returns the new proposal fields. HTTP 200 can represent
a recorded partial approval; clients must inspect `state` and must never infer
execution authority from a successful approval response alone. Bulk decisions
also retain `state=proposed` until the required count is met. Current request
schemas do not accept these fields as authority: extra severity/count fields are
ignored, and the gate rejects callers supplying managed proposal fields directly.

Proposals and audit remain files for both document backends. The proposal lock
serializes concurrent approvers, including separate gate instances. Audit is
written before proposal state; an I/O failure can leave an audit event whose
decision was not saved. The complete ordered receipt list and current lifecycle
must agree with the audit, including the final decision identity. An old proposal
snapshot cannot revive a cancelled, denied or already-consumed approval. An
audit/state mismatch fails closed: cancel a still-pending persisted proposal and
create a fresh one, rather than replaying an orphaned decision. No last-good or
in-memory approval bypass is permitted.

## Legacy and local development

Old records load with `approval_requirements=None`, `required_approvals=None` and
an empty approval list. Reading or cancelling a legacy record does not invent
proposer evidence or approvals. Verified approval and start-apply reject legacy
records, including previously approved development records. Cancel and propose
again from current evidence; there is no silent migration to verified authority.

Default local development keeps the existing typed-name, single-approval workflow.
Tests or an explicitly configured local harness may opt into the new rule with
`ApprovalGate(..., unverified_separation=True)` or set the same gate attribute
before proposing. This mode uses case-folded typed names and records
`mode=unverified_dev` and `verified=false`. It provides no proof of human identity.
Persisted protected records cannot bypass the rule by turning that setting off,
and development approvals cannot be upgraded into verified decisions.

## UI approval review

The decision queue and review dialog display the server's required count, distinct
recorded human approvals, remaining approvals and proposal state. A successful
approval response can leave the proposal proposed; it stays in the queue without
an Apply action. Selected reviews advance after a recorded partial vote while
leaving unfinished proposals selected. Only a returned approved state is presented
as approved. Existing proposal audit events refresh other reviewers' changes.

Public session issuer/subject metadata explains proposer and duplicate refusals;
existing capability checks still apply, and the server remains the authority.
Expandable provenance shows the original proposer, each approver, decision time,
assessment acknowledgement and binding digests. It does not render session tokens
or raw identity objects. Explicit development rules are labelled unverified;
ordinary development retains its single-approval workflow.

After the first vote, later reviewers must acknowledge the exact attached receipt
or explicitly repeat the recorded no-assessment choice with their own reason.
Protected approved proposals expose the receipt without a single-person refresh.
Expired or changed bound assessments require a new proposal and fresh approvals.
The UI consumes the existing proposal fields and public `/auth/status` metadata;
it sends no count, severity or identity override. Source tests cover partial/final
decisions, identity refusals, permission loss, receipt binding and legacy behavior.
The combined application build and multi-person enclave acceptance remain separate.

## Acceptance and limits

Focused tests cover JSON and SQLite document backends, direct gate and engine
calls, API and bulk decisions, concurrent distinct/duplicate approvers, restart,
actor spoofing, roles, target/session revocation, original requirements, payload
tampering, real stored assessment receipts and legacy behavior. They use isolated
fixtures and no target connections. Actual multi-person enclave acceptance remains
open, including the realm's mapping of distinct people to stable accounts.

The rule counts distinct verified human principals, not biometric people. It
does not correlate one person's separate accounts across issuers. Each approver
must be authorized at decision time; recorded votes do not perform later IdP
introspection or step-up. The current caller must still pass session, role and
target authorization for every new decision and apply.

The node's state directory, audit log/checkpoint, executable code and internal
callbacks remain trusted server resources. These records are not cryptographically
signed approvals or an externally anchored ledger. Audit validation currently
reads the local chain for each protected decision; large-log indexing is future
work. The optional first-change device-registrar rule is not implemented here.

## Independent review checks

The bounded review reproduced and fixed three gaps: restoring an old proposal
snapshot bypassed later audited cancellation/denial/apply; revocation during
start-apply receipt validation was not rechecked; and finding, receipt or fix
changes during before-state capture could reach the mutation boundary. Tests in
`tests/security/test_separation_review.py` cover these cases, partial-receipt
deletion, final-identity relabeling, audit-first persistence failure/recovery,
source changes during assessment, and unchanged protected runbook issuance.

Focused validation uses both JSON and SQLite with the shared interpreter and
checkout `PYTHONPATH`: the separation suites, identity-boundary/browser suites,
engine/assessment/review/guardrail suites and approval-I/O tests. The adapters are
inert fixtures; no target or external identity-provider operations are performed.
The full integration gate and real multi-person acceptance remain separate.

Windows focused results, with both document backends in each run: separation
and initial adversarial cases **132 passed (87.52s)**; browser/API and engine
regressions **291 passed (167.52s)**; final adversarial, engine and guardrail
checks **111 passed (105.72s)**. These overlapping runs had no failures or skips;
warnings were framework deprecations.

A rejected final check performs no fix and no automatic rollback. If already in
`APPLYING`, the proposal remains blocked under the existing recovery state machine;
these checks do not grant recovery authority or turn it back into an approved
proposal. Previously counted votes still attest authorization at decision time,
not later IdP introspection or retroactive account revocation.
