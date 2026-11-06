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
before entering `APPLYING`. A policy or direct state transition cannot substitute
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
decision was not saved. Only persisted approvals with matching audit records
count, and no last-good or in-memory approval bypass is permitted.

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
