# Operator risk acceptance

This VAL-05 capability records an operator's temporary acceptance of an open scanner risk.
It does not establish official enclave risk authorization, compliance, a fixed vulnerability, a clean
system, or permission to change a target. Local development decisions are unverified fixtures.
Deployment policy must explicitly grant this authority to the intended accounts and targets.

## Decision and authority

Acceptance requires a nonblank reason, nonblank supporting evidence, and a future timestamp with
seconds and timezone. Expiry must be no more than **30 days** after the decision. This is a product
bound for reassessment, not a compliance policy. There is no automatic renewal. Revoke an active
acceptance explicitly before recording another acceptance. Revocation requires its own reason.

In verified mode, both accept and revoke require all of:

- A current verified human principal with the `approver` role; workloads and typed identities fail.
- The distinct `risk.accept` operation in a protected grant for that exact issuer/subject account,
  with both explicit `target_ids` and explicit `environments` containing the current target and
  environment. Group grants, wildcard selectors, omitted selectors and node grants do not confer it.
- Matching persisted finding ownership: environment, target ID and target authorization generation.
- The existing fresh-authentication policy and accepted assurance context. Missing configuration,
  missing assurance/authentication time, stale or future authentication, expired or revoked sessions
  deny the operation. The existing challenge flow requires a fresh explicit submission after login.

An ordinary `review` grant is insufficient. Accounts associated with the same person do not inherit
one another's grants. An example additional resource grant on the intended subject entry is:

```json
{"actions": ["risk.accept"], "target_ids": ["range-01"], "environments": ["range"]}
```

Read visibility remains separately authorized. Neither a stored review, an old login receipt, a
revocation receipt nor a recorded approver role authorizes another operation. Applying a fix still
requires its normal current account/target authority, independent approvals, assessment and guards.

## Service and API

`ReviewService.accept_risk(finding, *, actor, reason, supporting_evidence, expires_at,
expected_revision, evidence_fingerprint)` records `risk_accepted`.
`ReviewService.revoke_risk(finding, *, actor, reason, expected_revision, evidence_fingerprint)`
records `risk_revoked`, with effective review disposition `unreviewed`.

- `PUT /api/v1/findings/{finding_id}/risk-acceptance` accepts reason, supporting evidence,
  expiry, expected revision and evidence fingerprint.
- `POST /api/v1/findings/{finding_id}/risk-acceptance/revoke` accepts reason, expected revision
  and evidence fingerprint.
- Existing `GET .../review` returns both kinds of decision and their immutable history.
- Existing `PUT .../review` accepts only ordinary dispositions. It cannot replace active risk
  acceptance, even when the caller separately has `risk.accept` authority.

The two risk routes reject supplied identities and extra fields. `scan_id` writes are rejected.
They reread current persisted observations; historical scan views remain read-only. Errors use the
existing mappings: 400 invalid input, 401 fresh authentication required, 403 missing authority,
404 unavailable current observation, 409 stale revision/evidence or lifecycle contention, 423 kill switch.

## Projection and lifecycle

An active acceptance sets `remediation_held=true`, `risk_acceptance_status=active` and
`disposition=risk_accepted`. It always leaves `suppressed=false`. Scanner status, severity, evidence
and raw counts remain intact. Neither acceptance nor revocation changes proposal approval state.

The hold blocks automatic and manual proposal creation, standing-policy eligibility, and applying
existing proposals, including the final check after before-state capture and before runbook issuance.
Proposal creation and final execution share the review lifecycle lock. A competing decision cannot
commit while either is guarded. A hold recorded during capture stops apply without a rollback of an
unexecuted fix. An executing remote command cannot be cancelled by saving a review; the existing kill
switch governs subsequent guarded actions. Rollback and verification retain their existing authority.

Expiry releases the hold exactly at its timestamp, with status `expired`; no GET appends history.
Relevant evidence changes durably invalidate it through the existing scan-publication ledger and
show `reopened`. A failure → pass → same failure cannot reactivate the old acceptance. Timestamp-only
rescans retain it. Detector/content changes, relevant provenance and ownership are fingerprinted.
Reassignment hides the old owner's decisions from the new owner; a new observation and decision are
needed. Returning to the old scope after publication does not undo durable invalidation.

Explicit revocation sets status `revoked` and retains the prior acceptance. Once expired or reopened,
ordinary review may proceed; the last visible risk receipt and status remain available separately.
The existing `review` filter accepts `risk_accepted`, `risk_expired`, `risk_reopened`, and `risk_revoked`.
Expired/reopened/revoked risk facets can overlap an ordinary effective disposition such as `unreviewed`.

Finding detail displays the hold, reason, expiry, identity and history, with separate accept/revoke
submissions. Role-level controls explain `risk.accept`; the server also checks the account's resource
grant. A changed UI account or permission set requires refreshed evidence and acknowledgement.
Commander reports preserve open-risk totals and display a separate accepted-risk count. POA&M retains
the open row, scanner evidence/severity, hold status and exact recorded risk decision. Checklist scanner
status remains unchanged. Acceptance never increases verified-fix or scanner-pass counts.

## Persistence and audit limits

No new persistence family or schema version is introduced. Risk events use the existing version-2
review history and invalidation ledger on JSON and SQLite, with the same ownership filtering,
monotonic revision, evidence fingerprint and cross-process locks. Nodes reading these events must
support these decision types; older readers reject them rather than treating them as suppression.

The complete acted principal, authentication time, ACR/AMR and hashed session reference are retained
as recorded evidence, with the original scope/fingerprint. These snapshots are attribution only.
`finding.risk_acceptance` is audited as pending before state mutation, then as successful afterward.
Current principal, session, role, protected grants, ownership and assurance are rechecked after pending
audit and before persistence. Initial audit failure prevents mutation. The pre-existing audit/document
crash window remains: a pending record can survive without a decision, or a persisted decision without
its final success entry. Recovery uses the event ID; reads never repair or replay a decision.

Reason/evidence limits remain 4,000/16,000 characters, and history remains bounded to 1,000 human
events. The final slot permits risk revocation as well as ordinary reversal. No receipt is pruned.

## Narrow integration surface and validation

Changes are limited to the review service/API and documentation; role, action and fresh-authentication
maps; proposal/apply/policy/preview review guards; API review facets; assurance/commander/POA&M review
projections; Finding detail/review controls and the existing apply hold display; and focused tests.
The lifecycle lock implementation, current scanner/verified-fix model and storage adapters are retained.

Focused tests exercise JSON/SQLite decision and invalidation persistence, exact grants and unequal
accounts, session/assurance rejection and rechecks, expiry, reassignment, concurrency, audit failure,
proposal/apply holds, reports and UI authority changes. Validation uses fixtures and in-process HTTP;
it establishes no live enclave or external identity-provider acceptance. Exact run receipts and source
hashes are retained under the candidate's `.build` evidence directory, separately from prior receipts.
