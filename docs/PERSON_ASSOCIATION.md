# Person association for independent approval quorums

Protected access policy version 2 explicitly opts into mapped-person approval
quorums. It correlates a person's separately authenticated accounts for proposer
exclusion and vote uniqueness. Each operation still uses the acting account's
own roles, target/environment/action grants and credential binding. A mapping
grants no permission and never combines permissions or credentials across accounts.

Version 1 remains an account quorum: issuer and subject distinguish accounts,
which may belong to one person. Its existing rule name `cat-i-two-person-v1`
does not establish independent people. Version 2 uses
`cat-i-person-association-v1`. CAT I/high and unknown severity still require two
approvers; other severities require one. The proposer cannot supply any vote.

## Provisioning

Use the existing protected `<CT_STATE_DIR>/auth/access.json`. Its path, ownership,
permissions, bounded parsing and stable-read checks remain those documented in
[ACCOUNT_ACCESS.md](ACCOUNT_ACCESS.md). Version 2 requires this exact configuration:

```json
{
  "version": 2,
  "approval_identity": {
    "mode": "person",
    "version": 1,
    "namespace": "operators",
    "revision": 1
  },
  "entries": [
    {
      "issuer": "https://id.example/realms/operators",
      "subject": "normal-subject",
      "person_id": "p-5a71d06f",
      "node_actions": [],
      "grants": [{"actions": ["read", "scan", "propose"], "target_ids": ["host-a"]}]
    },
    {
      "issuer": "https://id.example/realms/operators",
      "subject": "privileged-subject",
      "person_id": "p-5a71d06f",
      "node_actions": [],
      "grants": [{"actions": ["read", "approve"], "target_ids": ["host-b"]}]
    }
  ]
}
```

This illustrative policy keeps the normal account's host-a scan/proposal grants
separate from the privileged account's host-b approval grant. Appropriate signed
roles and fresh authentication remain required. Target connections additionally
need an explicit operation-specific credential binding; this example supplies
none. Provision independently mapped reviewers and their own grants to complete
a quorum. Even if the privileged account later receives approval permission for
host-a, it cannot approve its normal account's proposal.

Person IDs and the namespace must be opaque ASCII identifiers: 1–128 characters,
starting with a letter or digit, followed by letters, digits, underscores or
hyphens. Generate random identifiers, keep them stable and never reassign one to
another person. **Do not use names, email addresses, employee/service numbers,
government identifiers, dates of birth or other sensitive real-world IDs.** The
syntax check cannot determine whether an otherwise valid string contains sensitive
information. These identifiers appear in proposals, audit events and authorized
reports, so provisioning must enforce this requirement.

The namespace identifies the operator-managed association registry, not an IdP
group. `(namespace, person_id)` is the quorum identity. Exact issuer/subject rows
may share it across issuers only when explicitly provisioned. Accounts with equal
display names or subject strings from different issuers are never automatically
associated. Tokens, roles, email and groups cannot provide a person association.

An exact subject row may contain `person_id` with empty actions and grants when
permissions come from group entries. Groups can still grant permissions, but a
group row containing `person_id` invalidates the policy. Unmapped subject entries
can serve other operations; they cannot propose or vote in person mode. Duplicate
subject rows, conflicting associations, unknown fields, unsupported versions and
malformed values invalidate the entire file. Revision is an integer from 1 to
9007199254740991; advance it whenever the associations change.

Only verified human principals may propose or approve in person mode. An internal
worker label retains its initiating human's account. A real workload, development
identity or standing approval policy cannot supply a person-bound proposer or
vote, even if an administrator has assigned its subject a person ID.

## Changes and operational cost

Creation pins the SHA-256 of the complete protected policy bytes, together with
schema, namespace and revision. Each approval, start-apply and final gate check
after before-state capture reads the policy again. Recorded proposer and voter
associations must still match. A missing mapping, relink, revoked mapping,
revision/namespace/schema change, unreadable policy or missing integration hook
fails closed. There is no last-good mapping cache or fallback to account identity.

**Any policy byte change invalidates pending person-bound proposals**, including
an unrelated grant change, whitespace or JSON key reordering. An unchanged
revision does not hide changed bytes. Plan policy updates accordingly: cancel
pending proposals, update policy atomically while retaining protection, then
create new proposals and collect fresh independent approvals. Changing a person
ID or namespace is not an in-place migration of existing approvals. An apply
already blocked in `APPLYING` retains the existing recovery state machine; this
feature neither executes a fix nor grants rollback authority after a failed check.

Switching from v1 to v2 refuses further approval/application of account-quorum
proposals. Switching back to v1 cannot downgrade v2 proposals. Legacy proposals
without separation evidence remain readable but cannot acquire verified or
person-bound authority. No saved receipt is rewritten or silently upgraded.

The policy, audit checkpoint, node runtime and administrative provisioning remain
trusted. Hash checking is not a transaction across policy, inventory, audit and
remote execution, and cannot recall an already-issued command. There is no
monotonic policy-version ledger: restoring the exact original policy bytes can
make an otherwise unconsumed proposal compatible again. Cancel pending proposals
before replacement when revival must be prevented; audited cancellation still
blocks replay. A trusted administrator restoring both policy and trusted audit
state is outside this boundary. Correct assignment of accounts to real people,
protection against identifier reuse and live enclave acceptance remain
organizational responsibilities.

## Source and receipt contract

`AccessPolicy.approval_identity_source()` returns an immutable
`ApprovalIdentitySource` observation of the protected file. It contains the policy
version/hash, namespace, revision and exact-subject mapping tuples. Its `basis`
property returns account mode for v1, or the following v2 metadata:

```json
{
  "mode": "person",
  "policy_version": 2,
  "version": 1,
  "namespace": "operators",
  "revision": 1,
  "policy_sha256": "<SHA-256 of complete policy bytes>"
}
```

`association(issuer, subject)` returns `issuer`, `subject`, `person_id` and
`source` (the complete basis above), or refuses an absent/ambiguous mapping. It
does not authorize any action, validate a session or select credentials. Mapping
tables and policy file paths are never copied into approval evidence.

Verified `AppContext` construction wires exactly:

```python
self.gate.separation_policy = self.access.approval_identity_source
```

Standalone verified gates must install this callback alongside their existing
authorizer, resource/artifact guards, severity/fix source and assessment validator.
Missing policy wiring refuses verified creation/decisions even for v1, because
the gate cannot establish which schema is selected. Explicit development mode
continues to record unverified evidence. No identity model, token, role or
freshness validation changes are required.

New v2 `approval_requirements` retain their existing source and payload digests,
and add `identity_basis` and `proposer_association`. Each vote adds
`person_association` beside its original actor and principal; history retains the
same association. Creation and vote audit events cover these complete objects.
The gate checks the original audited lifecycle, immutable proposal, receipt and
assessment associations before checking current facts/mappings. Same-person
aliases cannot be another voter, including concurrent votes through separate gate
instances. Actual acting issuer/subject, roles and assurance evidence are retained.

`separation.validate_history(gate, proposal, quorum=False)` checks audit-bound
creation, lifecycle, payload and receipt associations. It does not read the current
mapping policy, require a historical login to remain active or establish current
authorization. `separation.validate(...)` additionally checks the current finding,
fix, mode and protected policy. Decision and apply paths use the latter and retain
normal current-account authorization. Historic principal evidence is never
converted into an active session.

## Reports and approval UI

Reports retain raw requirements/receipts and actual account attribution. They label
the recorded quorum as account-based or mapped-person and show the recorded
association, policy revision and hash. `historical_validation` and
`historical_quorum_evidence_checked` describe audit-bound evidence only.
The existing `validation` and `quorum_evidence_checked` additionally check current
source/mapping compatibility. Thus a valid changed policy can produce checked
historical evidence with current compatibility `not_established`. Neither result
is current permission to execute; `current_apply_authorization` remains
`not_established_by_report`. Disputed receipts remain visible as recorded claims.

Current read, original-target ownership, audit and export checks still run. If
the policy becomes unreadable or removes those permissions, export is refused;
historical validation is not an alternate authorization route. Already saved
reports remain snapshots. HTML, Markdown, commander JSON, POA&M and CKLB preserve
the recorded evidence through their existing output paths.

The approval UI recognizes v2, counts distinct recorded person associations and
labels mapped-person quorum. Version 1 is explicitly an account quorum, and
development is unverified. It displays the acting account beside recorded
associations without inferring the current session's person ID from a name or
old receipt. Other-account participation is decided by the backend. Displayed
counts never authorize execution or supersede the server's proposal state.

## Verification

Person-specific regressions live in `tests/security/test_person_access.py`,
`tests/security/test_person_association.py` and
`tests/report/test_person_approval_evidence.py`. They exercise both document
backends, the real gate and API, policy changes at operation boundaries,
concurrent aliases, provenance, reports and preserved unequal account access.
Focused UI tests cover v1/v2 labeling, recorded association consistency and
the absence of inferred current-user mapping. Existing access, file-trust,
credential-binding, separation, report and engine regressions remain applicable.
These are isolated fixtures; they do not establish live IdP, target or enclave
acceptance. This source change is separate from frozen release candidates.
