# Maintenance windows — FUTURE candidate

This bounded COV-03 slice restricts when a new remediation may start. It is a
candidate for review and acceptance, not release evidence. It does not add a
host-validated dry run, recurring schedules, a DST scheduler, or timed jobs.

## Operator configuration

Set `CT_MAINTENANCE_POLICY` to an **absolute path** to an operator-managed JSON
file. Provision it outside writable application/user content. There is no API
for changing it and application administrator status does not grant authority
to change its filesystem protections.

```json
{
  "version": 1,
  "rules": [
    {
      "id": "training-enclave",
      "environments": ["training"],
      "windows": [
        {"start": "2026-11-09T22:00:00-05:00", "end": "2026-11-09T23:00:00-05:00"}
      ]
    },
    {
      "id": "web01-short-window",
      "target_ids": ["web01"],
      "environments": ["training"],
      "windows": [
        {"start": "2026-11-10T03:15:00Z", "end": "2026-11-10T03:45:00Z"}
      ]
    }
  ]
}
```

At least one exact target or environment selector is required per rule. When
both are specified, both must match. Patterns and wildcards are rejected. The
windows within one rule are alternatives; **every applicable rule must permit
the start**. In the example, `web01` in `training` can start only between 03:15
and 03:45 UTC. Empty `windows` deliberately holds all new applies covered by
that rule. A target with no applicable rule has no maintenance time restriction;
this is explicitly reported as `not_applicable`.

Timestamps require a full date, time including seconds, and explicit `Z` or
numeric timezone offset. Unknown offset `-00:00`, naive local time, invalid
offsets, duplicate keys, unknown fields, overlapping windows within a rule,
repeated IDs/selectors, and nonpositive durations are rejected. Fractional
seconds are supported through six digits. Comparisons and API times are
normalized to UTC. Start is inclusive; end is exclusive. Offsets describe the
specific instant; no zone-name or future DST calculation is inferred.

Limits: 256 KiB, 256 rules, 2,048 total windows, 128 values per selector, and
bounded JSON depth. The existing protected-file reader checks ownership,
ancestor permissions, native Windows owner/DACL trust, and file identity while
reading; redirects, hard links and concurrent replacement are refused. POSIX
files/parents must be owned by the service account or root and not writable by
other accounts (the existing root-owned sticky ancestor exception applies).
Windows deployments require the same protected account/system/administrator
ownership and DACL provisioning as the access policy. Reuse the access-policy
deployment's protected directory; ordinary inherited writable directories are
not trusted merely because the application can read them.

Every decision reloads and validates the configured file. Atomic operator
replacement is supported; a race or invalid replacement blocks that attempt.
There is no cached last-known-good fallback. A missing/unreadable/untrusted
configured file, an empty setting, or a malformed policy holds apply. **Only an
unset setting (`None`) disables maintenance restrictions**, preserving existing
behavior without a hidden expiry. The UI explicitly reports this condition.
Configuration removal or any policy-byte change during an admitted apply also
refuses that attempt; the operator must review and submit again.

## Apply, verification and recovery

The API checks before queuing. The engine independently checks before the
proposal enters `applying`, before connecting or capturing before-state, and
again immediately before issuing a runbook or calling the apply adapter.
Execution uses the existing per-target serialization and current persisted
ownership. The final maintenance audit occurs before the existing final
approval, quorum, assessment, scope, identity and kill-switch checks; a last
maintenance recheck follows those checks. Expiry or a policy/ownership change
during capture cannot authorize the payload. The node's nondecreasing freshness
clock prevents a backward wall-clock correction from reopening an expired window
within that running process.

A configured policy requires the proposal's original ownership scope. Legacy
proposals without it must be recreated and approved; leaving the policy unset
preserves their existing behavior.

Initial refusal leaves proposal and target state unchanged and reports
`Outside maintenance window; apply is held.` A refusal after read-only capture
may mark the proposal failed and retain capture evidence; it executes no
payload and does not initiate a rollback for work that never ran. Audit failure
at the maintenance boundary also refuses execution.

All existing approval, payload digest, person quorum, account permissions,
scope, kill switch, credential, assessment, finding-review and risk-acceptance
guards remain mandatory. A window is neither approval nor target access.

Once apply has started, the window does not interrupt its commands. Verification,
automatic recovery and explicitly authorized rollback remain subject to their
existing guards and can proceed after the window ends, even if the maintenance
policy subsequently becomes unavailable. Maintenance policy does not give an
operator rollback permission or bypass the kill switch.

## Deliberate human exception

The exception is available only to a verified human with the approver capability
and a separate **`maintenance.override` exact issuer + subject + target +
environment grant**. Example additional access-policy grant on that subject's
entry:

```json
{
  "actions": ["maintenance.override"],
  "target_ids": ["web01"],
  "environments": ["training"]
}
```

It cannot be derived from an administrator role, group, wildcard, node grant,
ordinary apply grant, or another login associated with the same person. It
does not select credentials or provide apply/approval permission. Development
actor labels cannot use it. Fresh authentication must satisfy the configured
step-up assurance and maximum age at each exception check; there is no grace
period that replaces current assurance.

For an approved, held proposal, **Review window override** opens an explicit
review. **Review current change** retrieves the current payload and timing; the
operator supplies a reason of 10–1,000 characters and chooses **Apply once with
this reason**. The client sends `maintenance_override` with `binding`,
`expires_at`, and `reason` to the existing proposal apply endpoint. It does not
approve the proposal. No request is replayed after authentication, rejection,
closing/reopening, or changing accounts. A rejected submission discards its
review; another attempt requires another explicit review.

The binding is an expectation digest, **not a bearer token**. It binds the
proposal and approval/assessment content, current and originally recorded fix
digest, original ownership generation, current endpoint identity, current
maintenance-policy bytes, access-policy bytes/person association, exact account,
assurance settings, and expiry. There must be an original payload digest and
ownership scope. Missing binding data disables the exception. Changing any
bound fact requires a new review. The supplied expiry must still be future
and no more than 120 seconds away at every check. The same authorized request
can run at most once because the existing serialized approval transition admits
only the current approved proposal. Nothing is stored as a reusable exception
grant; request expectations alone never authorize work.

Audit records include the acted account, validated principal evidence, reason,
expiry, binding, policy observation and request/admission/execution stage.
These `pending` checks are admission evidence, not evidence that the adapter
completed a change. Existing remediation/verification events record outcomes.
An invalid or unavailable maintenance policy cannot be overridden. An exception
submitted after the window opens must still pass all of its original binding
and expiry checks; it is never silently ignored or converted to a different
authorization request.

## Validation and remaining external acceptance

Focused automated cases exercise JSON and SQLite state, exact start/end/future
times, UTC offsets, rule intersection, strict/untrusted/missing configuration,
reload, unchanged target/proposal on initial hold, final-boundary expiry and
revocation, unequal account grants/person association, fresh assurance,
stale/replayed/concurrent requests, mandatory approval and transport authority,
audit failure, recovery after expiry, API refusal before queueing, and explicit
UI rejection without replay. Commands, source hashes, counts and raw failed and
successful receipts are retained under `.build/maintenance-windows`.

External acceptance still requires operator provisioning/replacement of the
protected policy on the deployment host, real identity-provider fresh-login
and account revocation, browser interaction rehearsal, and an authorized
isolated-range apply/verify/rollback across a real window boundary. Full release
gates, merges, pushes, real target execution and independent risk evidence are
outside this candidate. No claim of production or zero-trust acceptance is made.

The node clock and filesystem authority remain trusted infrastructure. This
slice cannot establish trustworthy time across process restart, make a target
mutation atomic with an external administrator's edits, coordinate other nodes
or host aliases, or stop a multi-command payload at window expiry. The enforced
boundary is admission of the existing adapter operation, not each command in a
distributed transaction. Host-validated dry run and recurring/DST schedules
remain separate work.
