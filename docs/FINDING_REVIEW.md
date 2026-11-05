# Finding review

Reviews record a named operator's decision separately from the scanner's original observation. They never
change scanner status, severity, evidence, confidence, or remediation approval. Identity is self-asserted:
`identity_verified` is always `false`. This is not authentication or a role/authorization redesign.

`ReviewService(ctx)` exposes `summary(finding, *, now=None)`, `history(finding)`, and
`save(finding, *, actor, disposition, reason, supporting_evidence='', expires_at=None,
expected_revision, evidence_fingerprint)`. `now` accepts a timezone-aware datetime or an explicit ISO timestamp.
`remediation_guard(finding)` is a context manager for the final current-review/policy checks, kill guard,
and apply or runbook issuance. Release it before verification or rescan publication.

## Decisions and response

Dispositions are `unreviewed`, `confirmed`, `false_positive`, `not_applicable`, and `needs_investigation`.
Every save, including reversal to `unreviewed`, appends an event with a required nonblank reason. Reversal
does not remove any prior event. An original scanner pass is not a human decision.

Summary fields:

| Field | Meaning |
|---|---|
| `disposition` | Effective decision; `unreviewed` when absent, expired, reversed, or mismatched |
| `active` | Latest event is a matching, unexpired decision other than `unreviewed` |
| `suppressed` | Active `false_positive` or `not_applicable` only |
| `revision` | Monotonic count of decisions plus durable invalidations; send back as `expected_revision` |
| `evidence_fingerprint` | Current observation's full SHA-256 digest; send back unchanged |
| `current` | Most recently saved event, even if it no longer applies; otherwise `null` |
| `history_count` | All saved events, including reversals |
| `reopened_reason` | Explanation for mismatched or expired evidence; otherwise `null` |
| `identity_verified` | Always `false` |

History views add `history`, in append order. Each event has `id`, `revision`, `disposition`, `reason`,
`supporting_evidence`, `expires_at`, `reviewed_at`, `reviewed_by`, `identity_verified`, `scope`, and
`evidence_fingerprint`. GET never appends automatic reopen events. It evaluates current facts, expiry, and
the persisted invalidation ledger. Human history remains intact; automatic invalidation advances revision
without adding a human decision or increasing `history_count`.

## Scope and expiry

Suppression requires an explicit future expiry and exact current scope/evidence. Any supplied expiry, for
any disposition, must be a future ISO date/time with seconds and timezone, such as `2026-12-01T12:00:00Z`
or `2026-12-01T07:00:00-05:00`. Epoch numbers, date-only values, missing timezones, malformed offsets, and
expired dates are rejected. Suppression ends exactly at expiry. Other dispositions may omit expiry.

Fingerprint version 1 hashes canonical sorted-key UTF-8 JSON using SHA-256. It covers host, source, rule,
rule version, group, benchmark/release, asset type, scanner status, severity, exact evidence, title,
description, check/fix content, sorted unique tags and references, and structured collection provenance.
Detector versions, package versions, image digests, authentication/privilege metadata, and other supplied
provenance are retained. Unknown provenance is not invented. Changing relevant content reopens review.

Observation bookkeeping is excluded: scan ID, collection/observation/display timestamps, raw artifact
location, derived confidence/review/explanation data, and model fields. These exclusions also apply inside
structured provenance. Free-text scanner evidence remains exact; timestamps embedded in that evidence
are not rewritten. A timestamp-only rescan of identical facts may retain a decision until expiry.

## API and persistence

`GET /api/v1/findings/{finding_id}/review` returns current history. Optional `scan_id` evaluates the same
review history against that scan's observation, without writing. This is a historical evidence view at the
present time, not a reconstruction of which review existed when that scan ran.

`PUT /api/v1/findings/{finding_id}/review` accepts `disposition`, `reason`, optional `supporting_evidence`,
optional `expires_at`, `expected_revision`, and `evidence_fingerprint`. It requires `X-Actor` through
`ActorDep`, repeats `require_human` in the service, and enforces the kill switch. `scan_id` on PUT is rejected.
The service rereads current persisted findings, including partial-scan overlays; historical fallback is
never used for saving. Missing current finding returns 404. Stale revision or changed fingerprint returns
409; reload both before another decision. Invalid input returns 400; an engaged kill switch returns 423.

Documents live under `finding_reviews/`, routed through StateStore on both JSON and SQLite. A full digest
of the finding ID is the document filename, preventing imported IDs from becoming paths. Cross-process
file locking serializes review save against final remediation execution for the same finding. Locks use
`LK_NBLCK` on Windows and `LOCK_EX | LOCK_NB` on POSIX. They are non-reentrant, including callbacks in the
same thread. Saving while remediation holds the lock returns `ReviewConflict` (HTTP 409) immediately,
without persisting a review. Lock release only runs after successful acquisition. Unrelated finding locks
are independent. The backend lock gives SQLite a transaction for review and invalidation writes.

`StateStore.save_findings` invalidates a decision before publishing relevant changed observations.
`save_scan_run` also passes through this hook so findings-first imports and scan completion/removal cannot
bypass invalidation. Projection uses full-scan and partial-overlay ordering. Late older scans cannot
override newer evidence; incomplete full scans do not treat unseen findings as a final removal. Same facts
with only timestamp/path changes retain their decision. Open A -> passing B -> open A durably invalidates
the original dismissal even with no intermediate GET. A new human decision can review the recurrence.

Invalidations live alongside immutable human history in the version-2 review document. Each links the
invalidated decision ID, monotonic revision, previous/current fingerprints, scan ID, publication kind,
available run provenance, the SHA-256 of the published document, and a hash-chained audit receipt. The
audit record is written first; a missing audit or ledger write stops publication. Version-1 documents are
read without rewriting and upgraded on the next write. Malformed or incomplete ledgers fail closed.

Scan publication compares the prior and proposed published pictures using evidence fingerprints. Every
changed, added or removed finding ID takes its lifecycle lock in sorted order, including findings with no
review history. This also prevents policy evidence from changing between final checks and apply. Empty
in-progress runs are ignored; incremental full scans retain unseen prior observations until completion,
when omissions become final removals. Findings-first run publication and metadata changes use the same
comparison. Timestamp/raw-path-only changes and unrelated scans continue during apply.

Scan publication retries contention for up to 15 seconds, releasing coordination and all finding locks
between attempts. No SQLite transaction is held while retrying. Publication timeout leaves
observations untouched and reports an explicit error; the caller must retry after the active operation.
Publication from inside its own review/apply guard fails immediately instead of waiting on itself. Normal
concurrent scan workers serialize under publication coordination, including when there are no reviews.

The complete decision is appended to the hash-chained audit with outcome `pending` before writing review
state; a successful save appends outcome `ok` referencing the event ID. Initial audit failure prevents state
changes. A crash or I/O failure can leave a pending audit entry or a saved event without its final `ok` entry:
the filesystem audit and document store are not one atomic transaction. Match the pending event ID to
history during recovery; never delete or silently replay a decision. Every persisted decision already has
its full audit record. Reads do not repair or rewrite history.
Invalidation receipts likewise use a write-ahead `pending` audit entry, with the persisted ledger providing
the committed receipt. A failed JSON publication after ledger persistence can conservatively reopen a
review while leaving the old scanner document intact; SQLite rolls the document writes back together.

Limits are 4,000 characters for reason, 16,000 for supporting evidence, and 1,000 human review events per
finding, with at most one automatic invalidation per human event. Input
over the limits is rejected. The last event slot is reserved for reversal to `unreviewed`, so capacity
cannot prevent releasing suppression. At the history limit further saves are refused with an explicit error;
all existing history remains readable and intact. No automatic pruning or truncation is performed. Malformed
persisted history is rejected rather than reset.

Review saves and scan publications share coordination before taking the SQLite transaction. Scan publication
tries the affected lifecycle locks without waiting while coordinated; contention releases everything for
retry. Review save takes its lifecycle lock first and never waits for publication coordination. This
ordering avoids a cycle between review, apply, scan publication and SQLite. Neither backend's lock is an
authentication mechanism. Raw `write_json` calls bypass the observation hook; scanner/import code must use
`save_findings` and `save_scan_run` to publish observations.

The registered API, Findings page and reports expose the same review summary. Active suppression blocks
new proposals and applying an existing proposal, including a second check after before-state capture.
Capture-only stops do not execute rollback. Low/Unknown confidence or Needs investigation withholds
standing-policy approval; an existing policy-approved proposal is checked again before apply. Neither
Confirmed nor a confidence grade grants approval. Individual human approval remains available for
uncertain findings; active suppression must first be reversed or expire. Rollback keeps its existing guards.
These checks do not make review save and remote apply one atomic operation; reviewers cannot cancel an
already executing remote command by saving a review. Use the kill switch to stop subsequent guarded actions.
Focused tests use temporary fixtures and in-process HTTP only:

```powershell
$env:CT_STATE_BACKENDS = 'json,sqlite'
python -m pytest tests/findings/test_reviews.py tests/api/test_finding_reviews.py
```
