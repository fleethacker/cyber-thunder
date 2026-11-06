# Container OS import review

Reviewed candidate: `417dc3281c12935f16ae548be618f26a80dd9f25`.
The original branch is preserved. This review changes only the passive importer,
its route/CLI, dedicated regression tests and these documents.

## Fixed findings

| Priority | Finding | Resolution |
| --- | --- | --- |
| P1 | Cancellation abandoned a worker that could publish later. | Propagate a request lifetime event; observe disconnects and check the event before document writes. |
| P1 | Revocation, expired sessions or kill engagement during lifecycle contention could pass the final guard. | Recheck after lifecycle locks and SQLite writer acquisition, through a local view of the public store methods. |
| P2 | Filesystem permission errors exposed paths as authorization errors; SQLite errors escaped the storage mapping. | Fixed storage diagnostics and safe authorization diagnostics; preserve rejection without publication. |
| P2 | The shared kill-switch message exposed the state directory. | A dedicated fixed SCAP diagnostic retains the 423 response. |
| P2 | A CLI byte cap did not prevent blocking on a pipe or opening a device. | Require a regular nonsymlink file, use nonblocking/no-follow flags where supported, and verify the opened identity. |
| P2 | Reversed or timezone-incomparable timestamps could claim completion. | Reject inconsistent start/end timestamps while preserving source times. |
| P2 | Unexpected notselected rows repeatedly searched the expected-rule list. | Use a set; the calibrated comparison test found 90,300 comparisons for 600 rows before the fix. |

Regression assertions were run against the candidate before fixes: the initial
run reproduced 17 failures, a separate comparison calibration reproduced one,
and the subsequent kill-diagnostic calibration reproduced two. These failures
were expected and are retained in the local receipts.

## Boundaries checked

- Exact mapping, explicit target generation/environment, TestResult/benchmark/
  profile identity, foreign critical namespaces, DTD rejection including UTF-16,
  element/depth/field/result caps, and raw result/coverage truth remain enforced.
- Exactly one TestResult remains required. Multiple results, even with one matching
  manifest ID, are rejected. There is no new selection or implicit target mapping.
- Minimal analyst role with node import plus resource read/import grants works for
  both humans and workloads. Missing roles or either resource grant fail closed.
- Repeats preserve original account ownership, time and current precedence. A
  reused or moved target cannot adopt historical or interrupted staged evidence.
- Original and review tests cover both state backends, competing exact repeats,
  interruption before publication, and a committed run whose final audit fails.
- Original XML is hashed, not archived. Unconsumed XML details are not persisted.
  Deliberate provenance declarations and rule titles are retained, not redacted.
- Import remains passive. No scanner, target connection, inventory change or
  remediation was added. Existing registry behavior was inspected; no import-order
  failure justified changing the shared role/access tables.

## Integration and limitations

The parent separately integrated CLI registration and updated the CLI availability
paragraph in `docs/SCAP_RESULTS.md`. Keep that wording when applying this review;
the review does not edit that paragraph or the shared CLI, backlog or CI files.

Cancellation is cooperative and cannot undo an already committed run. A parser or
lock wait can outlive the HTTP request until the next guard. Identity policy and
disconnect delivery are not atomically committed with state. JSON review ledger,
audit and run writes are not one transaction; interrupted invalidations remain
conservative. Original byte/identity hashing and target-generation repeat refusals
are unchanged. Platform applicability and provenance remain unverified; no live
container evaluation or compliance certification was performed.

Full commands, sanitized test receipts, hashes and final commit identity are kept
in `.build/scap-review-handoff.md` and `.build/scap-review-receipts.json`. No full
project gate, push or merge is part of this review.

Validation results (counts are per run):

- Windows focused candidate and review suite: 238 passed, 1 expected POSIX FIFO skip.
- Additional publication checks: 3 passed, 2 expected skips (JSON has no SQLite
  writer contention; FIFO replacement requires POSIX). These five cases were
  added after the focused suite was collected, so the two Windows runs are disjoint.
- Native POSIX FIFO/device/locking/interruption subset: 14 passed, 1 expected JSON
  skip for SQLite writer contention. This overlaps the Windows cases.
- The initial native run crashed while a 45-second timeout stack dump was executing
  during import. The successful retry disabled that dump and plugin autoload.
  An intermediate publication test run also had harness errors corrected before
  the successful run; those receipts are retained, not counted as passing validation.
