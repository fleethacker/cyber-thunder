# Bounded scan collection independent review

Reviewed candidate `18d15c76850479daf1eb4234922750bdc5a385b0`, including `d037cef`,
against base `c9566db8e58021a7bfa26426cede86d9ef72e969`. Changes remain in scan
orchestration, scan worker tests and these documents. No shared store, security,
API, UI, container, workflow or namespace collector implementation changed.

## Findings addressed

| Priority | Reproduced issue | Correction |
| --- | --- | --- |
| P1 | Session revocation during findings/run publication lock admission, or after target audit, still published successful evidence in both worker and default serial modes. | Both modes use a per-run guarded store view checking current authority inside existing lifecycle locks and after SQLite writer admission. Failure withdraws staged observations before recording the error. |
| P1 | Credential registry contents could change after transport close while the configured path and account binding stayed the same. | Pin the resolver fingerprint in each worker and recheck it during collection, detection and publication. |
| P1 | An incomplete pass became `not_reviewed` and replaced a prior open finding, changing its status, source and freshness. | Preserve the prior observation exactly by omitting the uncertain replacement. Recheck for concurrent unresolved observations under the publication locks. |
| P2 | An inventory update exception left an error target with facts, positive counts and `collected.json`. | Clear all success fields and return the owned promoted directory to its temporary owner for cleanup. |
| P2 | Coordinator startup failure left a pending run and stale thread registry; startup admission was invisible to shutdown. | Record terminal startup failure, release registry entries and track the admitting caller until startup completes. |
| P2 | A worker start implementation raising after launch could leave that child outside the pending join list. Nonstandard collection/detection exceptions left unfinished outcomes. | Register the child before start, exclude only genuinely unstarted children from joining, drain on every exit and record unavailable outcomes before propagating. |

The unchanged active-transport duplicate rejection was verified: a rejected duplicate
neither closes nor rewraps the owning worker's connection. Cancellation before publication
is honored; cancellation after admission closes returns false. Separate copied contexts,
current account binding, lease cleanup, scope/configuration changes, prior omission
preservation and draining shutdown remain covered by the focused existing tests.

## Evidence

The original receipts were inspected, not rerun: Windows 190 and Linux 193 scoped
checks, smaller follow-ups, the simulated 500-host cases, and the separate 14-check
publication follow-up on each platform. Code/test hashes match the corresponding
commits. The documentation hashes predate their final measurement updates and do not
match the committed documentation; they are not presented as exact final source proofs.

Independent Windows calibration on the original candidate produced 10 failures and
6 passes. A separate preservation calibration failed on both JSON and SQLite. These
checks then passed after the relevant corrections. A later registry-content calibration
also failed on both backends before its fingerprint correction. Final validation uses fixture-only
collections with socket connections forbidden, both state backends, one pytest process,
CPU 0, the supplied Python interpreters and a fresh native Linux source export. The
500-host simulation is excluded; no real hosts, network, dependency installation,
full release gate or publication is part of this review.

The default serial path was separately calibrated: all six negative probes failed
(three revocation boundaries on JSON and SQLite). Thus disabling workers did not avoid
the authority race. The shared correction now guards incremental findings/run writes,
terminal publication and post-scan updates without changing store/security code or the
serial collector's existing stop boundaries. It clears rejected success fields and
withdraws only normalized files owned by that serial run; diagnostic raw artifacts may
remain. No claim of comprehensive serial collector parity with the worker scheduler is made.

Machine-readable receipts, exact arguments, source SHA-256 manifests and original
receipt comparisons are in the local evidence directory
`bounded-scan-independent-20261106-18d15c7`. The handoff identifies its absolute path
and the exact committed head. Final validation counts are recorded in those receipts.

## Open integration criteria

- The parent must integrate this reviewed head and run the separately owned release
  gate/publication checks. Namespace collector review remains separately owned.
- The per-host time budget is cooperative. Synchronous transport/helper/close calls
  must return; no hard whole-host deadline or real 500-host throughput is established.
- Connection admission is bounded per run, not globally across runs or nested adapter
  connections. Total retained evidence bytes are not bounded by the worker count.
- Raw artifacts, findings, run metadata, freshness and audit are separate publications.
  Permanent storage failure or a crash can interrupt withdrawal. Atomic visibility and
  durable recovery across these publications require a shared store/recovery contract
  outside this scan-only ownership boundary. Existing review invalidations are not undone.
- Retained old findings keep their old timestamps and identity. A per-finding stale or
  unavailable presentation still requires report/UI changes outside this scope.
- Default worker count one with zero budget retains serial collection and its existing
  stop boundaries. Locked authority checks and withdrawal are shared by both modes;
  cooperative budgets and conservative incomplete-host filtering remain worker-only.
