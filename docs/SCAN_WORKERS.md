# Bounded host collection (SCL-03: partial)

The opt-in scanner scheduler limits concurrent **host collections per run**. Detection,
normalization, inventory updates, and findings publication stay on one coordinator.
The default remains the existing serial scanner.

| Setting | Default | Meaning |
| --- | --- | --- |
| `CT_SCAN_MAX_WORKERS` / `Settings.scan_max_workers` | `1` | Integer from 1 through 32; maximum outstanding hosts, including completed results waiting for the coordinator. |
| `CT_SCAN_HOST_BUDGET_SECONDS` / `Settings.scan_host_budget_s` | `0` | Finite nonnegative collection budget; zero disables timed boundary checks. |

Either a worker count greater than one or a positive budget selects the new scheduler.
Invalid settings fail before starting a scan. There are no new CLI flags, endpoints,
dependencies, or automatic changes to existing deployments.

## Time, cancellation, and ownership

The budget begins when a host worker starts. It includes authorization, transport
creation, discovery, collection, and transport close. Checks occur before and after
public transport operations and between collection phases. A worker that exceeds
the budget returns `timed_out`; its normalized evidence and findings are discarded.
Detection and final publication are outside this collection budget.

**This is not a hard whole-host deadline or a bounded connection lifetime.** A
synchronous connection, command, adapter helper, or close already in progress must
return before the worker can stop. There is no `Future.cancel()` deadline claim,
detached worker, or forced connection close from another thread. A stuck call can
therefore keep a scan running indefinitely. While draining, the persisted run stays
`running` with `coverage_incomplete=true`, rather than claiming a terminal result.

`Scanner.cancel(scan_id, requested_by=...)` accepts cancellation for an active opt-in
collection from the requesting account with current scan authority. Acceptance closes
at the start of final publication; a later request returns `False`. There is no new
API/UI cancellation control. The kill switch remains checked at collection and
publication boundaries. Calls already in progress drain before the scan returns.
Hosts that finish after an accepted cancellation do not publish normalized evidence.

Each host gets its own copied `ContextVar` context and transport, constructed inside
that context. The principal, operation, session validity callback, current per-account
binding, source ownership, current persisted target configuration, scope, and kill
switch are checked. The scheduler never combines accounts' grants. Existing transport
guards, privilege limits, and credential leases remain in place inside its boundary
wrappers. An active transport object returned twice by a factory is refused without
closing the first worker's connection.

Workers and their coordinator are visible through `Scanner.threads`, which the
existing `AppContext.close()` drains. Every started worker is joined on normal and
exceptional exits. `close(timeout)` returns `False` and leaves SQLite open while work
remains; the caller must stop accepting work and retry shutdown after draining.

## Results and publication

Workers write adapter scratch artifacts into unique temporary directories. They do
not write `collected.json`, findings documents, inventory freshness, or proposals.
The coordinator processes outcomes in requested target order, rechecks authority
after all collection drains, and publishes findings once using the existing store
review/lifecycle locks. Audit append locking remains unchanged.

Successful scratch artifacts move to the usual `raw/<target_id>/` directory, with
artifact paths and finding references updated. Failed, timed-out, and cancelled
scratch directories are cleaned only after their owners finish. Existing transport
security and authorization audit events are still recorded; they are not successful
scan publication.

Per-host outcomes are `done`, `partial`, `error`, `skipped`, `timed_out`, `stopped`, or
`cancelled`. Collection errors make the host partial; pass/not-applicable findings
from that incomplete collection become `not_reviewed`. No unavailable host receives
facts, findings counts, or a new `last_scan` timestamp. A partial host can retain usable
observations but also does not advance `last_scan`. A mixed run is `partial`; an
entirely unavailable run is `error`. Kill/cancelled runs retain their stop status.
All terminal host outcomes count toward progress.

`ScanRun.scheduling` and findings metadata record the configured cap, budget semantics,
and deterministic outcome counts. IDs, timestamps, audit interleaving, and duration
are naturally variable; host/finding order and semantic outcomes are stable for the
same fixture inputs. Runs remain coverage-incomplete: missing observations cannot
erase prior findings in the store's current view. Partial or stopped runs skip bulletin
rematching, automatic proposals, and explanation precomputation. A fully successful
run follows the existing post-scan path, including catalog read-authority checks.

## Remaining boundaries

- A genuine whole-host wall-clock deadline needs cooperative cancellation and deadline
  propagation in `context.py`, transport factories, SSH/WinRM/kubectl internals,
  adapter helper subprocesses (including Kubernetes k3d/node collection), and shutdown.
  These are outside this change's write scope. Close itself also needs a bounded contract.
- The cap is per run and bounds primary host collection connections. Simultaneous runs
  each have their own cap. Kubernetes secondary-node connections and adapter-internal
  helpers can add resources; this is not a global socket/process cap. A shared admission
  policy across producers and nested transports remains deferred.
- Results wait behind earlier hosts to keep order and memory for outstanding collections
  bounded. A slow first host can reduce utilization. Normalized findings for the whole
  run still occupy memory until final publication; total artifact/finding bytes have no
  new scheduler quota.
- Progress publication is conservative: the new path publishes the normalized findings
  after collection drains. There is no early terminal partial response while a call is
  still running. All-failed runs can contain zero observations, never an inferred pass.
- Authority is rechecked at boundaries, using the existing persisted-inventory readers
  and store locks. This does not introduce a transaction spanning policy files, target
  files, raw artifacts, and final run/findings documents. Existing crash/write-failure
  recovery and cross-file race limitations remain.
- Existing report/UI summaries are findings-based and do not render the new scheduling
  fields. Consumers must inspect run status/results/coverage and scheduling metadata to
  distinguish unavailable hosts. Report/UI integration is deferred.
- Default serial behavior remains unchanged, including its existing per-target
  publication and stop semantics. The stricter timed-boundary and incomplete-host
  behavior described here applies only to the opt-in scheduler.

## Validation

All new tests forbid socket connections and use disposable fixture targets. Both JSON
and SQLite are exercised. The 500-host simulation uses an explicitly **in-memory**
inventory, 1 ms fixture collection delays, and one host that waits 30 ms then fails.
It measures scheduling, audit, scratch files, and final publication; it does not model
network latency, persisted inventory parsing cost, real leases at scale, or remote
scanner throughput. The serial simulation selects the same scheduler with one worker
and a 60-second budget, making the comparison meaningful.

Focused checks include connection caps, ordered metadata and findings, retained prior
observations, report assurance counts, late-result rejection, source/configuration and
account changes, session revocation, concurrent account isolation, mounted credential
lease cleanup/expiry, and SQLite shutdown while workers are blocked. Existing scoped
scanner, import, catalog, risk-authority, separation, and publication checks run alongside
them. No broad suite or real network scan is part of this validation.

### Reproduction and source boundary

Only these repository files change:

- `cyberthunder/scan.py`
- `cyberthunder/scan_workers.py`
- Scan-specific fields and validation in `cyberthunder/config.py`
- `tests/scan_workers/test_workers.py`
- `docs/SCAN_WORKERS.md`

Run the scope below serially, with `CT_STATE_BACKENDS=json,sqlite`. No test worker
processes are used. The independent release gate remains a separate activity.

```text
python -m pytest --durations=10 -o junit_family=legacy
  tests/scan_workers
  tests/engine/test_scan.py
  tests/engine/test_guardrails.py::test_scan_refused_while_killed
  tests/engine/test_guardrails.py::test_scan_stops_remaining_targets_when_killed
  tests/engine/test_guardrails.py::test_full_scan_rematches_bulletins
  tests/engine/test_scan_content.py
  tests/security/test_account_isolation_review.py::test_queued_scan_cannot_switch_target_ownership_before_execution
  tests/security/test_account_isolation_review.py::test_scan_rechecks_authorization_before_publishing_collected_facts
  tests/security/test_account_transports.py
  tests/ingest/test_catalog_rule_metadata.py::test_scan_integration_preserves_prior_results_on_catalog_failure
  tests/ingest/test_catalog_rule_metadata.py::test_scan_rechecks_read_after_annotation_and_preserves_previous_results
  tests/ingest/test_authorized_imports.py
  tests/security/test_risk_authority.py::test_current_authority_rechecked_after_pending_audit
  tests/security/test_risk_authority.py::test_saved_receipt_never_grants_revocation_or_apply
  tests/security/test_separation_review.py::test_apply_authority_revoked_during_receipt_validation_is_rechecked
  tests/security/test_separation_review.py::test_kill_and_scope_are_checked_after_final_quorum_validation
  tests/findings/test_reviews.py::test_partial_overlay_and_completed_full_scan_absence_invalidate_correctly
  tests/state/test_lifecycle.py::test_active_work_timeout_retry_and_late_write[scan-json]
  tests/state/test_lifecycle.py::test_active_work_timeout_retry_and_late_write[scan-sqlite]
```

The displayed argument list is wrapped for readability; pass it as one command or
as an argument array. Additionally run the two catalog integration nodes above with
`CT_SCAN_MAX_WORKERS=3` to exercise their existing protections through the new scheduler.

### Measured environment

Windows: Python 3.12.10 on an Intel Core i7-6820HQ, four physical cores/eight logical
CPUs, 63.84 GiB RAM; one serial pytest process, no process affinity restriction.
The 190-test scoped run passed in 228.58 s. Subsequent checks for the final partial-host
freshness refinement, aborted-consumer joining, and opt-in catalog behavior passed
7 tests in 20.56 s; the explicit blocked-transport deadline checks passed 2 tests in
3.94 s. These are 199 successful invocations, including repeats, not 199 distinct tests.

Linux: native source export at
`/home/joshua/cyber-thunder-scan-workers-20261106-6d97a2`, using
`/home/joshua/cyber-thunder-linux-validation-20261105-f7018959/venv312/bin/python`
(Python 3.12.16). WSL exposes six CPUs and approximately 19.5 GiB RAM; validation is
restricted to **CPU 0** with `taskset -c 0`, while the independent release gate shares
the VM. There is no dedicated memory reservation or process memory cap. Shared load
and filesystem differences prevent interpreting these timings as controlled speedups.
The final 193-test scoped suite passed in 80.32 s. Both platforms emitted only existing
FastAPI/Starlette deprecation warnings in the scoped suite.
Linux's additional opt-in catalog integration run passed 4 tests in 3.69 s.

| Platform / store | 500 hosts, 1 worker | 500 hosts, 4 workers | Observed peaks |
| --- | ---: | ---: | --- |
| Windows / JSON | 16.624 s | 14.812 s | 1 / 4 |
| Windows / SQLite | 16.016 s | 14.781 s | 1 / 4 |
| Linux, CPU 0 / JSON | 3.676 s | 2.829 s | 1 / 4 |
| Linux, CPU 0 / SQLite | 2.977 s | 2.252 s | 1 / 4 |

Each case finished with 499 findings, 499 successful hosts and one explicit delayed
failure; no live connection was used. Timings are measured inside the test around the
scan call and exclude test setup/teardown. They are observations under shared load,
not throughput guarantees.

Machine-readable Windows proofs and the exact argument array are under
`C:/Users/joshu/.codex/tmp/bounded-scan-workers-20261106-6d97a2/`:
`suite.json`, `source-hashes.json`, `windows-scoped.xml`,
`windows-final-targeted.xml`, and `windows-blocked-transport.xml`.
Linux proofs are in the owned export's `proofs/` directory and are copied into that
Windows proof directory for review. The source hashes bind the validated code/tests;
this documentation's final measurement update happens after validation.
