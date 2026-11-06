# State lifecycle independent review

Candidate: `f016ef8c7ba736c38088a08264b4fcfe754acda9`, directly based on
`e15e34bdf101463453c3a8eaa83382d33b277e74`. Review branch:
`codex/state-lifecycle-review`. This remains a separate future release candidate.

The initial bounded fixes are committed as `ff13a9e`. The authorized follow-up
extends ownership to detached impact work. This remains separate from the current
combined release; no merge or publication is part of this review.

**Final verdict: the identified lifecycle ownership blockers are corrected within
the documented contract.** Permanently stuck workers still require a later retry
or process exit; cleanup does not claim success or close state beneath them.

## Corrected issues

- **P1: children created during explanation drain escaped cleanup.** The candidate
  inspected service/API registries, then drained explanation callbacks, then closed
  SQLite without checking registries again. An event-controlled callback starting
  an API writer made `close()` return true while that writer was alive. Cleanup now
  repeats worker and explanation draining until both are quiescent, using the same
  deadline. A timeout retains connections for retry. Self-close from the explanation
  thread returns false rather than trying to join itself.
- **P2: startup construction failure skipped owned cleanup.** Runtime construction
  and import were outside the startup handler's exception boundary. Injecting a
  constructor failure left the saved SQLite connection usable after startup failed.
  They now share the existing cleanup boundary. Borrowed contexts remain borrowed.
- Partial context construction now uses worker-aware cleanup rather than immediately
  closing its store. Registry inspection tolerates services not yet assigned. The
  regression injects a failure after a real registered background write is admitted.
  Current built-in service constructors do not themselves start background workers.

## Actual worker ownership

| Creation site | Ownership and drain result |
| --- | --- |
| `runtime.py`, interval threads | Registered on `RuntimeTasks`; stopped and joined before service draining. |
| `ingest/link.py`, `probe(background=True)` | No thread creation. The flag controls scheduling checks; the probe executes synchronously on its calling runtime/API worker. |
| `ingest/probe.py`, disposable process | Network-only subprocess; its caller kills/reaps it in `finally`. Link observation and reservation writes remain on the joined caller. |
| `ingest/content/service.py`, reconnect | Registered in `ContentService.threads` before start. Its check and automatic pull run on that thread; automatic pull uses `background=False`. |
| `ingest/content/service.py`, background download | Thread starts then is appended to `threads` before its caller returns. An owned producer is joined before resnapshotting; external admission must already be stopped. |
| `scan.py`, scan threads | `Scanner._threads`; includes the scan's synchronous callbacks and submitted explanation work. |
| `discovery/service.py`, discovery threads | `DiscoveryService._threads`. |
| `vulnerabilities/service.py`, update threads | `VulnerabilityService.threads`. |
| `api/util.py`, API jobs | Process-wide `_threads`; unrelated applications can conservatively delay close. |
| `explain/worker.py`, queued explanations | Wait for idle, stop, join, then resnapshot other registries for callback children. |
| `impact/service.py`, `_bounded_call` | Required service owner; actual threads retained and exposed through a locked `worker_threads()` snapshot. Context drains them with the other registries. |

The link/reconnect/download omission concern is refuted for the actual candidate
code, not classified as arbitrary plugin behavior. Tests drive the real runtime
loop, `Link.probe`, reconnect callback, content check and download job. Event-controlled
probe/index/download boundaries prevent live network access; production scheduling,
registry handling and state writes execute normally. No sleep-based race orchestration
or new broad cleanup fixture was added.

## Impact ownership correction and limits

**P1, corrected: impact timeout did not establish quiescence.** `_model.checked_call` invokes
`guard()` inside `_bounded_call`'s detached thread. That guard calls `_guard` and
`_snapshot`, including `store.current_findings()`. If the caller's timeout expires
while the guard is still executing, the calling API job can finish while the detached
thread can still access SQLite. Absence of final assessment publication is insufficient.

The follow-up reproduces this through real `ImpactService.assess`, `_guard`, `_snapshot`
and findings storage, using event barriers at the findings-read boundary. Both probe
and generation timeouts reported successful owned-API cleanup before the fix. Releasing
the actual guard then reopened one SQLite connection on Windows and **3 descriptors**
on native Linux (zero immediately after cleanup). These four JSON/SQLite cases fail
against `ff13a9e` on both platforms. No live network or target operation is involved.

Both production `_bounded_call` sites now require their service owner. Worker start
and registration share a lock with snapshots, preventing a drain from mistaking a
not-yet-started thread for completed work. Finished threads are pruned; timed-out
calls remain registered until their actual thread exits. Context resnapshots include
impact children created during draining, and all joins use its existing shared
deadline. Failure to drain returns false with state usable for retry. Startup errors
release their semaphore slot and propagate. Existing backend-error classification
and permission checks remain; no token lifetime, policy, cancellation or publication
authority was extended. A thread-start failure now propagates rather than publishing
a fallback receipt for work that could not start.

Focused tests additionally cover nested impact workers created during drain, three
workers sharing one waiting budget, borrowed and unrelated context ownership,
repeated thread-start failure without semaphore leakage, propagated permission denial,
self-close refusal and later reopening. Final successful cleanup checks the real
connections, empty worker registry and native descriptor count before fixture cleanup.

Existing exclusions remain: callers stop external admission and synchronous users;
concurrent close/admission and arbitrary unregistered threads are unsupported. A
timeout does not kill workers or install a finalizer. Partial-construction cleanup
also retains state if draining times out. Later explicit store use can reopen handles;
no permanent closed flag was introduced. Borrowed API shutdown never closes its store.

## Earlier evidence (preserved, not final-source receipts)

Independent native 12-cycle API control with applications retained and GC disabled:
parent revision **0 / 36 / 36** descriptors (initial / shutdown / after explicit GC);
reviewed implementation **0 / 0 / 0**. The two primary regressions fail against the
unchanged candidate on Windows and native Linux. The final callback test uses
`demo.json`, a real SQLite document, for its delayed writes.

The initial review selection, without extra skip allowances:

```text
python -m pytest tests/state/test_lifecycle.py tests/state/test_backends.py
  tests/test_store.py tests/ops/test_vulnerability_cli.py
  tests/ingest/test_measured_link.py tests/cluster/test_guardrails.py
  tests/security/test_browser_api_identity.py -ra --tb=short
```

Windows 3.12.10: **333 passed, 0 skipped**, 110.86 seconds.
Native Linux 3.12.16: **333 passed, 0 skipped**, 57.78 seconds.
This is 36 lifecycle cases and 297 surrounding regression cases, independently
rerunning the candidate's 328-case selection plus five new cases. Each run reported
177 existing deprecation warnings; no test allowances or dependencies changed.

Windows interpreter: shared `coverage-report/cyber-thunder/.venv/Scripts/python.exe`
(3.12.10). Native Linux interpreter:
`/home/joshua/cyber-thunder-linux-validation-20261105-f7018959/venv312/bin/python`
(3.12.16). Native source: `/home/joshua/state-lifecycle-review-f016ef8-native`.

The earlier runs verified all **1,069** snapshot files against SHA-256 before and after
testing. Bytes, including line endings, matched exactly. This document was added
after that freeze. Git may normalize line endings when recording blobs, so the
following hashes describe the earlier raw tested files, not the impact follow-up:

| File | SHA-256 |
| --- | --- |
| `cyberthunder/context.py` | `06b2f77faac01714a498d636c2e9fe00f8ad20f694217381ce4ee8426502d4b4` |
| `cyberthunder/api/app.py` | `6053f9b17ef05c99eaf7bd72ae996648f43952c93e4ee7ac645001654b807b95` |
| `cyberthunder/runtime.py` | `8b95924eb8be84cf894610f5913f8c6a19ec10a19a0d11058e64e058126b7ca6` |
| `cyberthunder/store.py` | `4c7e7dde2f335cda12c81823549a68637e4344b98e17d1a83a327e6b137f0613` |
| `cyberthunder/state/sqlite.py` | `a53174be431dc0e02aed4694f77b0a2f9e4ea907c4d487da6b1fccf6b5457f59` |
| `tests/state/test_lifecycle.py` | `efc3cfddc6a4fb4b4c0e1a90ca9f8811e9f5f21fc20509c3a478864b2463f14b` |
| `docs/STATE_LIFECYCLE.md` | `7a28b2bbdf5d89634e7525d21a301a076c5c504507a49d558eda233d498b6662` |

Manifest SHA-256: `32df1858ef0c6293f1b4fc6f21fef56588e2ce60a06696560683ad196dab2d44`.
Source archive SHA-256: `2b8ead83ece355e8f29c698939f28bd3ccd4ad7d17f53c36f5d8241cb0c87c9f`.
New receipts are isolated under `.build/state-lifecycle-review-f016ef8/` in this
worktree and `/home/joshua/state-lifecycle-review-f016ef8-native-receipts/` on Linux.
They include source manifests, raw logs, JUnit results, control scripts and per-platform
interpreter/command/hash receipts. Earlier `.build` review receipts were preserved.
No full gate, push, deployment, live target access, or publication was performed.

## Follow-up source and validation

The final focused selection repeats the earlier seven paths and adds `tests/impact`
and `tests/api/test_impact_routes.py`; flags are `-ra -s --tb=short` plus a per-platform
JUnit output path. No skips or dependency changes are introduced. Results are recorded
in `.build/state-lifecycle-impact-ff13a9e/windows/` and
`/home/joshua/state-lifecycle-impact-ff13a9e-receipts/`. Native source lives at
`/home/joshua/state-lifecycle-impact-ff13a9e-final`. Interpreters are unchanged.

Windows 3.12.10: **703 passed, 0 skipped**, 212.17 seconds.
Native Linux 3.12.16: **703 passed, 0 skipped**, 119.00 seconds.
Each run reported 429 existing event-handler/test-client deprecation warnings;
there were no thread-exception warnings. The nine new impact lifecycle cases are
included in those totals. No full gate was run.

All **1,070** source files are checked before and after each platform run. Only this
review narrative is excluded from the snapshot manifest; implementation, tests and
`STATE_LIFECYCLE.md` are frozen byte-for-byte, including line endings. Exact per-file
hashes are in `.build/state-lifecycle-impact-ff13a9e/source-sha256.json`.

Manifest SHA-256: `891be5e7efb3bf80abb6ed1428efebcf2a11591f4d67d2820a98c713ace55f60`.
Source archive SHA-256: `1bcb0b17286c2c36f772e133f183fe596c0913f619caf951184fd64b0a96fb51`.
Earlier receipts under `.build/state-lifecycle-review-f016ef8/` remain untouched.

| Follow-up file | Raw tested SHA-256 |
| --- | --- |
| `cyberthunder/context.py` | `e9ea11334fd9c65beb6fa333e706649ea88d34de111031ec947228ca94d3222a` |
| `cyberthunder/impact/service.py` | `e952febc69b68c5d403ee331af933eadb536ca77a6d66590dbb8974557af73ba` |
| `tests/impact/test_lifecycle.py` | `e56b53fc3dbf73723d59565250d1687c4928f191b852e0a2884e9cd728f8b281` |
| `tests/impact/test_authorized_jobs.py` | `a9fb214f7e3203416e556aedff5f62dcb9fdf29fdb4a9dc2deb64d28761b621b` |
| `tests/impact/test_service.py` | `4db31122682c7f009f452f58753ed97617beecab257e9fd4b83ebc23372a641b` |
