# State lifecycle candidate

This is a separate future candidate based on `e15e34b`, not a release change.

## Evidence and scope

The reported full-suite observation (1,375 descriptors, including 843 SQLite
handles at about 30%) was an investigation input, not reproduced as a full-suite
measurement. No full gate or live target run was used.

A native Linux Python 3.12.16 control on the base revision created and discarded
12 real SQLite contexts with cyclic GC disabled. `/proc/self/fd` contained 36
handles under their temporary state root; explicit GC reduced this to zero.
Services and callbacks reference their context, so dropping the caller's last
reference does not imply immediate reference-count cleanup.

A second control created 12 internally owned API applications and entered/exited
`TestClient` for each. It counted 0 state handles initially, 36 after shutdown
with GC disabled, and 36 after explicit GC in that process. Only MainThread
remained. This demonstrates missing deterministic release at API shutdown, not
proof that a single continuously serving production instance grows indefinitely.
The reason every API object remained reachable after collection was not isolated;
explicit cleanup must work even when an embedding application retains objects.

The same API control on this candidate measured 0 initially, 0 after 12 shutdowns
with GC disabled, and 0 after GC. The regression test deliberately retains all 12
applications and checks both real connection closure and native descriptor counts.
Windows tests assert saved SQLite connections reject SQL after successful cleanup;
they do not rely on process-level fixture cleanup to establish that result.

The concrete defect is an ownership gap: `AppContext` supplied no release method,
`create_app()` did not distinguish owned and borrowed contexts, and shutdown only
called `RuntimeTasks.stop()`. That method joined each interval thread for five
seconds without reporting whether it had stopped. Interval jobs can also launch
separate scan/content/vulnerability/API/explanation work. Closing SQLite directly
after the old stop call would therefore introduce a worker/use-after-close race.

## Contract

- `AppContext.close(timeout=5)` stops registered runtime producers and drains known
  API/service workers, resnapshotting their registries to include spawned children.
  Explanation work drains before its worker stops. Success releases store handles
  and returns `True`. The timeout is one shared waiting budget, not a per-worker
  allowance. OS/backend close time itself is not forcibly interrupted.
- A timeout returns `False` with the store still usable. No worker is killed and
  no finalizer or detached cleanup thread is installed. The owner must retain the
  context, stop admitting work, let outstanding work finish, and retry `close()`.
- `create_app()` owns its internally created context. Shutdown and startup failure
  attempt cleanup. `app.state.close(timeout=5)` provides an explicit retry and
  cleanup path for an application constructed but never started. Shutdown logs a
  warning if cleanup times out. A factory failure before work begins also releases
  the owned context.
- `create_app(existing_context)` borrows it: API shutdown stops that application's
  runtime tasks but leaves the caller's store and jobs available. The caller owns
  eventual context cleanup. `serve()` likewise closes only a context it created,
  including bind/setup/server failures and server return.
- Construction failures release already opened store/backend connections. Optional
  service absence retains its existing behavior.
- Cleanup is idempotent resource release, not permanent object invalidation.
  Existing `StateStore`/SQLite later-use semantics remain: later explicit writes
  can reopen a connection, and require another close. Reopening with a new context
  reads persisted data. JSON remains file-backed. Audit logs remain files; cleanup
  does not delete/reset state, revoke sessions, or change authorization policy.

## Compatibility limits

Owners must stop accepting new work and wait for external synchronous users before
calling close. ASGI servers normally drain active requests before shutdown; direct
embedders must provide that coordination. Concurrent submission/close, concurrent
close calls, arbitrary plugin threads, and unregistered user threads are outside
this bounded contract. Low-level `StateStore.close()` and backend `close()` still
require callers to establish quiescence themselves.

The existing API background registry is process-wide. Cleanup conservatively waits
for all entries, so an unrelated application's job can delay release. This avoids
changing route signatures or worker admission behavior in this candidate. Future
worker implementations must be included in lifecycle coordination before assuming
safe automatic cleanup. Current service registries are inspected without creating
lazy services. Detached impact probe/generation calls retain their service owner
after caller timeout. Context cleanup drains their actual threads and any registered
children before releasing state; their guards can still read SQLite. The owning
synchronous/API work must also drain normally. See `STATE_LIFECYCLE_REVIEW.md` for
the independent reproduction and subsequent ownership fix.

A permanently stuck worker intentionally retains its state until process exit or
an explicit successful retry. Borrowed contexts do not gain automatic cleanup.
CLI call sites and existing broad test fixtures are unchanged. These limits mean
this candidate does not promise to remove every descriptor observed in a full-suite
run or provide cancellation of arbitrary background operations.

## Validation receipts (2026-11-06)

Base: `e15e34bdf101463453c3a8eaa83382d33b277e74`.
Implementation and first expanded test tree:
`3e4c3ccc2afe94a197409d4bb95b791e61b03f1c`.
Archive SHA-256:
`be5423ef5ffe60d8953222810a7466cf49e0ce8ce130bddb8edb5a2702e3b8e2`.
Final tested source tree (before this documentation-only addition):
`b35a6ca64bc97a35fa42b90ff66402c564fba8f9`.
The only difference between the two test trees is supplying required `source` and
`status` fields in the new explanation-worker test's sample finding. Implementation
bytes are identical. All 1,068 files in the native snapshot were checked against
Git blob hashes from the final index: zero mismatches. The Windows working tree
matched that index after Git's normal line-ending normalization.

Windows interpreter:
`C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe`
(Python 3.12.10). Working directory:
`C:/Users/joshu/.codex/worktrees/person-association-review/cyber-thunder`.

Linux interpreter:
`/home/joshua/cyber-thunder-linux-validation-20261105-f7018959/venv312/bin/python`
(Python 3.12.16). Native snapshot:
`/home/joshua/state-lifecycle-candidate-3e4c3ccc`.
This is a native filesystem export, with no Windows-worktree `.git` indirection.

First expanded selection on both platforms:

```text
python -m pytest tests/state/test_lifecycle.py tests/state/test_backends.py \
  tests/test_store.py tests/ops/test_vulnerability_cli.py \
  tests/ingest/test_measured_link.py tests/cluster/test_guardrails.py -ra --tb=short
```

Each returned 320 passed and two failures caused by the incomplete new sample
finding (Windows 101.62 s; Linux 50.35 s). All 291 surrounding regression cases
passed; no implementation failure was found. After correcting that sample:

```text
python -m pytest tests/state/test_lifecycle.py \
  tests/security/test_browser_api_identity.py -ra --tb=short
```

Linux: 37 passed in 33.42 s. Windows: 37 passed in 65.43 s.
This covers 31 lifecycle cases plus six existing session/identity cases, including
logout revocation and idle-session behavior. Combined with the 291 unchanged
regression cases, 328 distinct cases passed per platform. Existing event-handler
and test-client deprecation warnings remain; no dependency changes were made.

Local raw receipts:
`C:/Users/joshu/.codex/state-lifecycle-windows312.txt`,
`C:/Users/joshu/.codex/state-lifecycle-windows312-final.txt`,
`/home/joshua/state-lifecycle-linux312.txt`, and
`/home/joshua/state-lifecycle-linux312-final.txt`.
No push, deployment change, full gate, target access, or global test-policy change
was performed.
