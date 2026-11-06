# Independent local checkpoint review

Reviewed source: `f371d37015526ac6ae1ec7ec7d0c05747b121cbf`.
The review is limited to detached checkpoint parsing/signing, protected local
files, the shared audit/store lock, receiver continuity, failed publication, and
the native CLI boundary. It does not establish off-node retention or approval of
an enclave deployment.

## Reproduced defects and correction

The shared `audit.chain.file_lock` accepted a timeout but used blocking `flock`
on POSIX. A second process holding the lock kept a caller with a 0.1-second
timeout blocked beyond a one-second test deadline. This can leave checkpoint
export/import or other state writers waiting indefinitely. Native Linux reproduced
the failure; it is not inferred from a mocked Windows platform.

On Windows, the same contention reached `TimeoutError`, then the unconditional
unlock attempted to release an unacquired byte range and replaced that exception
with `PermissionError`. The anchor command still refused the operation, but the
shared lock's timeout contract was broken. Native Windows reproduced this failure.

Lock acquisition now uses nonblocking attempts with the existing deadline on both
platforms, retries only contention errors, and releases only successfully acquired
locks. The default remains 15 seconds. The protected critical section and native
descriptor validation are unchanged. This also makes POSIX callers of the shared
lock time out under sustained contention, matching the existing Windows limit;
operators must schedule long checkpoint reads and retry busy operations explicitly.

The regression holds the real lock in another process, checks two independent
timeouts, verifies the CLI emits a sanitized refusal without an artifact, and
then verifies acquisition succeeds after the holding process exits. Additional
cases check immediate failure on unsupported locking and release after a critical
section raises an exception.

## Reviewed boundaries

- Real Ed25519 signatures cover the domain separator and exact canonical body.
  Every variable checkpoint field was changed independently while retaining the
  original signature, including trusted alternate scope/key names; verification
  and import refused each changed body without changing receiver state.
- Schema-valid signatures cannot bypass the stored predecessor, sequence or
  stream. A valid successor using another trusted stream's predecessor is refused.
  Existing tests also cover lower sequences, same-sequence forks, missing state,
  corrupt stored signatures, exact replay, concurrent fork imports and rotation.
- Public/private key files reject wrong types, private material in a public-key
  slot, multiple PEM blocks and encrypted private keys. Signature text rejects
  padding, trailing characters and alternate encodings with nonzero padding bits.
  Trust is explicitly configured; a checkpoint cannot select its own key path.
- File checks use native ownership/permissions and stable descriptors. Native
  Linux regressions exercise FIFOs, key/lock symlinks and writable parents.
  Native Windows exercises DACL failures, hardlinks and a junction in the existing
  suite. Existing tests verify trust changes during validation prevent publication.
- Fault injection before flush/publication leaves prior receiver bytes intact.
  Failure after publication returns no success receipt; the surviving complete
  bundle can be verified and a repeated import is idempotent. Rollback remains
  refused after recovery. These are process-level I/O failure tests, not physical
  power-loss or storage-controller durability acceptance.
- The native CLI requires explicit paths and rejects an actor override even with
  otherwise complete arguments. Authority is the OS account's protected-file
  access, not an application role/session. There is no new API, automatic hook,
  ambient key lookup or network receiver. Operators must not expose the command
  through a shared privileged shell wrapper.

No signature-binding or monotonic-store bypass was reproduced within these cases.
This is bounded evidence, not a claim that every possible filesystem race or
cryptographic implementation defect has been excluded.

## Evidence

The original 55 anchor cases passed separately on native Windows Python 3.12.10
and native Linux Python 3.12.16 before the change. The new contention regression
failed on both original implementations. The independent review adds 34 cases.
Both platforms use cryptography 50.0.2 and pytest 9.2.0. Linux tests run from a
separate copy of tracked source on the native Linux filesystem, using the existing
Python 3.12 interpreter and disposable local fixtures. No shared state, production
keys, external receivers or existing clusters are used.

| Focused command selection | Native Windows | Native Linux 3.12 |
| --- | --- | --- |
| `tests/audit tests/test_audit_and_control.py tests/test_approval_io.py` | 142 passed, 4 skipped; 40.31 s | 144 passed, 2 skipped; 6.93 s |
| `tests/state/test_concurrency.py tests/state/test_file_read_sharing.py tests/api/test_audit_kill_policy.py` | 37 passed, 49 warnings; 112.96 s | 31 passed, 6 skipped, 49 warnings; 80.76 s |

The state-store checks include both JSON and SQLite. The four Windows skips are
the native POSIX protection cases. All eight Linux skips require Windows file
sharing semantics. None of the 89 anchor cases was skipped on native Linux.

Exact focused results, platform-specific skip node IDs, interpreter paths, tested
source hashes and reproduction logs are recorded in the accompanying local review
receipt. No full repository gate is claimed by this review.

## Remaining acceptance

Independent receivers, actual transfer/acknowledgement, protected receiver
administration, independently retained state, compromised-key response, hardware
custody and physical storage durability remain outside this review. An operator
who can replace the entire store with an older valid backup can still roll it back;
the same local store cannot prove that it has not been restored. A signer with the
private key can make false or divergent statements, and separate receivers need
reconciliation to discover forks between them. These limitations remain explicit
in `AUDIT_ANCHORS.md`; local success does not close external acceptance items.
