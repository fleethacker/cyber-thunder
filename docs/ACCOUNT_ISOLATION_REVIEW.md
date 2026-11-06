# Account isolation review

Reviewed the integrated identity candidate at `24489ca`: request resource checks,
target ownership stamps, status and list filtering, saved reports and legacy
outbox imports, account-bound transports, and copied worker/session guards.
This review uses isolated fixtures and both JSON and SQLite stores.

## Findings fixed

* **High: an old target snapshot could borrow a replacement target's grants.**
  Artifact validation compared the saved ownership stamp with one inventory read,
  but `AppContext.authorize` resolved the ID again without checking that it still
  represented the same owner. A move or delete/recreate between those reads let
  the new account read the previous account's saved report. Target-list filtering
  could likewise authorize a replacement and serialize the old target's notes.
  Object authorization and visibility now require matching environment and
  authorization generation. Transport creation also rejects a stale caller
  snapshot before selecting credentials or opening a transport.
* **High: queued scans could follow a replacement target ID.** A scan carried its
  original ownership stamps but did not check them before execution. Current
  grants on a reused ID could therefore redirect queued work. Scan execution and
  collection now validate the run's recorded ownership, in addition to current
  account and scope checks.
* **Medium: final discovery and scan publication missed revocation.** Transport
  calls already checked authorization before and after I/O, but adapter processing
  could finish after logout, policy revocation, or target reassignment. Discovery
  now rechecks the requesting actor and original target at its existing guards,
  including the final response guard; authorization failures remain permission
  errors. Scans recheck the actor, target and recorded run ownership before
  publishing collected facts and findings. Previously acquired adapter files are
  not erased by revocation; state-directory protection remains required.

Prospective inventory administration retains its existing explicit node and target
grant requirements. Current target IDs remain usable by their authorized owners;
saved evidence and already-started work cannot inherit new ownership merely by
reusing the identifier. Development mode, kill switches, scope checks, transport
cleanup, and per-target export semantics are preserved.

## Verification

The new `tests/security/test_account_isolation_review.py` contains 44 cases across
both stores. The pre-fix runs reproduced 40 failures; four unchanged-authority
controls passed. Regressions cover moves and deletion/recreation, saved reports,
target-list private notes, refusal before transport construction, queued scans,
and policy/session revocation after the last I/O in copied worker contexts.
Identities are constructed during test execution, not at collection time.

The focused verification selection is:

```text
tests/security/test_account_isolation_review.py
tests/security/test_resource_ownership.py
tests/security/test_identity_boundary.py
tests/security/test_browser_api_identity.py
tests/security/test_credential_binding.py
tests/api/test_host_scope.py
tests/api/test_host_scope_review.py
tests/engine/test_scan.py
tests/engine/test_scan_content.py
tests/report/test_access.py
tests/report/test_checklist_access.py
```

Run with `CT_STATE_BACKENDS=json,sqlite`, `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, and
`python -m pytest <selection> -o addopts= -q --tb=short -p no:cacheprovider`.
The report unit modules use an inert policy contract; the new review module and
resource/identity modules exercise the actual application policy and ownership
implementation. Linux verification uses a checkout and test state under the
native Linux home filesystem, not Windows mount permission metadata.

Windows completed with **394 passed, zero failed, zero skipped** in 245.75 seconds;
Linux completed with **394 passed, zero failed, zero skipped** in 164.18 seconds.
Both runs reported 705 existing Starlette/FastAPI deprecation warnings and no
unhandled-thread warning. Local JUnit receipts are
`.build/account-isolation-windows.xml` and `.build/account-isolation-linux.xml`.
The Linux checkout was
`/home/joshua/.cache/ct-browser-tests/account-review-76_wa5z5`.

The parent owns the
complete gate and integration of its independent lifecycle, local subprocess,
separation-of-duties, signed-import and vSphere reviews. This review does not
replace those checks or assert that all possible authorization races are absent.
