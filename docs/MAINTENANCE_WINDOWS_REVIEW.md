# Independent maintenance-window review

Candidate: `aaaeba952ca706dafc6fe5700f3bc59b1a6d22a2`.
Reviewer and correction author: Joshua Ott <Joshua.ott@outlook.com>.
This is future-batch review evidence, not release or deployment acceptance.

All 24 candidate paths were inspected. Their SHA-256 values matched the
candidate's `final-checks.json` before editing. The candidate's
`EVIDENCE.md` and `docs/MAINTENANCE_WINDOWS.md` were checked against the
execution paths, not treated as proof of those paths. All 22 pre-existing
ignored evidence files were inventoried and preserved.

## Concrete findings and corrections

| Priority | Reproduction | Correction |
| --- | --- | --- |
| P1 | An ordinary API apply queued under a configured, open policy discarded the request observation. Removing the setting or changing even one policy byte before the worker ran still reached connection. | Carry a private, context-local request observation through the worker and target-lock wait, bound to the exact application context and proposal. Engine admission compares the current policy with it. Direct engine calls still perform their own admission. |
| P2 | Expiry or policy removal during `start_apply` still reached connection/capture, contrary to the documented pre-connection guarantee. | Recheck policy, ownership, override and freshness after the state transition and execution binding, before obtaining the transport. |
| P1 | A failure writing the capture audit invoked automatic rollback although `adapter.apply` was never called. The reproduction observes the rollback attempt directly; it does not infer a successful remote mutation. | The generic exception path can attempt recovery only after entering apply or verification. Capture and validation failures retain evidence without initiating rollback. |
| P1 | Changing the library payload during the last maintenance read still reached `adapter.apply`, with and without an override. The engine retained the mutable library object. | Take a private payload copy, revalidate current approval/quorum/assessment/ownership and payload integrity after maintenance reads, then check the kill switch and time/assurance immediately before adapter admission. |
| P2 | Retained override handlers submitted after close/reopen, rejection, reason clearing, proposal change or expiry. A retained ordinary Apply handler also submitted after the card changed to a maintenance hold. | Require the current review object, reason, proposal, open dialog and authority; consume the review synchronously before awaiting; reject expired reviews locally. Ordinary Apply checks its current proposal and blocking state, permission and window end. Server enforcement remains mandatory. |
| P2 | Revoking the exact override grant during capture denied the payload but left the proposal stuck in `applying`. | Pre-payload authorization refusals record a failed proposal and re-raise the refusal, without rollback. |
| P1 | Manual rollback after a maintenance refusal during capture reached connection on an adapter without file-drift support, even though no apply had run. | A failed proposal with neither an apply result nor an applied history entry cannot enter manual recovery. The refusal occurs before transport acquisition. |

The UI findings concern unintended submissions and stale review consent. They
do not demonstrate a bypass of server account authorization. The binding is
an expectation digest, not a signed receipt proving a person read the UI.
The reason is editable before deliberate submission; retained handlers cannot
submit an earlier reason after the displayed reason changes. Changing binding
or expiry alone is rejected by the server's recomputed expectation.

## Verified boundaries

- An override requires a verified human, approver capability, fresh configured
  assurance, and one matching exact-account grant with both target and
  environment. Role/admin membership, groups, wildcard grants, another issuer,
  associated accounts, node permissions and split selector grants cannot be
  assembled into that grant. Credentials for the override action cannot supply
  the apply action's transport credentials or elevation.
- The exception cannot grant approval, satisfy distinct-person quorum, repair
  a missing approved assessment, release a risk hold, change approved payloads,
  override scope or ownership, or bypass the kill switch. Positive execution
  cases accompany the negative tests so denial is not mistaken for a broken
  fixture that rejects everything.
- Strict finite timestamps, duplicate keys/fields/selectors, bounded structure,
  adjacent windows, rule intersection, inclusive starts and exclusive ends are
  exercised. Every protected-policy read uses the same native trust reader as
  account authorization. Platform-specific ownership, DACL, redirection and
  replacement tests are reported by exact skipped node ID, not hidden.
- Missing/invalid/changed/removed policy and ownership changes are checked at
  request, admission, connection, capture/audit and payload boundaries. A
  nondecreasing process clock cannot reopen an expired window after a backward
  wall-clock correction; invalid time fails closed.
- Authorized verification and automatic/manual recovery of executed work can
  continue after expiry; a missing policy does not strand those operations.
  No payload execution means no automatic rollback. Existing recovery guards
  still apply.
- UI tests cover rejected challenges without replay, CSRF request headers,
  late responses from an old account, concurrent clicks, closed reviews,
  retained handlers and expiry. Native browser-session regression tests use
  isolated fixtures, not a real identity provider.

## Evidence and validation

Raw logs, XML results, exact commands, timestamps, source manifests and source
archives are retained in `.build/maintenance-review`. Earlier diagnostic
failures remain alongside passing receipts. Counts overlap across runs and
must not be summed as distinct tests.

| Receipt | Passed | Skipped | Failed |
| --- | ---: | ---: | ---: |
| `windows-final` (maintenance, plan, proposal API, protected-file trust) | 372 | 11 | 0 |
| `windows-dacl` (native ownership/DACL/file sharing) | 46 | 0 | 0 |
| `windows-recovery-final` (final recovery correction and regressions) | 156 | 0 | 0 |
| `linux-reviewed` (maintenance, engine, approval, assessment, access, sessions) | 929 | 47 | 0 |
| `linux-recovery` (final recovery correction and regressions) | 156 | 0 | 0 |
| `ui-final` (focused handlers, API and rendering) | 97 | 0 | 0 |
| `tsc-final` (`node node_modules/typescript/bin/tsc -b --force`) | Exit 0 | 0 | 0 |

The Windows receipts contain exact argument arrays, runtime versions, start/end
timestamps and source SHA-256 values. `linux-reviewed.sh` and
`linux-recovery.sh` contain the exact native commands. Their source archives
and manifests each include 1,004 files; every included hash was verified before
execution. `linux-reviewed-source-manifest.json` binds the broader Linux run.
`linux-recovery-source-manifest.json` binds the final production source. The
last four-line manual-recovery guard and its two backend cases were added after
the broad runs started and are verified by the final 156-case recovery runs on
both platforms. `final-recovery-source-delta.patch` preserves that source delta.
The broad results are not represented as a rerun of the final recovery change.

All current UI source hashes still match both the 97-test UI receipt and the
TypeScript receipt. Final documentation-only edits follow those test snapshots.
`validation-summary.json` contains counts and every executed node ID;
`skip-allowlist.json` contains the exact platform skips and reasons below.
Each skipped case passed on the other native platform. Existing
FastAPI/Starlette deprecation warnings remain visible; no dependency or warning
policy was changed. There are no remaining failing checks in these selections.

Windows uses the existing Python 3.12.10 interpreter at
`C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe`.
Linux uses the existing Python 3.12.16 interpreter at
`/home/joshua/cyber-thunder-linux-validation-20261105-f7018959/venv312/bin/python`
under WSL2 Ubuntu. Native Linux snapshots verify every included source hash
before pytest and exercise native filesystem temporary state. Both JSON and
SQLite backends run. Node and TypeScript use the existing local installation;
no dependencies are downloaded.

Preserved diagnostic receipts include the initial queue/connection/rollback
reproduction (10 failures, 6 passes), final-payload reproduction (4 failures),
override-handler reproduction (5 failures, 9 passes), ordinary-handler
reproduction (1 failure, 7 passes), stuck-proposal reproduction (2 failures),
and capture-only manual recovery reproduction (2 failures).
Intermediate correction runs also exposed overly narrow test expectations for
the existing kill-switch and approval-source refusal types, and an API fixture
whose legacy engine signature did not accept a new argument. The request
observation now travels through operation context without changing that
signature. These failures are retained rather than counted as passing evidence.

| Intermediate receipt | Exact result | Resolution |
| --- | --- | --- |
| `windows-corrections` | 227 passed, 6 failed | Four cases now expect the actual approval-source refusal; two expect the kill-switch exception. Target and rollback sentinels were retained. |
| `windows-trust-plan` | 123 passed, 11 skipped, 8 failed | Context-local request observations preserve the legacy engine call signature. |
| `linux-final` | 909 passed, 1 skipped, 12 failed | The same four assertion-type cases and eight signature cases; superseded by `linux-reviewed`. |
| `windows-boundaries-final` | 14 passed, 225 deselected | Targeted kill/scope/time/assurance, credential, risk-hold and assessment checks; included again in the broad passing run. |
| `ui-corrections` | 69 passed | Earlier focused UI scope, followed by the ordinary-handler reproduction and final 97-test scope. |

## Remaining acceptance and limits

No known reproduced finding is intentionally deferred within the correction
scope. The validation does not establish live-enclave acceptance, trustworthy
time across process restart, real identity-provider session revocation, browser
interaction acceptance or deployment-host policy provisioning. Those require
separate authorized acceptance work.

The boundary is admission to the existing adapter operation, not every command
inside a multi-command payload. Reads and remote mutation are not an atomic
transaction with external filesystem administrators, other nodes or host
aliases. The final time check avoids further policy/inventory reads, but does
not claim distributed atomicity. Node time, protected local state and local
filesystem administration remain trusted infrastructure.

No release gate, push, merge, real target operation, provider change, dependency
download, client login, publication, catalog, global CI or built UI change is
part of this review. Parent integration remains separate.

## Correction paths

- `cyberthunder/api/routes/proposals.py`
- `cyberthunder/remediation/engine.py`
- `cyberthunder/remediation/maintenance.py`
- `cyberthunder/ui/src/components/ProposalCard.tsx`
- `cyberthunder/ui/src/components/ProposalImpact.test.mjs`
- `cyberthunder/ui/src/components/ProposalMaintenance.test.mjs`
- `cyberthunder/ui/src/components/ProposalMaintenance.tsx`
- `tests/engine/test_maintenance_windows.py`
- `docs/MAINTENANCE_WINDOWS_REVIEW.md`

The handoff commit identity and author/committer verification are retained in
`.build/maintenance-review/commit.json`. No global CI allowlist was edited.

## Exact platform skips for future CI review

These are platform exclusions, not a failure allowlist. All 58 excluded node
IDs passed on the opposite native platform in this review.

windows-final: requires POSIX owner/mode and descriptor-relative filesystem semantics.

```text
tests/security/test_access_file_trust.py::test_posix_parent_swap_to_symlink_before_open_denied_and_fds_closed
tests/security/test_access_file_trust.py::test_posix_permission_change_during_parse_denied
tests/security/test_access_file_trust.py::test_posix_policy_write_permissions_denied[386]
tests/security/test_access_file_trust.py::test_posix_policy_write_permissions_denied[400]
tests/security/test_access_file_trust.py::test_posix_policy_write_permissions_denied[438]
tests/security/test_access_file_trust.py::test_posix_policy_write_permissions_denied[950]
tests/security/test_access_file_trust.py::test_posix_root_sticky_directory_exception_never_applies_to_file
tests/security/test_access_file_trust.py::test_posix_untrusted_owner_denied[file]
tests/security/test_access_file_trust.py::test_posix_untrusted_owner_denied[parent]
tests/security/test_access_file_trust.py::test_posix_writable_parent_denied[455]
tests/security/test_access_file_trust.py::test_posix_writable_parent_denied[504]
```

linux-reviewed: requires Windows NTFS junction support.

```text
tests/security/test_access_file_trust.py::test_actual_windows_junction_parent_denied
```

linux-reviewed: native Windows security descriptors and file sharing.

```text
tests/security/test_windows_file_trust.py::test_cache_integrity_allows_readers_and_rejects_writer_or_replacement
tests/security/test_windows_file_trust.py::test_child_creation_is_safe_for_existing_reads_but_not_cache_creation
tests/security/test_windows_file_trust.py::test_dacl_change_after_read_invalidates_the_operation
tests/security/test_windows_file_trust.py::test_deny_ace_does_not_make_a_dangerous_allow_acceptable
tests/security/test_windows_file_trust.py::test_external_kube_public_certificates_and_private_key_have_distinct_rules
tests/security/test_windows_file_trust.py::test_file_mutation_granted_to_everyone_is_rejected[1073741824]
tests/security/test_windows_file_trust.py::test_file_mutation_granted_to_everyone_is_rejected[16]
tests/security/test_windows_file_trust.py::test_file_mutation_granted_to_everyone_is_rejected[256]
tests/security/test_windows_file_trust.py::test_file_mutation_granted_to_everyone_is_rejected[262144]
tests/security/test_windows_file_trust.py::test_file_mutation_granted_to_everyone_is_rejected[268435456]
tests/security/test_windows_file_trust.py::test_file_mutation_granted_to_everyone_is_rejected[2]
tests/security/test_windows_file_trust.py::test_file_mutation_granted_to_everyone_is_rejected[4]
tests/security/test_windows_file_trust.py::test_file_mutation_granted_to_everyone_is_rejected[524288]
tests/security/test_windows_file_trust.py::test_file_mutation_granted_to_everyone_is_rejected[65536]
tests/security/test_windows_file_trust.py::test_fixture_is_genuinely_protected_and_checks_private_bytes
tests/security/test_windows_file_trust.py::test_group_membership_or_unknown_sid_cannot_grant_file_mutation[S-1-5-11]
tests/security/test_windows_file_trust.py::test_group_membership_or_unknown_sid_cannot_grant_file_mutation[S-1-5-21-100-200-300-4444]
tests/security/test_windows_file_trust.py::test_group_membership_or_unknown_sid_cannot_grant_file_mutation[S-1-5-32-545]
tests/security/test_windows_file_trust.py::test_handles_prevent_file_and_parent_replacement_and_data_writes
tests/security/test_windows_file_trust.py::test_inherit_only_grant_is_checked_on_new_cache_file_before_write
tests/security/test_windows_file_trust.py::test_junction_created_between_checks_and_open_is_rejected
tests/security/test_windows_file_trust.py::test_kubeconfig_confidentiality_and_guard_recheck
tests/security/test_windows_file_trust.py::test_native_api_unavailable_fails_closed_for_policy_and_cache
tests/security/test_windows_file_trust.py::test_null_dacl_and_unsupported_object_ace_are_rejected
tests/security/test_windows_file_trust.py::test_owner_must_be_in_the_trusted_sid_set
tests/security/test_windows_file_trust.py::test_owner_rights_is_only_accepted_for_a_checked_trusted_owner
tests/security/test_windows_file_trust.py::test_parent_mutation_including_delete_child_is_rejected[grandparent-16]
tests/security/test_windows_file_trust.py::test_parent_mutation_including_delete_child_is_rejected[grandparent-256]
tests/security/test_windows_file_trust.py::test_parent_mutation_including_delete_child_is_rejected[grandparent-262144]
tests/security/test_windows_file_trust.py::test_parent_mutation_including_delete_child_is_rejected[grandparent-2]
tests/security/test_windows_file_trust.py::test_parent_mutation_including_delete_child_is_rejected[grandparent-524288]
tests/security/test_windows_file_trust.py::test_parent_mutation_including_delete_child_is_rejected[grandparent-64]
tests/security/test_windows_file_trust.py::test_parent_mutation_including_delete_child_is_rejected[grandparent-65536]
tests/security/test_windows_file_trust.py::test_parent_mutation_including_delete_child_is_rejected[parent-16]
tests/security/test_windows_file_trust.py::test_parent_mutation_including_delete_child_is_rejected[parent-256]
tests/security/test_windows_file_trust.py::test_parent_mutation_including_delete_child_is_rejected[parent-262144]
tests/security/test_windows_file_trust.py::test_parent_mutation_including_delete_child_is_rejected[parent-2]
tests/security/test_windows_file_trust.py::test_parent_mutation_including_delete_child_is_rejected[parent-524288]
tests/security/test_windows_file_trust.py::test_parent_mutation_including_delete_child_is_rejected[parent-64]
tests/security/test_windows_file_trust.py::test_parent_mutation_including_delete_child_is_rejected[parent-65536]
tests/security/test_windows_file_trust.py::test_policy_dacl_change_during_parse_invalidates_decision
tests/security/test_windows_file_trust.py::test_public_read_is_allowed_but_private_data_read_is_not
tests/security/test_windows_file_trust.py::test_replacement_between_policy_lstat_and_native_open_is_rejected
tests/security/test_windows_file_trust.py::test_windows_path_aliases_are_rejected[ ]
tests/security/test_windows_file_trust.py::test_windows_path_aliases_are_rejected[.]
tests/security/test_windows_file_trust.py::test_windows_path_aliases_are_rejected[:stream]
```
