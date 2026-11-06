# Person-association implementation review

Review baseline: `9bab76a9940a574d734767c96118d48cb1e887f7`.
Reviewer and change author: Joshua Ott <Joshua.ott@outlook.com>.
Review date: 2026-11-06.

## Findings and fixes

1. **Audit evidence accepted equal-valued JSON type changes.** Python container
   equality treated integer authentication timestamps as equal to floats, and
   assessment booleans as equal to integers. An altered voter principal, final
   decision principal, or proposal assessment could therefore retain checked
   historical evidence. The same comparisons allowed those records through the
   gate. This affected account and mapped-person proposals. Canonical JSON
   digests now compare audited receipts, final principal evidence and assessment
   associations, including freshly read assessments. This closes an evidence
   integrity gap; the reproduction did not substitute another person or grant
   an unauthorized account permission.
2. **The UI counted malformed account evidence.** Matching absent issuer/subject
   values could compare equal and produce a displayed mapped-person vote.
   Non-string values could also become account keys. The helper now requires
   nonempty string account identifiers before accepting their association.
   Backend validation already refused these records. The UI still does not
   establish a current user's mapping or grant execution authority.

The baseline Windows regression reproduced the first finding with **12 failures
and 2 passes**, across both document backends and both policy versions. The UI
reproduction had **1 failure and 10 passes** after dependencies were copied.
Those are reproduction results, not final validation totals.

## Reviewed boundaries

- Explicit `(namespace, person_id)` associations exclude proposer aliases and
  duplicate voters, including across explicitly mapped issuers and concurrent
  gate instances. Display names, email, groups and identical subject strings
  across issuers do not establish a person association.
- The protected parser rejects ambiguous mappings and group person IDs. Account
  roles, grants, target visibility and credential selection remain separate.
  The existing `_load()` return contract and immutable source observation are
  preserved; no access, principal, claim or credential implementation changed.
- Creation pins complete policy bytes, requirements and proposer association.
  Vote and application boundaries recheck current policy, findings, vetted fixes,
  assessments and authority. Missing callbacks, mapping changes and v1/v2
  switches fail closed. Legacy records are not upgraded.
- Historical validation checks recorded evidence without creating an active
  session. Current policy/source compatibility and current apply authority remain
  separate. Reports retain disputed evidence while refusing to certify it.
  Target generation changes still prevent application, even when historical
  person-bound receipts remain intact.
- Version 1 retains an honest account-quorum label. Version 2 counts recorded
  mapped people; browser counts and old receipts do not identify the current
  session's person. Existing API response and requirements fields are retained.

## Verification

Native Linux Python 3.12.16: **507 passed, 1 skipped, 0 failed/errors**
in 476.17 seconds. Receipt: `.build/person-review-linux.xml`; output:
`.build/person-review-linux.txt`. The sole skip is
`tests.security.test_access_file_trust.test_actual_windows_junction_parent_denied`
(requires Windows NTFS junction support). POSIX protection tests passed.

Windows Python 3.12.10: **496 passed, 12 skipped, 0 failed/errors**
in 776.04 seconds. Receipt: `.build/person-review-windows.xml`; output:
`.build/person-review-windows.txt`. Its exact skipped cases are:

- `tests.security.test_access.test_fifo_is_rejected_without_opening_or_waiting`
  (requires POSIX FIFO).
- `tests.security.test_access_file_trust.test_posix_policy_write_permissions_denied[400]`
- `tests.security.test_access_file_trust.test_posix_policy_write_permissions_denied[386]`
- `tests.security.test_access_file_trust.test_posix_policy_write_permissions_denied[438]`
- `tests.security.test_access_file_trust.test_posix_policy_write_permissions_denied[950]`
- `tests.security.test_access_file_trust.test_posix_writable_parent_denied[504]`
- `tests.security.test_access_file_trust.test_posix_writable_parent_denied[455]`
- `tests.security.test_access_file_trust.test_posix_untrusted_owner_denied[file]`
- `tests.security.test_access_file_trust.test_posix_untrusted_owner_denied[parent]`
- `tests.security.test_access_file_trust.test_posix_permission_change_during_parse_denied`
- `tests.security.test_access_file_trust.test_posix_root_sticky_directory_exception_never_applies_to_file`
- `tests.security.test_access_file_trust.test_posix_parent_swap_to_symlink_before_open_denied_and_fds_closed`

The eleven file-trust skips require POSIX ownership, modes and descriptor-relative
filesystem semantics. Every person-specific regression ran on both platforms.
Each platform collected 508 distinct cases. Both runs reported 41 existing
Starlette/FastAPI deprecation warnings and no thread warnings. The machine-readable
counts and exact skip reasons are in `.build/person-review-receipt-summary.json`.

Both Python runs select the same nine test modules and explicitly enable JSON
and SQLite. The tests use local fixtures and deny target/external connections.
No model, running server, identity provider or live target is required.

The final native Linux run uses copied source on the Linux filesystem, verifies
its source-file hashes, and sets `PYTHONPATH` to that copy. The final source
manifest excludes release package archives and vendored wheels. Windows
uses an explicit `PYTHONPATH` pointing to the review checkout.
Platform/import evidence is in `.build/person-review-linux-environment.txt` and
`.build/person-review-windows-environment.txt`; the 915-file source manifest is
`.build/person-review-source-manifest.json`. Counts describe this review only,
are not added across platforms, and do not include the baseline's earlier runs.

UI verification: **419 passed, 0 failed, 0 skipped** in the complete test run;
TypeScript project checks and the production build passed. Build output is
`.build/person-review-ui`; the integrated distribution is left to integration.
The focused UI rerun (**15 passed**) overlaps the complete run and is not added
to it. Receipts: `.build/person-review-ui.txt`,
`.build/person-review-ui-focused.txt`, `.build/person-review-typecheck.txt`,
and `.build/person-review-build.txt`.

## Scope and remaining limits

Production changes are confined to `control/separation.py`,
`control/approvals.py` and `ui/src/lib/proposalApprovals.ts`. Regression changes
are in `tests/security/test_person_association_review.py`,
`tests/report/test_person_approval_evidence.py` and
`ui/src/lib/proposalApprovals.test.mjs`, plus this review document.
The original callback installation and unrelated transport startup are intact.

Correct association provisioning remains a trusted operator responsibility.
These tests do not prove a real-world person's identity, live IdP acceptance,
production provisioning authority or enclave readiness. No mapping grants or
combines privileges. A trusted administrator restoring exact prior policy bytes
can make an otherwise unconsumed proposal compatible again; there is no monotonic
policy ledger. Audit checkpoints, runtime integrity and provisioning remain
trusted. Policy checks are not an atomic transaction with remote execution and
cannot recall a command already issued. See [PERSON_ASSOCIATION.md](PERSON_ASSOCIATION.md)
for the cancellation and re-proposal procedure.

No push, full release gate, parent-tree edit or frozen-tree edit was performed.
