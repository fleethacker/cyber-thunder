# Content publication independent review

Reviewed implementation `6c8df074aea8521d59ba3428d0ab790ffad840d0` as integrated at `f5b74c0135f182ccb1222b793052c13fd6e5bc43`, on the dedicated review branch. Scope: immutable content publication and its local import/UI boundaries. Implementation receipts were read from the separate windows-policy-trust worktree; they are historical evidence, not this review's acceptance results.

## Confirmed defects and fixes

1. **Conflicting release claims (P1).** A candidate with version `V2R13` or `002.013` and internal `Release: 11` activated over an accepted release 12 through upload, folder import and direct STIG import. The version parser now rejects contradictory recognized release-info claims. Consistent integer, DISA-pair and padded-pair spellings still upgrade normally. Refused imports leave the ledger unchanged.
2. **Incomplete activation map (P1).** Removing an active-lineage reference left its accepted publication and floor intact but allowed catalog lookup to fall back to legacy bytes. Readers and writers now require a reference for every previously activated lineage, and every member of an active multi-benchmark package must point to the same generation. Missing references and split SCAP generations require recovery.
3. **Stale upload operations (P2).** A pending batch sent its next file after same-account reauthentication, file selection changes or unmount. Batches now bind to the current authority and selection/view lifetime. Their own successful library refreshes may advance the generation without stopping the batch. Late exceptional upload/folder responses cannot replace the new view or reuse confirmation.

## Calibration and acceptance

Before production changes, the new backend reproductions failed **14/14** on Windows (both JSON and SQLite), and the three new UI cancellation regressions failed while the existing 17 publication tests passed. Final regression coverage adds 22 backend cases and eight UI cases, including positive controls.

| Module | Windows 3.12 | Native Linux 3.12 |
| --- | ---: | ---: |
| `tests.ingest.test_content_publication_review` | 22 | 22 |
| `tests.ingest.test_content_publication` | 94 | 94 |
| `tests.ingest.test_content_uploads` | 201 | 201 |
| `tests.ingest.test_content_library` | 30 | 30 |
| `tests.ingest.test_content_authenticity_review` | 31 | 31 |
| `tests.ingest.test_step_up_transfers` | 30 | 30 |
| `tests.api.test_content_library` | 10 | 10 |
| `tests.api.test_scap_review` | 11 | 11 |
| Total | 429 | 429 |

Both backend runs: **0 failures, 0 skips**. UI: **47 passed, 0 failed, 0 skipped**. TypeScript no-emit compilation passed. UI tests use the component hook harness, actual client serialization and real Mantine server rendering; no interactive browser acceptance is claimed.

The publication module includes abrupt child-process exits, competing directory/direct/upload writers, pinned readers, exact and historical retries, one-use review/session binding, audit-before-activation failures, uncertain ledger writes and pending postcommit bookkeeping. The selected authority tests cover revocation and transfer step-up continuity. The integrated SCAP route review module was included as a narrow seam check. No separate feature edits were made there.

Windows: `3.12.10`, shared coverage-report interpreter, frozen source copy and the existing protected disposable Windows fixture setup. Linux: `3.12.16`, the requested native venv, source `/home/joshua/ct-content-review-9o0_unzt`, filesystem verified ext4. Linux pytest state is under that directory's `.pytest-state`; general temporary files are under `.temporary`. No packages were installed.

Both runtime copies verified **907 source/fixture files** before and after testing. The checkout matches those same hashes. UI manifest covers **141 files**. Earlier **24 CLI receipt/artifact files** remain hash-identical.

- Source manifest SHA-256: `567be78369a5cffec999c9b85b349b9a72f791e2661552ce9762974267809e73`.
- Source archive SHA-256: `8498b1c33f412dfe4eb6b4e9c42059dfc52aa5d29a8d1e58cd8b527bfa2a08c3`.
- UI manifest SHA-256: `446cdca6807e6e35461e96b13cfeb6233b382245968b4f0d81fd929567983a84`.
- Detailed counts, runtimes and commands: `.build/content-review-receipt.json` and `.build/content-review-run.py`.
- Backend receipts: `.build/content-review-final-windows.xml` / `.log` and `.build/content-review-final-linux.xml` / `.log`.
- UI and TypeScript receipts: `.build/content-review-ui-acceptance.log`, `.build/content-review-tsc.log`.
- Initial negative calibration: `.build/content-review-calibration-windows.xml` / `.log` and `.build/content-review-ui-calibration.log`.

An intermediate UI positive control checked completion before nested refresh promises settled; its bounded harness wait was corrected. Linux preparation first rejected tmpfs. A second run used an ext4 source copy but default temporary fixtures; it was stopped and discarded. Only the final run with explicit ext4 source, pytest and general temporary roots counts as acceptance. Diagnostic receipts remain in `.build`.

## Limits and handoff

This is a bounded review, not a full gate or a production acceptance decision. It does not add general ledger repair, detect privileged local tampering or whole-state rollback, establish power-loss durability, or validate SMB/ReFS/domain deployments. Missing activation references now fail closed and need controlled recovery. In-flight requests can commit before the client changes views; the replacement view must reconcile the library. Source signatures and explicit review do not establish the newest publisher release.

No real network content, cluster changes, global CI edits, dist build, push or merge. The parent owns combined validation and PR publication. Changes are limited to content publication/parser logic, ContentUpdates, dedicated regressions and this documentation. Commit author and committer are Joshua Ott <Joshua.ott@outlook.com>, without trailers.
