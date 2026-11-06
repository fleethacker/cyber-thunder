# Independent recovery timeline review

Reviewed candidate `efa9ccdb8f8cf9a957dc9c79ff2342452f8f6ca0` against base `799aac915a321d78cbb28f5adb6e38fcba756a88` on 2026-11-06. Repairs affect only the candidate's six paths and this report.

## Findings and disposition

| Finding | Evidence and repair |
| --- | --- |
| P2: prior verification appears current after incomplete recovery | A VERIFIED proposal can undergo a manual rollback that fails or stops without changing its saved state. The candidate qualifies verification only after confirmed restoration. Earlier verification now explicitly says it is historical and the current target state is unconfirmed after later failed, blocked or incomplete recovery too. |
| P2: old success masks newer contrary evidence | The candidate combines any saved or recorded verification success with the latest check using an unconditional success preference. Newer failed, manual or incomplete checks now control the displayed result and receipt badge. An older rollback transition likewise cannot mask a newer failure or attempt. Audit sequence wins over conflicting milestone timestamps. Tests include conflicting/legacy records; they do not assert that the current engine permits arbitrary repeat transitions. |
| P2: malformed or mismatched evidence crashes or confirms a milestone | Null records/history entries crash the candidate; invalid sequence types and contradictory proposal/target/finding bindings can supply success evidence. Runtime envelope validation, binding checks and conservative result handling now reject these inputs. A malformed rollback result cannot assert a successful start. |
| P2: conflicting fetch/stream copies silently choose success | The candidate cache selects one record per sequence. Conflicting copies are now retained and quarantined on read. Equal content with a different object key order remains valid. Contradictory success bodies do not prove success. |
| Account-switch concern: not reproduced through the actual parent | `IdentityBoundary` uses `authorityKey(identity)` as its provider key. That key includes principal identity, roles, permissions and session binding. `main.tsx` places `AppStateProvider` and the application below it. The real browser fixture confirms proposal switches, account switches, permission revocation, late responses and stale stream callbacks clear or reject earlier audit details for the same proposal. No identity or global authentication edits were needed. |

The implementation preserves successful capture receipts, recorded application, verified history, manual verification, and successful manual/automatic rollback receipts. It does not infer completion from an allocated snapshot path, a generic failure, or runbook issuance. Recovery actor labels come from recovery evidence.

## Validation and calibration

- Unmodified candidate: **47/47 passed** with locally available dependencies matching its lockfile.
- Added regressions against an archived copy of the unmodified candidate: **16 failed, 2 passed**. The complete calibration is in `calibrated-candidate-52.txt` (36 passing tests including the candidate's original 34, and 16 failures). The two passing additions are a newer successful verification and the real identity boundary test.
- Repaired focused UI suite: **91/91 passed, zero skipped**: 52 timeline tests, 13 existing history/rendering tests and 26 existing rollback guard/confirmation tests.
- Forced TypeScript check: `tsc -b --force` passed with no diagnostics.
- `git diff --check` passed. No release gate, distribution build, Linux broad suite, real target operation, push or merge was performed.

The first baseline attempt used an older dependency directory and failed to import an existing router export. That infrastructure failure is retained in `candidate-focused.txt`; `candidate-matched-focused.txt` is the valid baseline. The first offline browser fixture omitted automatic JSX compilation; the diagnostic and corrected runs are retained separately. Neither harness issue is counted as a candidate defect.

The browser check runs real React, Mantine, `IdentityBoundary`, `AppStateProvider`, `ApplyTimeline`, and the API client's authority checks. It bundles in memory, mounts into an empty browser page, mocks fetch and EventSource, and blocks browser requests. It uses actual button clicks and asserts zero unexpected requests, zero page errors, GET-only fixture I/O, and closed old streams. The test requires local module URLs in `CT_PLAYWRIGHT_MODULE` and `CT_TIMELINE_BUNDLER_MODULE`, with `CT_PERMISSION_BROWSER` selecting a local Chromium executable. Without the module variables, this one explicit browser test is skipped.

Focused command from the repository root, with those variables set:

```powershell
& 'C:/Program Files/nodejs/node.exe' --test --test-concurrency=1 cyberthunder/ui/src/components/ApplyTimelineRendering.test.mjs cyberthunder/ui/src/components/ApplyTimelineAudit.test.mjs cyberthunder/ui/src/lib/proposalTimeline.test.mjs cyberthunder/ui/src/components/RollbackHistoryRendering.test.mjs cyberthunder/ui/src/lib/proposalHistory.test.mjs cyberthunder/ui/src/components/RollbackGuard.test.mjs
```

TypeScript command from `cyberthunder/ui`:

```powershell
& 'C:/Program Files/nodejs/node.exe' node_modules/typescript/bin/tsc -b --force
```

## Source fingerprints

SHA-256 of the tested source bytes (paths relative to `cyberthunder/ui/src`):

| Source | SHA-256 |
| --- | --- |
| `components/ApplyTimeline.tsx` | `EF21CBD4D7A3A7C80EEB1AC394A9AACF4B6710C23738D0428B079AAAD7351BAD` |
| `components/ApplyTimelineAudit.test.mjs` | `803DEEECC697790D6F8CD6384C64D9FE43814FD183F01F61E39D06CB65455476` |
| `components/ApplyTimelineRendering.test.mjs` | `94CB9BBB94DFE83ADADFC7ED9A51CAC174756A29327BC36FD0260006D0BB3F00` |
| `lib/proposalTimeline.ts` | `218702BC2CFCBE2D5D8AA42762724D9EADB3FD130D7EAC805DEA691C7F3A20F8` |
| `lib/proposalTimeline.test.mjs` | `76975C35D00AF73077C1F9DDF43E551DA12E3112329B9DE4CD1BB5D345848A05` |

## Evidence, cleanup and limits

New evidence is isolated under `.build/recovery-timeline-review-12868a8d9ea443adbd87a617d6e851f0/`. The prior recovery-timeline evidence directory is unchanged. The new directory preserves baseline and regression logs, a candidate source archive, final test/typecheck logs, and a source manifest. Temporary dependency junctions and local TypeScript build-info files are removed after validation; the test browser is closed and no server is started.

No known in-scope issue remains. Timeline labels report available historical evidence, not cryptographic audit verification, snapshot validity, live target state or worker liveness. Missing/truncated audit data and histories without comparable dates limit ordering; uncertain outcomes stay pending. Separate frozen release gates and the single distribution build remain the integrating parent's responsibility.
