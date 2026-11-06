# Recovery timeline evidence

The proposal timeline displays saved milestones and specific audit receipts. It does not track a live worker. Unknown stages remain pending, with neutral bullets; a later known milestone does not turn earlier unknown stages green.

## Defect reproduced

Six rendering regressions failed against the original timeline:

- A failed proposal with only an allocated snapshot path reported a completed capture and active rollback.
- Maintenance and authorization stops before payload execution appeared to trigger recovery.
- A post-apply capture failure appeared as a verification failure.
- An issued runbook appeared as applied work with verification running.
- A saved verified state incorrectly implied a completed capture without capture evidence.
- An old rolled-back record without actor evidence was attributed to an operator.

## Evidence rules

| Stage | Display evidence |
| --- | --- |
| Apply start | Saved applying state/history or successful `proposal.applying`; never a claim that scope remains authorized or a worker is currently running. |
| Before-state capture | Exact successful `remediation.before_state` receipt. A snapshot reference, failed state, or unrelated snapshot event is insufficient. |
| Application | Applied state/history or successful `proposal.applied` plus the engine's payload completion note confirms the milestone. APPLIED alone is ambiguous because it can also mean runbook issuance. Runbook issuance receipts or the engine's issuance note are labeled as operator steps; a runbook kind alone cannot confirm their completion. |
| Verification | The latest relevant check controls the result: saved verified history, successful `proposal.verified`, or a complete successful `remediation.verify`. Newer failed, manual or incomplete receipts cannot inherit older success. Audit sequence orders receipts; an independently newer dated history entry can fill an audit gap. |
| Verification failure | A specific failed/error verification receipt or the engine's explicit failed-rule note. Generic `error during verify` notes remain under change failure because post-apply capture errors use that wording too. |
| Rollback | Saved rolled-back state/history, successful rollback transition, or a successful rollback result confirms the milestone unless newer evidence supersedes it. Start/mutation records alone have an unknown outcome. Failed results, rollback errors and blocked recovery checks are not active recovery. Earlier verification is historical after these outcomes too. |
| Attribution | Only the rollback record/history actor is displayed. Approval actors and inferred manual/automatic classifications are not used. |

`execute()` in `cyberthunder/remediation/engine.py` allocates the snapshot reference through `start_apply()` before capture. It saves `before_state.json` using `cyberthunder/remediation/snapshot.py`, then emits the successful capture receipt. Later post-apply capture runs before the verification step, but its exception can still receive the generic verification error note. Runbook issuance records APPLIED without executing the operator steps. These existing semantics are unchanged.

Audit records are filtered by the exact proposal at stream admission, cache read and timeline construction. Conflicting proposal, target or finding bindings cannot supply evidence. Malformed envelopes and conflicting copies of the same sequence are excluded; equivalent objects with different key order remain usable. Fetch and stream copies are retained together so a conflict cannot be silently resolved into success. Switching proposals immediately hides the previous cache. Late responses are ignored, and fetch responses preserve newer streamed records. An unavailable audit leaves saved history and explicit unknown labels.

The existing identity boundary keys its entire application subtree by account authority, including permissions. Account switches and permission revocation unmount this hook and its stream listener even when the proposal ID is unchanged. The API client independently rejects responses and stream callbacks from an earlier authority revision. The focused browser test exercises those actual providers and hooks with in-memory I/O.

## Focused validation

The tests use real React/Mantine server rendering, pure evidence fixtures and the existing hook harness with in-memory audit I/O. They cover prepayload stops, capture errors, post-apply errors, runbooks, manual checks, verified and rolled-back history, successful automatic/manual rollback receipts, failed/blocked recovery, limited history, unavailable audit, unrelated records and request races.

Validation on 2026-11-06: all 47 focused tests passed (34 new and 13 existing regressions), and forced TypeScript checking passed. All six initial rendering regressions failed on the original component before the fix.

Independent review added 18 tests: 16 reproduce candidate defects, while two preserve a positive verification flow and confirm the existing account boundary. The expanded focused run passes 91 tests, including 26 existing rollback confirmation/click regressions, with no skips when the browser fixture is enabled. Forced TypeScript checking passes. See [the independent review](CHANGE_TIMELINE_REVIEW.md) for calibration, source hashes and limits.

From the repository root:

```powershell
& 'C:/Program Files/nodejs/node.exe' --test cyberthunder/ui/src/components/ApplyTimelineRendering.test.mjs cyberthunder/ui/src/components/ApplyTimelineAudit.test.mjs cyberthunder/ui/src/lib/proposalTimeline.test.mjs cyberthunder/ui/src/components/RollbackHistoryRendering.test.mjs cyberthunder/ui/src/lib/proposalHistory.test.mjs
```

From `cyberthunder/ui`:

```powershell
& 'C:/Program Files/nodejs/node.exe' node_modules/typescript/bin/tsc -b --force
```

The view does not inspect snapshot contents, recover unavailable audit history, verify a live target or prove a worker is still running. Historical verification is explicitly marked after later recovery evidence, including failed, incomplete and blocked recovery. Release gates and distribution rebuilding remain integration checks.
