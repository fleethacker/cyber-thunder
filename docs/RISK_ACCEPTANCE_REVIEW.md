# Independent review of the risk-acceptance future candidate

Reviewed candidate: `a509e763651428fa405c47b02d40873ba4b0ffb5`.
Scope: that candidate's changed feature files and tests, its risk-acceptance contract,
and the supplied VAL-05 verification receipt. Release integration is separate.

## Finding and correction

**P3 — Bind acknowledgement to the account that fetched the evidence.**
In `cyberthunder/ui/src/components/FindingReviewPanel.tsx`, the acknowledgement
handler assigned the current global authority revision to the draft even when the
displayed evidence had been loaded under an earlier authority revision. A second
account or permission change after refresh could therefore let a retained checkbox
adopt that new authority and submit without another refresh. The same handler serves
risk acceptance and ordinary review.

The component regression reproduced an outgoing submission for each decision type
when none should have occurred: **11 passed, 2 failed** before the fix. The corrected
panel retains the authority revision alongside the fetched review, checks it at
submission, and binds acknowledgement to the revision captured by that checkbox's
render. An old checkbox also cannot acknowledge a later account's refresh. Both
cases now require a fresh load and explicit acknowledgement before one submission.

This is a component guard defect, not a demonstrated server authorization bypass.
The outer `IdentityBoundary` normally remounts children when authority changes, and
the server independently checks the current principal and resource grant. The
regression exercises retained handlers directly to cover the panel's own contract;
it is not an end-to-end browser or identity-provider reproduction.

## Bounded backend review

No additional backend defect was confirmed in the inspected paths. The review and
selected regressions cover these boundaries:

| Boundary | Evidence checked |
|---|---|
| Distinct authority | `risk.accept` is a human approver operation, separate from `review`; the ACL requires an exact issuer/subject entry with explicit target and environment selectors. Group, wildcard, omitted, node and associated-account grants do not confer it. |
| Current decision authority | Accept and revoke require configured fresh assurance in verified mode. Current principal/session, role, grant and persisted ownership are rechecked after pending audit and before persistence. Prior receipts only attribute decisions. |
| Input and expiry | Reason, acceptance evidence and a future expiry of at most 30 days are required. A new independent test advances time to expiry during pending audit and confirms no persisted decision on either backend. |
| Lifecycle | Revision/fingerprint checks and shared lifecycle locks protect decision, proposal and final apply boundaries. Existing publication regressions cover process contention, evidence changes, disappearance, recurrence and ownership transitions. |
| Remediation | Active acceptance holds manual/automatic proposals, policy eligibility and final apply, including acceptance during capture. A new independent test verifies that a held finding still permits authorized rollback and restores the fixture target. |
| Scanner/report claims | Acceptance leaves raw scanner evidence, severity, open/pass counts and checklist status intact. Reports show a separate accepted-risk count and hold. Expired/reopened/revoked filter facets may overlap an ordinary disposition and must not be summed as disjoint categories. |

The two new backend tests passed without changing backend production code. They
strengthen coverage of expiry at the mutation boundary and rollback while held.

## Independent verification

Exact command arrays, working directories, source hashes, logs and result receipts
are retained in `.build/risk-acceptance-review/`. Earlier failed receipts remain
intact, including the original candidate's receipt and this review's UI reproduction.

Counts are independent per run; overlapping selections and operating systems are
not summed. Python run counts include both JSON and SQLite, not that many cases
per backend.

| Run | Passed | Failed / errors / skipped | Receipt |
|---|---:|---|---|
| UI reproduction before fix | 11 | 2 / 0 / 0 | `ui-before.txt` |
| Windows backend probes | 70 | 0 / 0 / 0 | `windows-probes-before.xml` |
| UI panel after fix | 13 | 0 / 0 / 0 | `ui-after.txt` |
| Windows final bounded selection | 649 | 0 / 0 / 0 | `windows-final.xml` |
| Native Linux final bounded selection | 649 | 0 / 0 / 0 | `linux-final.xml` |
| Final affected UI selection | 58 | 0 / 0 / 0 | `ui-final.txt` |
| TypeScript 5.6.3 forced project check | exit 0 | no test count | `tsc-final-command.json` |

Windows used Python 3.12.10; Linux used Python 3.12.16 on ext4. Each final Python
run emitted 665 existing dependency/API lifecycle deprecation warnings. The UI
run also retained the runtime's experimental localStorage warning. No assertion
was weakened to accommodate these warnings. All 2,378 pre-existing `.build`
evidence files were checked against their original SHA-256 hashes and are intact.

The tested source inventory contains 1,072 tracked files. Its SHA-256 is
`66ccb5cb10cca87aca30f6f54b6c5003b5ae5c1acbc50eb1c55b950d87d5f524`.
This digest hashes the compact, sorted JSON map of relative path to file SHA-256;
it is not a Git tree ID and uses a different aggregate format from the source
candidate's receipt. `tested-source.json` records every file hash. The final review
document is added after testing; tested implementation and test bytes are unchanged.

The Python selection is explicitly listed in `selections.json`: review identity,
review lifecycle, risk authority, risk decisions, proposal/apply holds, preview,
assurance/report projections, and affected review/query API modules. Both JSON and
SQLite are enabled. Linux uses a separate native source tree and native fixtures;
no Windows-path symlink is used for source or tests. UI verification uses the eight
affected module selections in that same file and a forced TypeScript project check.

## Limits and disposition

- Development mode intentionally permits unverified fixture decisions, as documented
  in the candidate. These tests do not establish official risk authorization or
  zero-trust compliance.
- The existing audit/document crash window remains: a pending audit may have no
  saved decision, or a saved decision may lack the final success entry. Event IDs
  permit correlation; this review does not introduce recovery or a new transaction model.
- Expiry is evaluated at read/action time; reads do not append expiry events.
  Evidence invalidation is durable through scan publication. An executing target
  command is not cancelled by a later risk decision.
- Fixtures and in-process HTTP only. No live target or external identity provider,
  full gate, production UI build, deployment, push or merge was performed.
- Changes are confined to the review panel, its regression tests, the two feature
  test modules and this document. Global backlog, README, CI, distribution and
  other release work are outside this review.

The confirmed component defect is corrected. This bounded review is not release
approval; integration and any required release gate remain separate.
