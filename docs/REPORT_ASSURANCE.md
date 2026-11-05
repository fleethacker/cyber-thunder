# Finding assurance in reports

Commander HTML and Markdown reports and the POA&M CSV read confidence through
`assess_for_context(ctx, finding, now=...)` and review through
`ReviewService(ctx).summary(finding, now=...)`. The confidence wrapper labels known
simulated inventory targets even when older findings have no collection provenance.
Each report evaluates its observations at one timestamp. No report changes scanner
status, grants change approval, or records a review decision.

## Counts and evidence

The commander report distinguishes these counts:

- **Raw scanner open:** every selected observation whose original status is `open`,
  including currently suppressed observations and findings with a verified change.
- **Confirmed:** raw-open observations with an active `confirmed` human review.
- **Unreviewed:** raw-open observations whose effective review is `unreviewed`,
  including expired reviews, changed evidence, and explicit reversals.
- **Suppressed:** raw-open observations with an active, matching, unexpired
  `false_positive` or `not_applicable` review.
- **Needs investigation:** raw-open observations with that active review disposition.

The four review counts are subsets of raw open; they are not extra findings to add
to it. Scanner `not_reviewed`, `error`, `not_a_finding` (pass), and `not_applicable`
are separate counts. An unchecked result or scanner error is never a pass, and an
unreviewed scanner pass is never represented as a human confirmation.

The action table and top risks exclude observations covered by a later verified
change and active review suppressions. The complete evidence section keeps every selected scanner observation,
including suppressed findings, with its original status, severity, source, citations,
evidence, confidence grade/reason, and review. This section may extend the commander
report onto additional pages. The report's pre-existing current discovery supplement
is included and labeled; it is not presented as part of a historical scan.

Review details show effective disposition, active/suppressed flags, last reviewer,
reason, supporting evidence, review time, expiry, fingerprint, and reopening reason.
The last event may describe an expired or mismatching review: its disposition is
labeled separately from the effective review. Every report labels reviewer identity
**Unverified (self-asserted)**. Suppression is explicitly **not remediation**.

## POA&M and scanner checklists

The CSV keeps the existing planning `Status` and adds `Scanner Status` and
`Scanner Evidence`, confidence columns, and review columns. Suppressed observations
remain rows with planning status `Suppressed (review)` and a reassessment milestone.
Unchecked observations and scanner errors remain rows needing investigation, even
when an earlier proposal was verified. Passing observations without a suppression
or verified proposal remain outside the POA&M; the commander evidence section
still includes them. CSV output uses LF line endings.

Review decisions never change checklist statuses to `not_a_finding` or
`not_applicable`. The original scanner artifact is never overwritten.

### Verification timing

`report/closure.py` supplies the same `verified_closure(finding, proposal)` check to
commander, POA&M, and CKLB. An open observation is closed only when its matching
proposal is still verified and the latest verified event has a valid timestamp at
or after the observation's `collected_at`. Equal timestamps are accepted because
stored times have second precision; explicit UTC offsets are compared as instants.
The proposal must match both finding ID and host. No API module is imported.

A newer open observation remains in the commander's action table and top risks,
has POA&M status `Open` with a reassessment milestone, and remains `open` in CKLB.
Missing, malformed, timezone-free, or invalid-offset timestamps leave it open.
Approval and proposal-creation times never substitute for an absent verification
event, and an invalid latest verified timestamp never falls back to an older event.
For POA&M, a raw scanner pass can independently establish completion and is labeled
`Scanner reports not_a_finding`; unchecked results and errors never do.

The proposal's verified event remains in decision history even when a newer open
observation prevents closure. Assurance raw counts, evidence, and reviews remain
unchanged by this timing check.

## History and persistence

An explicit scan ID supplies that scan's original findings to both assessment
services. The report does not look up a current finding merely by its stable ID and
borrow its review. The review service decides whether the latest event matches the
selected observation's evidence fingerprint and scope and is still unexpired.
Identical evidence across scans can keep its decision; changed evidence or benchmark
release cannot. Review validity is evaluated at report generation time, not at the
historical scan timestamp. Saved report history retains the rendered snapshot.

Legacy finding documents require no migration. Review persistence stays behind
`ReviewService` and `StateStore`, so both JSON and SQLite use the same report code.
Builders perform no writes; `ReportService` retains its existing report-history and
audit writes under the configured state directory. No API import, external fetch,
new dependency, or additional filesystem location is used.

## Focused validation

`tests/report/test_assurance.py` runs against the existing JSON/SQLite fixture and
covers counts, suppressed evidence retention, error/unchecked handling, legacy
simulation labels, fingerprint and expiry behavior, checklist preservation,
snapshot retention, read-only builders, and literal review text in HTML/Markdown.
It also checks reopened findings after verification across all three reports,
closure of older observations, and conservative handling of missing/invalid times.
