# Finding reassessment history

The findings list and detail APIs include a read-only `reassessment` field.
It explains why an older observation remains visible after
a later target scan could not reassess it. It does not change scanner status,
observation time, evidence, confidence, review fingerprints or validity, risk
acceptance, proposal permissions, approvals, or rollback interpretation.

The Findings table shows **Not reassessed** beside the API's original observation time.
Its keyboard-accessible button and the finding detail panel show the original
observation time/source separately from the later scan's recorded start time and
target outcome. A missing timestamp is never replaced with the page load time.
An omission is neither a verified fix nor a false-positive decision.
The original collection time remains in the detail header. Older servers without
the new field retain their recorded collection-time display; an explicitly
unknown observation time from the new API stays unknown.

## API contract (version 1)

`GET /api/v1/findings` and `GET /api/v1/findings/{id}` decorate each returned
finding with:

```json
{
  "reassessment": {
    "version": 1,
    "status": "not_reassessed",
    "reason": "partial_collection",
    "explanation": "The later scan collected only partial results and did not reassess this observation.",
    "observation": {
      "observed_at": "2026-11-05T10:00:00Z",
      "source": "native",
      "scan_id": "original-scan"
    },
    "latest_attempt": {
      "scan_id": "later-scan",
      "started_at": "2026-11-05T11:00:00Z",
      "finished_at": "2026-11-05T11:01:00Z",
      "target_status": "partial"
    },
    "view": "current"
  }
}
```

`not_reassessed` means a later completed attempt in the readable, relevant history
omitted this observation. Reasons distinguish unavailable collection, incomplete
or unstarted target assessment, partial collection, and retained omissions.
`no_known_gap` means no such gap was established; it does **not** assert freshness,
coverage, or a current pass. `unknown` means ordering, scope, or coverage cannot
be established. Only `not_reassessed` includes `latest_attempt` and an orange row
badge. Unknown and absent server support have explicit detail text.

`observation.observed_at` uses recorded `collection_provenance.observed_at` when
present, otherwise `collected_at`. Invalid or timezone-free values are unknown.
Original `collected_at`, `source`, and `scan_id` remain unchanged. The added
observation scan ID is included only if that entire run is readable and belongs
to the same persisted target generation.

## Scope and ordering

- The helper uses the existing persisted artifact ownership and account read
  checks. Both the finding and the complete candidate run must be readable.
  Mixed-target runs are excluded when any constituent target is inaccessible.
  Current inventory IDs cannot relabel historical evidence. Deleted, moved,
  recreated, unclassified, or mismatched target generations do not grant history.
  Named detail views enforce the same whole-run boundary as named list views.
  After loading observations, the helper rechecks every run that influenced the
  page's answers, including origins, cutoffs, and tied candidates. Revoked runs
  are removed from the request-local index and the entire page is derived again,
  so revocation while processing a later row also invalidates earlier badges. The API
  also rechecks finding and named-history authority before returning the response.
- Runs must name the same target and ownership scope, include the relevant
  module, and match the finding's rule ID, rule version, group ID, or citation
  when restricted by `rule_filter`, following the scanner's selection semantics.
  A host scan has no authority over independent cluster image
  survey evidence, bulletin-only processing, or scanner imports.
- Supported collection triggers are `manual`, `scheduled`, `stig_delta`, `verify`,
  and `demo`. Known native/check sources map to `check`, `hunt` to `hunt`, and
  `cve`/host `trivy` to `cve`. Unknown producers remain unknown instead of being
  guessed from title text or severity.
- Terminal runs are ordered by timezone-aware start times after both the actual
  observation and collection times (and its readable source run). Running and
  pending runs do not assert completed reassessment. Equal latest times produce
  unknown ordering, including in named historical views; selecting an ID does
  not establish which of two equally timed runs came first.
- An explicit `scan_id` bounds history at that run's start, including that run
  itself. Later scans cannot change the historical badge. A carried row retains
  its original identity/time and does not count as a new observation. A new
  observation within a partial run supersedes that finding normally. Both its
  collection time and actual observation time must be at or after that attempt's
  start. Repackaging older evidence under a newer scan ID does not clear the gap.

## Scheduler integration boundary

The helper reads `ScanRun.targets`, `authorization_scopes`, `modules`,
`rule_filter`, `trigger`, `started_at`, `finished_at`, `status`, `results`, and
`coverage_incomplete`. It understands `scheduling.unavailable_targets`,
`scheduling.partial_targets`, and
`scheduling.omitted_observations = retain_without_revalidation` from the bounded
worker implementation at base `c27334a`. It does not modify these producers.
The frozen release `a2a33c6`, inspected read-only during independent review,
retains the worker contract introduced by `db489ef` and supplies
`scheduling.retained_incomplete_observations: {target_id: [finding_id, ...]}`.
An exact target/finding match gives reason `retained_incomplete_observation`:
the worker withheld a `not_reviewed` or `error` replacement of prior unresolved
evidence, retaining the original observation exactly. It does not expose the
withheld result or invent its status. Unavailable collection takes precedence;
a published new actual observation is still affirmative evidence. Absent,
unrelated, or malformed lists keep the earlier metadata behavior.

The assembled follow-up at base `e0c4531` includes the worker, reassessment, and
retention implementations. `tests/test_reassessment_worker_integration.py`
executes the real bounded `Scanner.start` path with fixture transports and a
supported `native` finding source on JSON and SQLite. The scanner itself
publishes the run, findings, collector artifacts, and scheduling metadata;
these tests do not manufacture scheduler records. Withheld `not_reviewed` and
`error` replacements, downgraded pass/not-applicable results, partial omissions,
and unavailable collection reach the actual `ReassessmentView` and list/detail
APIs. Original evidence, times, status, confidence, review decisions, proposal
state, and rollback interpretation remain unchanged. A fresh observation in a
partial run is separately exercised without advancing target scan freshness.
An actual mixed-target worker run cannot expand a reader's history authority.
The retention planner reads the resulting state directly and records
`current-observation` pinning for the older unresolved observation's source.
The source also remains incomplete coverage; this does not claim that removing
the observation alone would make it eligible for export.

The earlier independent review used persisted helper fixtures and inspected the
release scanner source read-only; it did not merge or execute that source.
Those historical review receipts retain that limitation. The assembled tests
add execution evidence without extending the earlier independent review's scope.
No release gate, deployment, or immediate-release dependency is introduced.

The helper keeps only a request-local run index and lazily reads each selected
run's observations once. It never creates a state directory, writes a document,
stores credentials, migrates a schema, appends audit records, or caches across
accounts. Existing list filtering, sorting, counts, and pagination are unchanged.

## Validation and limits

The focused tests cover JSON and SQLite persistence, failed/missing/unstarted
collection, empty success, partial scans, carried rows, fresh observations,
historical views, timestamp uncertainty, unrelated scopes, account denial,
mixed-target runs, revoked grants, target reassignment/reuse, immutable evidence,
false-positive reviews, approved/verified proposals, and rollback semantics.
UI tests render the panel and drawer, exercise the table integration, and check
accessible controls, missing metadata, escaping, and unchanged decision controls.

This batch deliberately adds no reassessment filter or sort: a correct global
facet requires deriving every visible row before existing query pagination,
which belongs to the shared query layer outside this batch's file ownership.
The existing collection-time sort stays available; it does not sort provenance
observation times or reassessment state. A follow-on query change
should consume this exact helper and test complete-view counts and pagination;
it must not infer status or timestamps in the UI. Dedicated cluster/import
reassessment and additional producer mappings also remain follow-on work.
These remaining query and producer capabilities are tracked in BACKLOG UI-04.

Implementation receipts are retained under `.build/finding-reassessment-next/`
in the implementation worktree. Independent review receipts are retained under
`.build/finding-reassessment-review/` in the review worktree. They bind tested
source and generated UI files to SHA-256 hashes. Negative calibration reproduces
whole-run detail authorization, revocation during history reads, pre-attempt
evidence, and named-view timestamp-tie defects on the unmodified candidate.
Validation uses fixture state only; it does not contact target hosts or
production systems. Assembled worker integration receipts are retained separately
under `.build/reassessment-integration/`, including exact commands, logs, JUnit
XML, and source SHA-256 manifests. The new module passes 24 cases on Windows
Python 3.12.10 and the same 24 cases on native Linux Python 3.12.16, run serially
on CPU 3. Each run covers 12 JSON and 12 SQLite cases, with no failures or skips.
It executes the assembled scanner source against injected collectors; it does
not validate live transport behavior, a full release gate, or the combined
release head.
