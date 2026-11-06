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

## Filtering and observation-time ordering

`GET /api/v1/findings?reassessment=not_reassessed,unknown&sort_by=observed_at&sort_dir=asc`
selects either reassessment state and orders the matching observations from oldest
to newest. `reassessment` accepts `not_reassessed`, `no_known_gap`, and `unknown`,
using the same CSV, OR-within/AND-across filter semantics as the other finding
filters. Invalid values or sort directions return `400` with a string `detail`.

The list derives this exact `ReassessmentView` for every authorized observation
before reassessment filtering, sorting, or pagination. `total` counts matches;
`unfiltered_total`, `summary`, and `facets.reassessment` describe the entire
authorized selected view. An empty page or a filter with no matches still has
the full-view facets. Named historical views keep their existing whole-run read
requirement and cutoff, including when no rows match.

`sort_by=observed_at` compares the helper's `observation.observed_at` instants,
normalizing time zones. Unknown, invalid, and timezone-free observation times
stay last in both directions. Ties always use finding ID ascending, including
unknown-time rows. `sort_by=collected_at` remains the separate, existing
collection-time sort. Reassessment states do not change either recorded time.

The UI names the filters **Not reassessed**, **No known gap**, and **Unknown**.
No known gap does not establish freshness, complete coverage, or a current pass.
It offers **Observation time** and **Collection time** as separate sorts and uses
the API annotations and facets directly. Filters and sorting persist with
existing browser preferences, scoped separately for each signed-in account;
development-mode preferences retain their existing keys. Clear filters and quick
views clear reassessment selections; Reset defaults also restores priority order.
Old servers without the reassessment facet pause these controls while retaining
saved preferences. Selected states missing from a new view remain clearable at zero.

Only returned rows receive explanation, fix, and proposal decoration. History is
rechecked after those reads; revoked history rebuilds selection, counts, and page
boundaries. Revoked off-page findings are removed and the entire authorized view
is rebuilt, including summary and facets. Revoked access to a decorated page
finding or the whole previously readable view fails the response closed.
Queries initiate no explanations, proposals, scans, or persistence. The helper
algorithm, original scanner result, confidence, reviews, and approvals are unchanged.

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
accounts. The shared query layer uses these annotations for the complete authorized
view before filtering and pagination; no new storage backend or index is added.

## Validation and limits

The focused tests cover JSON and SQLite persistence, failed/missing/unstarted
collection, empty success, partial scans, carried rows, fresh observations,
historical views, timestamp uncertainty, unrelated scopes, account denial,
mixed-target runs, revoked grants, target reassignment/reuse, immutable evidence,
false-positive reviews, approved/verified proposals, and rollback semantics.
UI tests render the panel and drawer, exercise the table integration, and check
accessible controls, missing metadata, escaping, and unchanged decision controls.

The query follow-up tests JSON/SQLite combined filters, complete-view counts and
pagination, account-specific visibility, revocation during storage/history/page
reads, historical cutoffs, observation-time ties and unknown times. UI interaction
tests cover persistence, reset, account changes, unavailable features, and late
responses. Query receipts (commands, logs, JUnit XML, and source hashes) are kept
under `.build/reassessment-query/`. Validation is focused, not a full release gate
or a general performance claim. Dedicated cluster/import reassessment and
additional producer mappings remain open in BACKLOG UI-04.

Independent combined-tree query review adds final-page history revocation and
repeated grant changes on both backends. Page authorization precedes the final
history derivation, including when only mixed-run history authority changes.
The query permits four rebuild attempts, then returns a sanitized `409` without
rows or aggregate metadata if authority continues changing. Separate fixtures
check every facet against a new authorized query after off-page grant revocation
or target-generation replacement, including filtered-out rows and page shifts.
Real browser validation mounts the findings page and account boundary, exercising
controls, counts, pagination, saved preference reset, forged values, and a delayed
response across an account switch. It uses intercepted fixture HTTP responses;
API authorization is tested separately with real fixture policies and stores.
Original failures, source hashes, logs, and browser receipts are retained under
`.build/reassessment-query-review/`. This remains focused validation; it does not
establish production performance or complete the open producer mappings.

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
