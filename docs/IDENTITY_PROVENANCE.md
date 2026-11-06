# Review identity and report ownership

Review identity describes who authenticated when a decision was recorded. It does
not establish that a scanner result is correct, that a suppression is remediation,
or that the person's old session is still valid.

## Review records

`ReviewService.save` obtains provenance only from `current_principal()`. A verified
review requires a human principal with review permission, a live session, and an
actor equal to `Principal.actor`. The service rechecks authority immediately before
persisting the decision. Verified mode also checks the finding's original resource
ownership through `security.resources.check_record`.

The event keeps `reviewed_by` as the canonical audit actor and adds
`reviewed_principal`, containing the server principal's credential-free evidence:
`kind`, `iss`, `sub`, `name`, `roles`, `groups`, `scopes`, `via`, `verified`, `acr`,
`amr`, `auth_time`, `expires_at`, and `session_id`. The audit event records the same
snapshot. Request bodies cannot supply identity flags, principal evidence, or actors;
the router forbids extra fields. A typed `X-Actor` cannot replace an authenticated
principal.

Legacy typed labels and development identities retain `identity_verified: false`
and no verified principal. Existing review documents remain readable without a
migration. Stored verified events must contain valid principal evidence whose
issuer, subject, and kind reproduce the canonical actor; a boolean alone is
insufficient. Contradictory, malformed, or mismatched provenance is rejected.

The summary's `identity_verified` describes its `current` (last) event. It may be
true after the decision has expired or been reopened. `active`, `suppressed`, and
`reopened_reason` remain the separate disposition indicators. Changing resource
ownership participates in the review scope/fingerprint, so an old decision cannot
silently apply to a reused target ID.
Summary/current-event and history views include only reviews matching the supplied
finding's original ownership. Old-owner and unstamped legacy events are preserved
on disk, but cannot become reviews of a newly stamped resource. `revision` remains
an opaque concurrency token for the complete document; `history_count` counts only
the returned owner's events.

## Report attribution

Commander HTML/Markdown, POA&M comments, and checklist closure comments show the
recorded display name and verified issuer/subject when the canonical actor binding
is valid. Commander data retains `decided_by` and adds `decision_identity`.
Manual rollback explanations use the corresponding history event's `principal`.
Legacy decisions, including canonical-looking hashes without evidence, are labeled
`Unverified (self-asserted)`.

POA&M keeps its existing columns and the canonical `Reviewed By` value. Its
`Reviewer Identity` field carries the readable verified attribution. HTML and
Markdown escape identity display fields. Stored report snapshots preserve the
content rendered at generation time; opening a snapshot does not reconstruct its
identity from current account state.

Recorded evidence is attribution, not a replacement for signature verification
at authentication or for protecting the state store and audit chain. Reading old
evidence does not reauthenticate an expired token.

## Export authorization

`ReportService` requires node `export`. Each consumed scan, finding, proposal, and
discovery observation must also permit target `export` under its original saved
ownership. Checks run before aggregation/rendering. Lifecycle/audit calculations
require explicit node `audit`; node export does not imply global audit access.
Neither service nor history requires `read.all`.

`report.access` uses the parent `security.resources` contract. Each scope has this
shape:

```json
{
  "version": 1,
  "target_id": "range-01",
  "environment": "range",
  "authorization_id": "server-controlled-target-generation"
}
```

The render collects scopes from actual contributors, including current overlays
and decisions outside the anchor scan. Immediately before publication it checks
the original scopes again and compares `capture(ctx, target_ids)` with those
scopes. Current inventory never supplies a replacement owner for historical data.
Changes, deletions, ID reuse, absent stamps, and mismatched target/stamp bindings
fail closed in verified mode. A combined report requires every contributor's
export grant; it is not silently reduced to a partial report.

Saved snapshots carry `authorization_scopes`. History checks node export and each
snapshot's target export permissions before content search, date/target filters,
totals, pagination, retrieval, or download. An unauthorized snapshot contributes
neither rows nor counts. Legacy imports always retain `authorization_scopes: []`,
even when a same-named target exists today. They remain available in development
mode and inaccessible in verified mode until regenerated from classified data.
Development rendering can retain complete original scopes; one unclassified
contributor leaves the entire export unclassified.

Queue metadata retains the existing fields and adds the original scopes:

```json
{
  "report": "poam",
  "scan_id": "scan-123",
  "host": null,
  "bytes": 1234,
  "history_saved": true,
  "authorization_scopes": [
    {"version": 1, "target_id": "range-01", "environment": "range",
     "authorization_id": "server-controlled-target-generation"}
  ]
}
```

Outbox list/sync authorization belongs to the outbox service. The report layer
rechecks scopes before enqueue and does not read raw outbox totals in a verified
commander report.

## Parent integration seams and limits

- The UI's review event and summary types must change `identity_verified: false`
  to `identity_verified: boolean`; event provenance is optional
  `reviewed_principal`. Do not infer verification from the canonical actor string.
- All routes in `api/routes/reports.py` delegate to the guarded report service or
  history functions. They can use the scoped route policy without a broad
  current-inventory `read.all` gate. Node export and per-contributor export remain
  mandatory; rendering that reads audit also requires node audit.
- The separate `api/routes/workflow.py` target-report builder/retriever is outside
  this change's write set. It must check all input records and the saved report's
  original ownership, then pass `authorization_scopes=...` to `history.save`.
  A new save without classified ownership is intentionally refused in verified
  mode. Merely authorizing today's inventory target does not close the ID-reuse gap.
- Target-scoped checklists currently authorize the complete selected scan and
  proposal inputs. This is conservative and can require grants beyond the selected
  host. There is no automatic historical-record migration.
- Range answer-key scoring refuses unclassified key files in verified mode.
  Classified keys carry `authorization_scopes` covering their `target` and optional
  `sim_target`. Orphan rollback audit records need their own ownership scope;
  results attached to an immutable, authorized proposal inherit its ownership.
- Fleet/friction documents and coverage catalogs are node content, not historical
  target observations. Rendering them requires node export and audit. Queueing a
  report with no target scopes is refused in verified mode until an explicit
  node-artifact outbox ownership contract exists.

## Focused verification

Use the shared interpreter with `PYTHONPATH` set to this checkout:

```text
python -m pytest -o addopts= -q tests/findings/test_reviews.py tests/findings/test_review_identity.py tests/api/test_finding_reviews.py tests/api/test_review_identity.py tests/report
```

Tests cover verified and legacy review round trips on JSON and SQLite, actor/body
forgery, expiration and session revocation before persistence, stored provenance
corruption, scan invalidation, escaped report identity, unchanged canonical actors,
and snapshot persistence. Report access contract tests cover deleted/moved/reused
targets, denied contributors, search/count/download exclusion, unknown legacy
ownership, scope preservation through queueing, and revocation during rendering.
The report access tests inject the declared resource-authorizer interface at the
sidecar's base commit; they do not certify the parent's policy, middleware, schema,
or outbox integration. No live identity provider, full gate, or external target
operation is part of this acceptance.
