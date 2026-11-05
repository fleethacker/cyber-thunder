# Cyber Thunder HTTP API (v1)

Base path `/api/v1`. JSON in and out. Served by `cyberthunder serve` from the same process as the UI.
Interactive docs at `/api/docs`.

**Identity.** Every request may carry `X-Actor: <name>` (the UI sends the name the Sailor typed).
Every POST, PUT, PATCH and DELETE route except `POST /policy/evaluate` requires it to name a person: a missing or
blank header, a bare or prefixed machine identity (`agent`, `llm`, `system`, `agent:*`, `llm:*`, `system:*`) and any
`policy:*` value are refused with `400`. Approvals, denials, kill switch, scope and policy changes are recorded under
that actor. Request validation errors return `400` with a string `detail`, not the framework default `422`.

**Errors.** `{"detail": "..."}`. `404` unknown id · `409` illegal proposal transition or duplicate live
proposal or stale preference revision · `403` scope violation or machine actor on a human edge · `423` kill-switch guard ·
`400` invalid body/validation · `413` upload size limit · `503` adapter/transport failure (detail carries the message).

**Shapes.** `Finding` = `Finding.to_dict()`. `Finding+` adds `cat` ("CAT I"), `explanation` (Explanation or null),
`fix` (FixEntry.to_dict() or null), `proposal` ({id, state} or null), and `categories` (overlapping
`stig`, `cve`, `hunt`, or fallback `other`), `scanner_status` (original stored result), `confidence`
(grade, reasons, rules version, timestamps and provenance) and `review` (disposition, revision,
fingerprint, current event, active/suppressed and reopening reason). See [CONFIDENCE](CONFIDENCE.md)
and [FINDING_REVIEW](FINDING_REVIEW.md). `Proposal+` = `Proposal.to_dict()` plus
`fix`, `finding` (Finding+ without nested proposal), `policy` (PolicyDecision or null), `severity`, `cat`,
`target` ({id, name, asset_type, simulated}). `Target` = `Target.to_dict()`. `ScanRun` = `ScanRun.to_dict()`
plus `progress` {done, total}. `AuditRecord` = one chain record. `Explanation` = `Explanation.to_dict()`.

## Status
| Method | Path | Body → Response |
|---|---|---|
| GET | `/status` | → `AppContext.status()` + `link` {kbps, latency_ms, connected} + `outbox` {pending} |

## Targets (inventory = scope)
| GET | `/targets` | → `{targets: [Target]}` |
|---|---|---|
| POST | `/targets` | Target fields → Target, `201`. Audit `inventory.add` |
| PUT | `/targets/{id}` | partial fields → Target. `in_scope` changes audited as `scope.change` with before/after |
| DELETE | `/targets/{id}` | → `{ok: true}`. Audit `inventory.remove` |
| POST | `/targets/{id}/discover` | → `AssetFacts` (read-only; opens transport, runs adapter.discover) |

## Scans
| POST | `/scans` | `{target_ids?: [..], modules?: ["check","hunt","cve"], rule_filter?: [..], trigger?: str}` → ScanRun, `202`. Runs in a background thread. Omitted target_ids = all in-scope targets |
|---|---|---|
| GET | `/scans` | → `{scans: [ScanRun]}` newest first |
| GET | `/scans/{id}` | → ScanRun |

## Findings
| GET | `/findings` | `?scan_id&host&status&severity&source&asset_type&category&benchmark&benchmark_release&confidence&review&q&sort_by&sort_dir&limit=200&offset=0` → `{findings: [Finding+], total, unfiltered_total, scan_id, view, summary, facets, sort_by, sort_dir, limit, offset}`. Filters and sorting run before pagination; see query contract below |
|---|---|---|
| GET | `/findings/{id}` | → Finding+ |
| GET | `/findings/{id}/review` | `?scan_id` optional historical view → summary and ordered review history |
| PUT | `/findings/{id}/review` | `{disposition, reason, supporting_evidence?, expires_at?, expected_revision, evidence_fingerprint}` → summary and history. Current findings only; stale revision/evidence returns `409`, historical writes `400` |
| POST | `/findings/{id}/propose` | → Proposal+ (`409` if a live proposal or active review suppression exists, `404` if no library fix) |
| POST | `/findings/{id}/explain` | `{force?: bool}` → Explanation (synchronous; may take up to `CT_LLM_TIMEOUT`) |
| POST | `/findings/explain` | `{ids?: [..]}` → `{queued: n}`; background precompute, default = all open findings of the latest scan |

### Findings query contract

- Omitted `scan_id` uses the store's current picture: the latest full scan plus newer partial runs.
  `scan_id` in the response remains the baseline metadata anchor; `view` is `current`.
  Explicit `scan_id` selects only that run and returns `view: "scan"`; unknown IDs return `404`.
  Existing verified-remediation status decoration is retained for both views.
- `host`, `asset_type`, `source`, `status`, `severity`, `category`, `benchmark`, `benchmark_release`, `confidence` and `review`
  accept comma-separated values (OR within an axis, AND across axes). Matching ignores case and outer
  whitespace. CSV-quote values containing commas or quotes; for example `benchmark_release="Release 1, November"`.
  Omit a filter or send an empty string to select all values. `__missing__` selects absent/blank text fields.
- `status` values remain `open`, `not_a_finding`, `not_applicable`, `not_reviewed`, `error`.
  These are result statuses, not general human triage. Kubernetes known-good exceptions can change
  an open result to `not_applicable`, with an exception tag and reason in its evidence. The UI labels them Failed / open, Passed, Not applicable,
  Not assessed, and Collection error. Verified fixes continue to appear passed (`not_a_finding`).
  Without a status filter the API includes every result; only the UI defaults to open.
- `severity` accepts the existing aliases, including `CAT I`, `CAT II`, `CAT III`, plus `info` and `unknown`.
  `category` accepts `stig`, `cve`, `hunt`, `other`; categories can overlap. Classification uses normalized
  references, rule identifiers, scanner provenance and STIG benchmark names, not title keywords.
  See [FINDINGS.md](FINDINGS.md) for classification details.
- `confidence` accepts `high`, `medium`, `low`, `unknown`; `review` accepts `unreviewed`, `confirmed`,
  `false_positive`, `not_applicable`, `needs_investigation`. The review facet is independent of scanner status.
- `q` is a case-insensitive substring of title, machine/host ID, rule ID, rule version, group ID,
  reference identifiers (including CVEs and STIGs), source, benchmark, or release.
- `sort_by` accepts `default`, `severity`, `host`, `asset_type`, `category`, `title`, `rule_id`,
  `rule_version`, `source`, `collected_at`, `benchmark`, `benchmark_release`, `confidence`, `review`.
  `sort_dir` is `asc` (default) or `desc`. The omitted/default sort preserves severity descending,
  open first, host, then rule version or rule ID; it accepts only `asc` as its direction token.
  Explicit sorts use case-insensitive text, numeric severity, UTC-normalized observation time,
  or the alphabetically sorted tuple of category names. Ties use finding ID ascending in either
  direction. Missing/invalid values, including unknown severity, come last for explicit sorts.
  Confidence orders Low/Medium/High with Unknown last in either direction; review orders Unreviewed,
  Needs investigation, Confirmed, False positive, Not applicable.
- `total` remains the filtered count. `unfiltered_total`, `summary`, and `facets` describe the complete
  selected view before filters or pagination. `facets` has one key per filter axis, each containing
  `{value, label, count}` entries. Values are normalized filter tokens, labels retain source spelling,
  and counts are findings, not pages. Overlapping category counts can exceed the result total.
- Invalid enumerated filters, sort fields/directions, malformed CSV lists and out-of-range pagination
  return `400` with a string `detail`. Unseen host/source/type/benchmark/release values are valid and
  return zero matches, allowing saved selections to survive changes in the current view.

## Cluster
| GET | `/cluster/survey` | `?target_id` → Kubernetes namespace/workload survey using the authorized inventory connection. Requires `X-Actor`, an in-scope target and a released kill switch |
|---|---|---|
| POST | `/cluster/baseline` | `{target_id?, use_openai?: bool}` → persisted namespace image-risk baseline. Requires `X-Actor`, an in-scope target and a released kill switch. Audit `cluster.baseline` |
| GET | `/cluster/risk` | → latest persisted namespace risk profiles |
| GET | `/cluster/known-good` | → `{exceptions: [KnownGoodException]}`. Exceptions are applied to future Kubernetes scans before summaries and proposals |
| POST | `/cluster/known-good/exceptions` | `{target_id, reason, rule_id?, rule_version?, group_id?, object?, object_prefix?, expires_at?}` → KnownGoodException, `201`. Audit `known_good.add` |
| POST | `/cluster/known-good/from-finding/{finding_id}` | `{reason, scope?: "object"|"object_prefix"|"rule", expires_at?}` → KnownGoodException, `201`. `object_prefix` keeps generated pod-name changes accepted, for example `kube-system/pod/metrics-collector-*` |
| DELETE | `/cluster/known-good/exceptions/{id}` | → `204`. Audit `known_good.delete` |

## Proposals (the decision queue)
| GET | `/proposals` | `?state&host&asset_type` (each takes comma-separated values; an unknown `state` is `400`) → `{proposals: [Proposal+]}` oldest first |
|---|---|---|
| GET | `/proposals/{id}` | → Proposal+ |
| POST | `/proposals/{id}/approve` | `{note?, assessment_id?, assessment_note?}` → Proposal+. An attached impact receipt must match current bindings and be unexpired; unknown dependencies require a review note. Without a receipt the decision is explicitly not assessed |
| POST | `/proposals/{id}/impact` | `{live?: true}` → immutable dependency/model assessment; explicit actor, scoped target and released kill switch required. Bounded read-only collection, no execution or approval |
| GET | `/proposals/{id}/impact` | → `{assessment: receipt or null}` with computed freshness; no collection or model call |
| GET | `/change-assessments/{id}` | → saved receipt with computed freshness, or 404 |
| POST | `/proposals/{id}/review-impact` | `{assessment_id, note?}` → Proposal+. A named human can refresh the reviewed receipt while a proposal remains APPROVED; does not execute it |
| POST | `/proposals/{id}/deny` | `{note?}` → Proposal+ |
| POST | `/proposals/{id}/cancel` | `{note?}` → Proposal+ |
| POST | `/proposals/{id}/plan` | → static remediation plan; named actor and kill switch checked, one `remediation.plan` audit event. Includes target identity, bound fix/digests, declared capture/verification/rollback metadata, checks and limitations. Makes no target connection, changes no proposal state and does not approve or apply anything. See [REMEDIATION_PLAN](REMEDIATION_PLAN.md) |
| POST | `/proposals/{id}/apply` | `{simulate_verify_fail?: bool}` → `202 {proposal_id, state: "applying"}`; engine.execute runs in background: before-state → apply → verify → verified, or failed → automatic rollback. `409` unless APPROVED, `423` if kill switch engaged |
| POST | `/proposals/{id}/rollback` | → `202`; manual rollback of APPLIED, VERIFIED or FAILED |
| POST | `/proposals/{id}/verify` | → Proposal+; re-checks an APPLIED proposal (used after an operator completes a runbook): VERIFIED or FAILED. `501` on a node whose engine lacks it |
| GET | `/proposals/{id}/diff` | → `{proposal, fix, before_state, before: {...}, after: {...}, verify: VerifyResult, apply: ApplyResult, rollback, files: [{path, before, after}]}` |
| POST | `/proposals/bulk` | `{action: "approve"|"deny", ids: [..], note?}` → `{results: [{id, state} | {id, error, status}]}` (`status` is the HTTP code the single call would have returned) |

## Audit
| GET | `/audit` | `?after_seq=0&limit=200&action&actor&subject` → `{records: [AuditRecord], head, count}`. An `action` value ending in `.` is a prefix filter (`proposal.`) |
|---|---|---|
| GET | `/audit/verify` | → `{ok, count, head, bad_seq, reason}` |
| GET | `/audit/stream` | `?after_seq&max_seconds` → `text/event-stream`; event `audit`, data = AuditRecord JSON; each event carries `id: <seq>`, so a reconnecting client resumes from the `Last-Event-ID` header; replays records after `after_seq` (`max_seconds` is `0 < x <= 86400`), then tails the file (poll ≤ 500 ms). Sends a `: keepalive` comment every 15 s; closes after `max_seconds` when given |

## Kill switch
| GET | `/kill` | → `{engaged, by, reason, at, via}` |
|---|---|---|
| POST | `/kill/engage` | `{reason?}` → status |
| POST | `/kill/release` | `{reason?}` → status |

## Standing approval policy
| GET | `/policy` | → `AutomationPolicy.to_dict()` |
|---|---|---|
| PUT | `/policy` | AutomationPolicy fields (enabling requires `reason`; server sets `signed_by` = actor and `signed_at`) → policy. Audit `policy.update` |
| POST | `/policy/evaluate` | `{proposal_id}` → PolicyDecision |

## Ingest and the constrained link
| GET | `/ingest/link` | → `{kbps, latency_ms, connected}` |
|---|---|---|
| PUT | `/ingest/link` | partial → link state. Audit `link.change`. `connected` false→true flushes the outbox |
| POST | `/ingest/stig` | multipart `file` (XCCDF/datastream xml or DISA zip) or `{path}` → DeltaReport `{id, benchmark_id, old_release, new_release, rules_added: [RuleRef], rules_removed: [RuleRef], rules_changed: [RuleRef+{change}], counts, sizes: {full_bytes, delta_bytes, compressed_bytes, ratio}, transfer: {full_s, delta_s, kbps}, rescan_rule_ids: [..]}` where RuleRef = `{rule_id, stig_id, title, severity}` |
| POST | `/ingest/stig/{delta_id}/rescan` | → ScanRun with `trigger: "stig_delta"` and `rule_filter` = changed rules, `202` |
| POST | `/ingest/bulletin` | multipart `file` (JSON) or Bulletin JSON `{id, title, severity, cves: [..], affected: [{product?, package?, versions_below?, cpe?}], source}` → `{bulletin_id, hosts_affected: [..], findings: [Finding+], scan_id}` (matches against the latest package inventory per host; findings source `iavm`) |
| GET | `/ingest/history` | → `{deltas: [DeltaReport], bulletins: [...]}` |
| GET | `/outbox` | → `{connected, pending: [{name, kind, bytes, created_at}], synced: [{name, kind, bytes, synced_at, seconds}]}` |
| POST | `/outbox/sync` | → `{sent, bytes, seconds}`; `409` if disconnected |
| GET | `/ingest/updates` | → last-check metadata `{checked_at, source, index_entries, index_wire_bytes, gzip, estimate_seconds_at_link}` plus `wanted`, `updates`, `current`, `skipped`, `index_estimate: {bytes, seconds, link}` and `connected`. Selection is always recomputed from saved subscriptions and eligible held files, including before the first check; `checked_at` remains null until a check runs. `selection_source` identifies the local cached/snapshot index used. See [CONTENT.md](CONTENT.md) |
| POST | `/ingest/updates/check` | `{source?: "live"|"snapshot"}` → the check report. `409` (naming the manifest path) when the link is down and source is live. Audit `content.check` |
| POST | `/ingest/updates/pull` | `{filenames?: [..]}` or `{all_matching: true}`, `pace?` → `202` job `{id, state, files: [{filename, state, bytes, total, error, delta?, datastream_path?}], deltas}`. `409` when the link is down; pulls are blocked while the kill switch is engaged. Audit `content.fetch`, `content.fetch_failed`, `content.quarantine`, and `ingest.stig` per manual STIG |
| GET | `/ingest/updates/jobs/{id}` | → the pull job with per-file progress; `404` if unknown |
| GET | `/ingest/content` | → `HeldContent` `{files: [HeldRecord], products, scap: [{product_key, filename, datastream_path}], quarantine, dir}`. HeldRecord includes `filename`, `product_key`, `kind`, `version`, `version_label`, `upload_date`, `sha256`, `etag`, `bytes`, `url`, `fetched_at`, `fetched_by`, `source`, and `ingest: {delta_id?, catalog_path?, datastream_path?, upload?}`. New upload records use `ingest.upload.imported_at/imported_by` with null fetch fields; duplicate bytes return the existing record without changing its provenance |
| POST | `/ingest/manifest` | → `{generated_at, node, items: [{filename, url, product_key, kind, version, expected_bytes?, expected_etag?}], path, sha256}` for missing updates matching saved subscriptions, written to `<state>/content/manifest.json`. Audit `content.manifest` |
| POST | `/ingest/import-dir` | `{path}` (a folder on this node) → `{imported, refused: [{filename, reason}], skipped, missing, verified_by, deltas}`; named actor required, kill-switch guard before starting and between files (`423`); invalid body `400`. Lock-file entries are verified against `manifest.lock.json`. Audit `content.import`, `content.quarantine` |

Folder imports route raw XML with no lock-file entry and unrecognized content kind through the validated
upload helper (32 MiB per file). New records use `source: "uploaded"` and `ingest.upload` import metadata;
invalid/oversized XML is reported per file in `refused`. Lock-file and known-content imports retain their
existing checks and `source: "imported"`. Previously accepted files remain if the kill switch stops the batch.

### STIG Library and subscriptions

| Method | Path | Body → Response |
|---|---|---|
| GET | `/ingest/library` | → library view below; local reads only, no network requests or writes |
| PUT | `/ingest/library/preferences` | complete preference body below → saved preferences with new `revision`, `updated_at`, `updated_by`; named actor required, audit `content.preferences`. `400` invalid body, `423` kill-switch guard, `409` stale revision; saves only, never downloads |
| POST | `/ingest/content/upload` | multipart `file`, exactly one supported XML or ZIP benchmark package, at most 32 MiB → `201 {record: HeldRecord, delta: PullDelta\|null}`. Named actor required, kill-switch guarded; works offline. `400` invalid content, `413` size limit, `423` kill switch |

The library response contains:

- `catalog: {source: "live"|"snapshot", saved_at, total_entries}`: cached public index or bundled snapshot.
  `live` means the cache came from a live check, not that this GET contacted the publisher.
- `sync: {last_attempt_at, last_attempt_status, last_error, last_successful_check_at, last_download_at,
  last_import_at}`: nullable timestamps/status; successful live checks, downloads and local imports are distinct.
  Snapshot checks do not advance `last_successful_check_at`; deltas created by pulls do not advance `last_import_at`.
- `preferences: {mode, products, kinds, check_on_reconnect, auto_pull, revision, updated_at, updated_by}`.
- `products: [{product_key, title, kinds, recommended, selected, targets, available, held, status}]`:
  one row per indexed product, including unavailable retired/external-only entries. `available` rows include
  `filename`, `kind`, `version_label`, `upload_date`, `sunset`, `allowed`, `url`; `held` contains HeldRecords.
  `status` is `update_available`, `current`, `not_downloaded` or `unavailable`, relative to the local index.
- `selection: {products, wanted, updates, current, skipped}`: recalculated from saved preferences and held files,
  even before a first live check. Content rows include product, type, version, publisher date and target IDs;
  skipped rows explain why content did not match. Unverified local uploads do not satisfy official update
  comparisons, even with matching product/version metadata; downloaded files and legacy imports retain their
  existing comparison behavior.
- `held: HeldContent`; `catalogs: [{benchmark_id, title, release, rules, imported_at, filename, origin, path}]`,
  where `origin` is `imported_catalog` or `bundled_reference`; `catalog_errors: [{filename, reason}]`.
  Legacy catalog imports remain visible. Bundled references are not synchronized/installed downloads, and
  catalog rule counts do not imply executable scan coverage.
- `jobs`: latest 20 PullJobs; `connected`: link state; `check_interval_s`: server-configured periodic interval.

Send all six writable fields to save preferences, using the revision returned by GET; omit timestamps/actor:

```json
{"mode":"selected","products":["RHEL_9"],"kinds":["manual_stig","srg","scap_benchmark"],"check_on_reconnect":true,"auto_pull":false,"revision":0}
```

Defaults are `mode: "inventory"`, all three kinds and an empty manual product list. Inventory mode follows
in-scope asset matches, not all STIGs; `selected` uses product keys without requiring targets. Empty selected
products or kinds yield no matching files. Reconnect defaults inherit server settings (normally true/false).
`auto_pull` checks then pulls matching updates on reconnect only, even if `check_on_reconnect` is false.
Manual/periodic checks never auto-pull; `CT_CONTENT_CHECK_INTERVAL_SECONDS` sets the periodic interval (0 = off).

Save before check/pull/manifest calls: all-matching pulls and manifests use persisted subscriptions. Uploads
validate/index content without running it or verifying publisher authenticity; multiple browser files require
sequential requests. Legacy STIG import, check, pull, job, manifest and folder-import endpoints remain available.

## Reports
| GET | `/reports/history` | `?q&kind&target&from_date&to_date&offset&limit` → `{reports, total, offset, limit}`; keyword search covers saved contents and metadata; kind is `commander`, `poam`, `checklist` or `target`; dates are inclusive UTC `YYYY-MM-DD`; limit defaults to 20 (max 100) |
|---|---|---|
| GET | `/reports/history/{id}` | → saved metadata and `content`; does not re-render current state |
| GET | `/reports/history/{id}/download` | → original saved content as an attachment |
| GET | `/reports/commander` | `?scan_id&format=html|md` → rendered one-pager and a saved history snapshot |
| GET | `/reports/poam.csv` | `?scan_id` → CSV |
| GET | `/reports/checklist.cklb` | `?scan_id&host` → CKLB JSON with statuses written back |
| GET | `/reports/fleet` | `?format=html|md` → path-to-fleet one-pager |
| GET | `/reports/friction` | `?format=html|md` → friction log |
| GET | `/reports/coverage` | `?format=html|md|json` → offline check/fix inventory and locally supplied benchmark coverage; no scan required |
| GET | `/reports/score` | `?scan_id` → `{seeded, found, share, items: [{id, kind, what, found, finding_ids}]}` against `range/answer_key/<type>.json` |
| POST | `/reports/queue` | `{kind: "commander"|"poam"|"checklist", scan_id?}` → outbox entry (queued for sync) |

## Demo
| GET | `/demo` | → `{available, loaded, targets: [id], simulate_verify_fail_next: bool}` (`targets` are the simulated target ids; read full records from `GET /targets`) |
|---|---|---|
| POST | `/demo/load` | → `{targets}`; adds one simulated target per adapter that supports it. Audit `demo.load` |
| POST | `/demo/reset` | → `{ok}`; simulated hosts back to seeded state. Audit `demo.reset` |
| PUT | `/demo` | `{simulate_verify_fail_next: bool}` → demo status; arms or disarms the forced verification failure for the next apply (demonstration control, audited as `demo.simulate_verify_fail`) |

## Discovery
The `/discovery/*` routes (scopes, sweeps, discovered assets, discovery findings, applicable benchmarks) are
documented in [DISCOVERY.md](DISCOVERY.md). They follow the same actor and error rules as above.

## Workflow
One pass over an isolated enclave: receive what came across the link, discover the system, scan a target,
explain and propose from those results, apply approved checklist items, report, and roll back.
These routes call the same services as the routes above. Apply and rollback still require a human approval
on each fix and still stop when the kill switch is engaged. A checklist entry is a rule id, STIG id, rule
version, CVE or other citation, fix ref, or proposal id. A rollback version is a proposal id, a scan id,
or a benchmark release.

| Method | Path | Body → Response |
|---|---|---|
| GET | `/receive/cve` | → `{cves: [bulletin]}` newest first. Bulletin fields: id, title, severity, cves, published, source, ingested_at, hosts_affected, findings, scan_id |
| GET | `/receive/stig` | → `{stigs: [delta]}` newest first. Delta fields match the ingest history summary (id, benchmark, releases, counts, sizes, transfer) |
| POST | `/discover` | `{system: target id}` (or `{target}`) → `{targets: [Target+]}`. Target+ is a Target plus `facts` on the system that was read. Other in-scope targets come along when `options.system` or `options.members` names that system, or the system id is one of their tags. `202` is not used; discover is read-only |
| POST | `/scan` | `{target, modules?}` → `202 {target, results: {<target>: {target, ok, scan_id, status, findings, open, errors}}}`. Poll `GET /scans/{scan_id}` until `status` is `done` |
| POST | `/generate/explain` | `{results}` → `{explanations: [Explanation], truncated}`. `results` is `{scan_id?, target?, finding_ids?}` or the POST /scan body. Named finding ids are explained as given; otherwise open findings for that scan and target. At most 40 explanations per call (`truncated` is how many were left) |
| POST | `/generate/propose` | `{results}` → `{proposals: [Proposal+], skipped: [{id, reason}]}`. Creates a proposal only when a library fix exists and the finding has no live proposal |
| POST | `/apply` | `{targets: [id], checklists: [id]}` → `{results: {<target>: {target, ok, applied: [{proposal_id, state, version}], skipped, errors}}}`. Applies approved proposals that match the checklist. Anything not approved is skipped and not changed. `423` when the kill switch is engaged |
| POST | `/rollback` | `{targets: [id], versions: [id]}` (`version` may be a string or a list) → `{results: {<target>: {target, ok, rolled_back: [{proposal_id, state, version}], skipped, errors}}}`. Rolls back applied, verified, or failed proposals on those targets whose id, scan, or benchmark release is in `versions` |
| GET | `/reports/{target}` | → the last report saved for that target (`404` if none). A target id does not shadow `/reports/commander`, `/reports/score`, and the other fixed report paths |
| POST | `/reports` | `{target}` → the same report, written for that target: inventory record, finding counts, summary, and a CKLB checklist when the report service can build one |
