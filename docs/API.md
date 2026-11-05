# Cyber Thunder HTTP API (v1)

Base path `/api/v1`. JSON in and out. Served by `cyberthunder serve` from the same process as the UI.
Interactive docs at `/api/docs`.

**Identity.** Every request may carry `X-Actor: <name>` (the UI sends the name the Sailor typed).
Every POST, PUT, PATCH and DELETE route except `POST /policy/evaluate` requires it to name a person: a missing or
blank header, a bare or prefixed machine identity (`agent`, `llm`, `system`, `agent:*`, `llm:*`, `system:*`) and any
`policy:*` value are refused with `400`. Approvals, denials, kill switch, scope and policy changes are recorded under
that actor. Request validation errors return `400` with a string `detail`, not the framework default `422`.

**Errors.** `{"detail": "..."}`. `404` unknown id · `409` illegal proposal transition or duplicate live
proposal · `403` scope violation or machine actor on a human edge · `423` kill switch engaged ·
`400` validation · `503` adapter/transport failure (detail carries the message).

**Shapes.** `Finding` = `Finding.to_dict()`. `Finding+` adds `cat` ("CAT I"), `explanation` (Explanation or null),
`fix` (FixEntry.to_dict() or null), `proposal` ({id, state} or null). `Proposal+` = `Proposal.to_dict()` plus
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
| GET | `/findings` | `?scan_id&host&status&severity&source&asset_type&q&limit=200&offset=0` → `{findings: [Finding+], total, scan_id, summary, limit, offset}`. Default = the current picture (latest full scan with newer bulletin and targeted-rescan runs overlaid). Filters accept comma-separated values; `severity` also accepts `CAT I`/`CAT II`/`CAT III`; an unknown `status` or `severity` is `400`. `q` matches title/rule_id/rule_version |
|---|---|---|
| GET | `/findings/{id}` | → Finding+ |
| POST | `/findings/{id}/propose` | → Proposal+ (`409` if a live proposal already exists, `404` if no library fix) |
| POST | `/findings/{id}/explain` | `{force?: bool}` → Explanation (synchronous; may take up to `CT_LLM_TIMEOUT`) |
| POST | `/findings/explain` | `{ids?: [..]}` → `{queued: n}`; background precompute, default = all open findings of the latest scan |

## Cluster
| GET | `/cluster/survey` | → Kubernetes namespace/workload survey from kubectl |
|---|---|---|
| POST | `/cluster/baseline` | `{use_openai?: bool}` → persisted namespace image-risk baseline. Audit `cluster.baseline` |
| GET | `/cluster/risk` | → latest persisted namespace risk profiles |
| GET | `/cluster/known-good` | → `{exceptions: [KnownGoodException]}`. Exceptions are applied to future Kubernetes scans before summaries and proposals |
| POST | `/cluster/known-good/exceptions` | `{target_id, reason, rule_id?, rule_version?, group_id?, object?, object_prefix?, expires_at?}` → KnownGoodException, `201`. Audit `known_good.add` |
| POST | `/cluster/known-good/from-finding/{finding_id}` | `{reason, scope?: "object"|"object_prefix"|"rule", expires_at?}` → KnownGoodException, `201`. `object_prefix` keeps generated pod-name changes accepted, for example `kube-system/pod/metrics-collector-*` |
| DELETE | `/cluster/known-good/exceptions/{id}` | → `204`. Audit `known_good.delete` |

## Proposals (the decision queue)
| GET | `/proposals` | `?state&host&asset_type` (each takes comma-separated values; an unknown `state` is `400`) → `{proposals: [Proposal+]}` oldest first |
|---|---|---|
| GET | `/proposals/{id}` | → Proposal+ |
| POST | `/proposals/{id}/approve` | `{note?}` → Proposal+ |
| POST | `/proposals/{id}/deny` | `{note?}` → Proposal+ |
| POST | `/proposals/{id}/cancel` | `{note?}` → Proposal+ |
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
| GET | `/ingest/updates` | → the last DISA content check `{checked_at, source, index_entries, index_wire_bytes, gzip, wanted, updates: [{filename, url, product_key, kind, version_label, upload_date, expected_bytes?, targets}], current, skipped: [{target_id|filename|product_key, reason}], estimate_seconds_at_link}` plus `index_estimate: {bytes, seconds, link}` and `connected`; `checked_at: null` before the first check. See [CONTENT.md](CONTENT.md) |
| POST | `/ingest/updates/check` | `{source?: "live"|"snapshot"}` → the check report. `409` (naming the manifest path) when the link is down and source is live. Audit `content.check` |
| POST | `/ingest/updates/pull` | `{filenames?: [..]}` or `{all_matching: true}`, `pace?` → `202` job `{id, state, files: [{filename, state, bytes, total, error, delta?, datastream_path?}], deltas}`. `409` when the link is down, `400` while the kill switch is engaged. Audit `content.fetch`, `content.fetch_failed`, `content.quarantine`, and `ingest.stig` per manual STIG |
| GET | `/ingest/updates/jobs/{id}` | → the pull job with per-file progress; `404` if unknown |
| GET | `/ingest/content` | → `{files: [{filename, product_key, kind, version, sha256, etag, bytes, url, fetched_at, fetched_by, source, ingest: {delta_id?, catalog_path?, datastream_path?}}], products, scap: [{product_key, filename, datastream_path}], quarantine, dir}` |
| POST | `/ingest/manifest` | → `{generated_at, node, items: [{filename, url, product_key, kind, version, expected_bytes?, expected_etag?}], path, sha256}` written to `<state>/content/manifest.json`. Audit `content.manifest` |
| POST | `/ingest/import-dir` | `{path}` (a folder on this node) → `{imported, refused: [{filename, reason}], skipped, missing, verified_by, deltas}`; verified against `manifest.lock.json` when present. Audit `content.import`, `content.quarantine` |

## Reports
| GET | `/reports/commander` | `?scan_id&format=html|md` → rendered one-pager |
|---|---|---|
| GET | `/reports/poam.csv` | `?scan_id` → CSV |
| GET | `/reports/checklist.cklb` | `?scan_id&host` → CKLB JSON with statuses written back |
| GET | `/reports/fleet` | `?format=html|md` → path-to-fleet one-pager |
| GET | `/reports/friction` | `?format=html|md` → friction log |
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
