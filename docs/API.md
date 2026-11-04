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
| POST | `/targets` | Target fields → Target. Audit `inventory.add` |
| PUT | `/targets/{id}` | partial fields → Target. `in_scope` changes audited as `scope.change` with before/after |
| DELETE | `/targets/{id}` | → `{ok: true}`. Audit `inventory.remove` |
| POST | `/targets/{id}/discover` | → `AssetFacts` (read-only; opens transport, runs adapter.discover) |

## Scans
| POST | `/scans` | `{target_ids?: [..], modules?: ["check","hunt","cve"], rule_filter?: [..], trigger?: str}` → ScanRun, `202`. Runs in a background thread. Omitted target_ids = all in-scope targets |
|---|---|---|
| GET | `/scans` | → `{scans: [ScanRun]}` newest first |
| GET | `/scans/{id}` | → ScanRun |

## Findings
| GET | `/findings` | `?scan_id&host&status&severity&source&asset_type&q&limit=200&offset=0` → `{findings: [Finding+], total, scan_id, summary}`. Default = the current picture (latest full scan with newer bulletin and targeted-rescan runs overlaid). Filters accept comma-separated values. `q` matches title/rule_id/rule_version |
|---|---|---|
| GET | `/findings/{id}` | → Finding+ |
| POST | `/findings/{id}/propose` | → Proposal+ (`409` if a live proposal already exists, `404` if no library fix) |
| POST | `/findings/{id}/explain` | `{force?: bool}` → Explanation (synchronous; may take up to `CT_LLM_TIMEOUT`) |
| POST | `/findings/explain` | `{ids?: [..]}` → `{queued: n}`; background precompute, default = all open findings of the latest scan |

## Proposals (the decision queue)
| GET | `/proposals` | `?state&host&asset_type` → `{proposals: [Proposal+]}` oldest first |
|---|---|---|
| GET | `/proposals/{id}` | → Proposal+ |
| POST | `/proposals/{id}/approve` | `{note?}` → Proposal+ |
| POST | `/proposals/{id}/deny` | `{note?}` → Proposal+ |
| POST | `/proposals/{id}/cancel` | `{note?}` → Proposal+ |
| POST | `/proposals/{id}/apply` | `{simulate_verify_fail?: bool}` → `202 {proposal_id, state: "applying"}`; engine.execute runs in background: before-state → apply → verify → verified, or failed → automatic rollback. `409` unless APPROVED, `423` if kill switch engaged |
| POST | `/proposals/{id}/rollback` | → `202`; manual rollback of APPLIED, VERIFIED or FAILED |
| POST | `/proposals/{id}/verify` | → Proposal+; re-checks an APPLIED proposal (used after an operator completes a runbook): VERIFIED or FAILED. `501` on a node whose engine lacks it |
| GET | `/proposals/{id}/diff` | → `{before: {...}, after: {...}, verify: VerifyResult, apply: ApplyResult, files: [{path, before, after}]}` |
| POST | `/proposals/bulk` | `{action: "approve"|"deny", ids: [..], note?}` → `{results: [{id, state} | {id, status, error}]}` (`status` is the HTTP code the single call would have returned) |

## Audit
| GET | `/audit` | `?after_seq=0&limit=200&action&actor&subject` → `{records: [AuditRecord], head, count}`. An `action` value ending in `.` is a prefix filter (`proposal.`) |
|---|---|---|
| GET | `/audit/verify` | → `{ok, count, head, bad_seq, reason}` |
| GET | `/audit/stream` | `?after_seq&max_seconds` → `text/event-stream`; event `audit`, data = AuditRecord JSON; replays records after `after_seq` (or the `Last-Event-ID` header on reconnect), then tails the file (poll ≤ 500 ms). Sends a `: keepalive` comment every 15 s; closes after `max_seconds` when given |

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

## Reports
| GET | `/reports/commander` | `?scan_id&format=html|md` → rendered one-pager |
|---|---|---|
| GET | `/reports/poam.csv` | `?scan_id` → CSV |
| GET | `/reports/checklist.cklb` | `?scan_id&host` → CKLB JSON with statuses written back |
| GET | `/reports/fleet` | `?format=html|md` → path-to-fleet one-pager |
| GET | `/reports/friction` | `?format=html|md` → friction log |
| GET | `/reports/score` | `?scan_id` → `{seeded, found, share, items: [{id, kind, what, found, finding_ids}]}` against `range/answer_key.json` |
| POST | `/reports/queue` | `{kind: "commander"|"poam"|"checklist", scan_id?}` → outbox entry (queued for sync) |

## Demo
| GET | `/demo` | → `{available, loaded, targets: [Target], simulate_verify_fail_next: bool}` |
|---|---|---|
| POST | `/demo/load` | → `{targets}`; adds one simulated target per adapter that supports it. Audit `demo.load` |
| POST | `/demo/reset` | → `{ok}`; simulated hosts back to seeded state. Audit `demo.reset` |
| PUT | `/demo` | `{simulate_verify_fail_next: bool}` → demo status; arms or disarms the forced verification failure for the next apply (demonstration control, audited) |
