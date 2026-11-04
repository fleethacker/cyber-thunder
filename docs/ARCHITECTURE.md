# Cyber Thunder architecture

Cyber Thunder finds, explains and fixes misconfigurations and vulnerabilities on isolated, low-bandwidth
networks with a human approving every change. It does not reinvent the Navy's scanners: it turns their
output, plus its own deterministic checks, into approved, verified, reversible fixes, offline.

Principle: **deterministic tools detect; the local model only explains and plans; a human decides;
every state change is approval-gated, kill-switch-guarded, logged and reversible.**

## 1. Pipeline

```
 constrained link                      enclave
 ───────────────►  INGEST  ─────────►  DISCOVER ─► COLLECT ─► CHECK / HUNT / CVE ─► NORMALIZE (Finding)
 STIG delta, IAVM     │                   (inventory = scope)   per asset-type adapter          │
                      │                                                                          ▼
 ◄── OUTBOX / SYNC ◄─ REPORT ◄─ AUDIT ◄─ APPLY → VERIFY → (ROLLBACK) ◄─ APPROVE ◄─ PROPOSE ◄─ EXPLAIN
  reports queued      one-pager   hash chain   adapter, before-state,   human / policy   fix library   local model,
  until reconnect     POA&M, CKLB            health check, auto-rollback                            validated citations
```

Kill switch (file, env or sentinel) blocks every apply and rollback edge. The audit log is the event
stream the UI tails.

## 2. Module map

| Path | Responsibility | State |
|---|---|---|
| `cyberthunder/findings/schema.py` | `Finding`, `Severity`, `Status`, `Reference`, citation extraction (STIG/CCI/CCE/CVE/ATT&CK/IAVM) | built |
| `cyberthunder/parsers/` | `xccdf.py` (DISA, SSG, oscap results, ARF), `cklb.py` (Evaluate-STIG, STIG Viewer 3), `nessus.py` (ACAS exports), `trivy.py`, `bulletin.py` (IAVM/CVE bulletins) | built |
| `cyberthunder/audit/chain.py` | append-only hash-chained JSONL + verifier | built |
| `cyberthunder/control/` | `killswitch.py`, `approvals.py` (proposal state machine), `policy.py` (standing approval) | built |
| `cyberthunder/inventory/targets.py` | `Target`, `Inventory`, scope guardrail (`assert_in_scope`) | built |
| `cyberthunder/transport/` | `base.py` contract + factory, `local.py`, `ssh.py`, `fixture.py` (replay/record), `winrm.py` | built |
| `cyberthunder/adapters/base.py` | `Adapter` contract, `registry`, `make_finding()` | built |
| `cyberthunder/adapters/linux/` | OpenSCAP + native STIG checks, hunt, Trivy CVEs, SSG fix library, simulated host | built; `options.benchmark_path` and `options.profile` run a DISA datastream through oscap instead of the SSG autodetect |
| `cyberthunder/adapters/cisco/` | IOS/IOS-XE config rules (NDM/RTR STIG), config-snippet fixes, runbook or SSH push, `configure replace` rollback | built |
| `cyberthunder/adapters/kubernetes/` | cluster/workload checks (Kubernetes STIG + CIS), manifest fixes, kubeconfig transport, simulated cluster | built |
| `cyberthunder/adapters/containers/` | docker/podman inspect checks, image CVEs via Trivy JSON | built |
| `cyberthunder/adapters/windows/` | Evaluate-STIG/PowerSTIG CKLB ingestion, PowerShell hunt (JSON), registry/policy fixes with export-based rollback | built; `options.scap_datastream` and `options.scap_profile` run the DISA benchmark through the OVAL evaluator in `cyberthunder/scap/`, and benchmark results win when native checks cover the same rule |
| `cyberthunder/scap/` | DISA SCAP datastream loader, OVAL 5.11 evaluator for the Windows test types, collection plan rendered as one PowerShell pass, benchmark results to findings, `scap info|plan|eval|subset` | built |
| `cyberthunder/discovery/` | scoped sweeps (nmap, neighbours, kube, AD, hypervisors), device typing, propose-only inventory, rogue and missing-asset findings | built |
| `cyberthunder/remediation/library.py` | `FixEntry`, `FixLibrary` (resolve finding → vetted fix) | built |
| `cyberthunder/remediation/models.py` | `BeforeState`, `ApplyResult`, `VerifyResult`, `HealthResult`, `RollbackResult` | built |
| `cyberthunder/remediation/engine.py` | propose / execute (apply→verify→auto-rollback) / rollback / diff | built |
| `cyberthunder/scan.py` | `ScanRun`, `Scanner` (collect + detect per target, persist, audit, auto-propose, precompute) | built |
| `cyberthunder/explain/` | local-model client (Ollama / OpenAI-compatible / template), prompt, citation validator, cache, precompute | built |
| `cyberthunder/ingest/` | STIG release delta, compression + link emulation, IAVM/CVE bulletin matching, outbox (sync on reconnect) | built; `ingest/content/` pulls what the inventory needs from the public DISA index when the link is up and writes a manifest plus folder import for disconnected sites |
| `cyberthunder/report/` | commander one-pager, POA&M CSV, CKLB write-back, path-to-fleet, friction log, answer-key score | built |
| `cyberthunder/api/` | FastAPI app factory, `routes/<area>.py`, SSE audit stream, static UI | built |
| `cyberthunder/ui/` | React + TypeScript + Mantine single-page app, built to `ui/dist` and served offline | built |
| `cyberthunder/store.py` | on-disk state layout | built |
| `cyberthunder/context.py` | `AppContext`: wires everything; CLI and API share it | built |
| `cyberthunder/cli.py` | `cyberthunder <cmd>`; modules add commands via `register_cli(subparsers)` | built |
| `range/` | local range: Rocky 9 VM notes, seed scripts, sample device configs/logs, `answer_key.json` | partial |

## 3. Core contracts

- **Finding** (`findings/schema.py`): one shape for every detector. `id = sha256(host|source|rule_id)[:16]`
  is stable across scans. `citations` lists every identifier the explain layer may cite. `fix_ref` is set
  when the engine resolves a library entry. `asset_type` tags the adapter.
- **Target / Inventory**: the inventory is the scope. `assert_in_scope()` runs before any collect or apply.
  No secrets in the inventory; `credential_ref` names an env var (`CT_CRED_<ref>`) or a key file.
- **Transport**: `run(cmd, sudo=)`, `read_file`, `write_file`, `fetch`. Generic kinds: `local`, `ssh`,
  `winrm`, `fixture`. Adapter-specific kinds (`simulated`, `file`, `kubeconfig`) come from `Adapter.make_transport()`.
  `RecordingTransport` turns a live session into a fixture.
- **Adapter**: `discover`, `collect`, `check`, `hunt`, `cve`, `fixes`, `capture_before_state`, `apply`,
  `verify`, `health_check`, `rollback`. Detection methods are pure functions of `Collected` (no network),
  so they are unit-testable from fixtures. Use `make_finding()`.
- **FixEntry / FixLibrary**: the only source of executable payloads. Declares disruption, reboot,
  service restarts, reversibility, rollback kind, what to capture before, how to verify after.
- **Proposal / ApprovalGate**: PROPOSED → APPROVED → APPLYING → APPLIED → VERIFIED, with DENIED,
  CANCELLED, FAILED → ROLLED_BACK. Human-only edges reject actors `agent`, `llm`, `system`.
  Apply and rollback edges call the kill switch guard.
- **AutomationPolicy**: off by default. A named human signs narrow criteria; eligible proposals are
  approved as `policy:<signer>`. Patches, reboots and service restarts are never eligible unless stated.
- **AuditLog**: every edge, including rejections and blocks, with `prev_hash`/`hash`. Head hash is shown
  in the UI and printed on every report so a truncated log is detectable.
- **AppContext**: builds store, audit, kill switch, gate, inventory, adapters, fix library, policy,
  scanner, engine, explain, ingest, reports. Everything goes through it.

## 4. Guardrails and where they are enforced

| Rule | Enforced in |
|---|---|
| Only scan, read, propose, apply approved library fixes | `RemediationEngine.execute` runs `FixEntry.payload` only; adapters take a `FixEntry`, never free text |
| Never arbitrary shell from model output | `explain/` returns JSON text fields only; validator strips anything that is not a known identifier; no code path passes model output to a transport |
| Human approval before any change | `ApprovalGate.HUMAN_ONLY` edges; engine refuses `execute` unless `APPROVED` |
| Rollback for every change | `FixEntry.rollback_kind` required; engine captures `BeforeState` before apply and auto-rolls back on failed verify |
| Never touch hosts outside scope | `Inventory.assert_in_scope()` in Scanner and engine; scope changes are audited |
| Never delete logs or audit | audit log is append-only; no API deletes it; chain verification exposed |
| Everything logged | gate edges, kill switch, scans, explanations, policy, inventory, link and outbox events |
| Kill switch | `KillSwitch.guard()` in gate `APPLYING`/`ROLLED_BACK` edges; file, env `CT_KILL`, or sentinel `KILL` |

## 5. Modes

| Mode | Transport | Use |
|---|---|---|
| live | ssh / winrm / kubeconfig | the event range, the local VM |
| fixture | `FixtureTransport(dir)` | tests; replay of a recorded live session |
| simulated | adapter emulator (stateful) | the demo before the range is reachable: seeded state matches `range/answer_key.json`; applying a fix changes the simulated state so verify and rollback are real state transitions |

`cyberthunder demo load` puts one simulated target per adapter into the inventory. The UI shows a
"simulated" badge on those assets. Nothing else differs between modes.

## 6. Adding an adapter

1. Create `cyberthunder/adapters/<type>/` with `__init__.py` importing your `Adapter` subclass decorated with `@register`.
2. Add the asset type to `inventory.targets.ASSET_TYPES` and the module path to `adapters.ADAPTER_MODULES`.
3. Implement `collect` (over the transport) and the pure detection methods from `Collected`.
4. Contribute `FixEntry` objects from `fixes()`; each must have `before_state`, `verify` and a rollback kind.
5. Implement `capture_before_state`, `apply`, `verify`, `health_check`, `rollback`.
6. Provide a simulated transport via `make_transport()` if the asset can be emulated.
7. Tests in `tests/<type>/`, fixtures in `tests/fixtures/<type>/`. Seeds and answer-key items in `range/`.

## 7. Conventions

- Python 3.11+, standard library first. Runtime dependencies are exactly those in `requirements.txt`;
  do not add any. Dev dependencies: pytest, httpx.
- No network access in tests. Live transports are exercised against the range by hand, with
  `RecordingTransport` producing fixtures for the suite.
- Paths must work on Windows and Linux (`pathlib`, no `/tmp` literals in library code).
- Each feature area owns its directory, its `tests/<area>/` and `tests/fixtures/<area>/`. Shared files
  (`schema.py`, `base.py`, `context.py`, `cli.py`, `app.py`, requirements, `.gitignore`) change only by
  agreement; new CLI commands go in the module's own `register_cli`, new API areas in `api/routes/<name>.py`.
- Environment variables are prefixed `CT_`. Actor identity is a plain string; `agent`, `llm`, `system`
  are reserved for the machine and are refused on human-only edges.
- Every finding cites something: a STIG ID, CCI, CVE, IAVM or ATT&CK technique. Hunt findings cite ATT&CK.
- Comments and docs are written for the Sailor or engineer who maintains this later. No tool names,
  assistant names or generation notes anywhere in the repository or in commit messages.
- Commit as yourself on your own branch; the repo hook strips any automated co-author trailers.
