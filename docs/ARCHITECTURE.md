# Cyber Thunder architecture

Cyber Thunder finds, explains and fixes misconfigurations and vulnerabilities on isolated, low-bandwidth
networks with a human approving every change. It does not reinvent the Navy's scanners: it turns their
output, plus its own deterministic checks, into approved, verified, reversible fixes, offline.

Principle: **deterministic tools detect; the local model only explains and plans; a human approves
remediation; the engine applies vetted changes with before-state, verification and rollback.**
Verified operations also require a signed identity, role permission and an explicit resource/action
grant. Inventory scope and target-account selection are independent checks.

## 1. Pipeline

```
 constrained link                      enclave
 ───────────────►  INGEST  ─────────►  DISCOVER ─► COLLECT ─► CHECK / HUNT / CVE ─► NORMALIZE (Finding)
 STIG delta, IAVM     │                   (inventory = scope)   per asset-type adapter          │
                      │                                                                          ▼
 ◄── OUTBOX / SYNC ◄─ REPORT ◄─ AUDIT ◄─ APPLY → VERIFY → (ROLLBACK) ◄─ APPROVE ◄─ PROPOSE ◄─ EXPLAIN
  local export        one-pager   hash chain   adapter, before-state,   human approvals  fix library   local model,
  staging             POA&M, CKLB            health check, auto-rollback                            validated citations
```

Kill switch (file, env or sentinel) blocks every apply and rollback edge. The audit log is the event
stream the UI tails.

## 2. Module map

| Path | Responsibility | State |
|---|---|---|
| `cyberthunder/findings/schema.py` | `Finding`, `Severity`, `Status`, `Reference`, citation extraction (STIG/CCI/CCE/CVE/ATT&CK/IAVM) | built |
| `cyberthunder/parsers/` | `xccdf.py` (DISA, SSG, oscap results, ARF), `cklb.py` (Evaluate-STIG, STIG Viewer 3), `nessus.py` (ACAS exports), `trivy.py`, `bulletin.py` (IAVM/CVE bulletins) | built |
| `cyberthunder/audit/chain.py` | append-only hash-chained JSONL + verifier | built |
| `cyberthunder/control/` | current principal, role/action mapping, account/resource policy, kill switch, approval state machine and separation of duties | built |
| `cyberthunder/security/` | signed-token validation, browser sessions, step-up policy, account-bound credentials/transports and saved artifact ownership | built |
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
| `cyberthunder/api/` | FastAPI app factory, authenticated routes, resource filtering, browser login/CSRF, SSE audit stream, static UI | built |
| `cyberthunder/ui/` | React + TypeScript + Mantine single-page app, built to `ui/dist` and served offline | built |
| `cyberthunder/store.py`, `cyberthunder/state/` | state layout; documents behind a json-files or SQLite backend, files beside them ([STATE.md](STATE.md)) | built |
| `cyberthunder/context.py` | `AppContext`: wires everything; CLI and API share it | built |
| `cyberthunder/cli.py` | `cyberthunder <cmd>`; modules add commands via `register_cli(subparsers)` | built |
| `range/` | local range: Rocky 9 VM notes, seed scripts, sample device configs/logs, `answer_key.json` | partial |

## 3. Core contracts

- **Finding** (`findings/schema.py`): one shape for every detector. `id = sha256(host|source|rule_id)[:16]`
  is stable across scans. `citations` lists every identifier the explain layer may cite. `fix_ref` is set
  when the engine resolves a library entry. `asset_type` tags the adapter.
- **Target / Inventory**: the inventory is the scope. `assert_in_scope()` runs before any collect or apply.
  Exact `environment` and a server-controlled `authorization_id` identify an ownership generation.
  Verified connections select credentials from protected account policy, not inventory authentication
  fields. References name server-side secrets or protected files; they do not contain the secrets.
- **Principal / AccessPolicy**: validated issuer/subject, human/workload kind and roles intersect
  exact account/group, target, environment and action grants. `node_actions` never grant target access;
  even `admin` needs explicit resource authority. See [ACCOUNT_ACCESS.md](ACCOUNT_ACCESS.md).
- **Transport**: `run(cmd, sudo=)`, `read_file`, `write_file`, `fetch`. Generic kinds: `local`, `ssh`,
  `winrm`, `fixture`. Adapter-specific kinds (`simulated`, `file`, `kubeconfig`) come from `Adapter.make_transport()`.
  `RecordingTransport` turns a live session into a fixture.
  In verified mode, `AppContext.transport_for()` reloads the target, binds the selected account,
  audits that selection and guards transport I/O against session, policy, scope or account changes.
  Local/file/fixture transports have no delegated verified-account design; simulation is explicit.
- **Adapter**: `discover`, `collect`, `check`, `hunt`, `cve`, `fixes`, `capture_before_state`, `apply`,
  `verify`, `health_check`, `rollback`. Detection methods are pure functions of `Collected` (no network),
  so they are unit-testable from fixtures. Use `make_finding()`.
- **FixEntry / FixLibrary**: the only source of executable payloads. Declares disruption, reboot,
  service restarts, reversibility, rollback kind, what to capture before, how to verify after.
- **Proposal / ApprovalGate**: PROPOSED → APPROVED → APPLYING → APPLIED → VERIFIED, with DENIED,
  CANCELLED, FAILED → ROLLED_BACK. Verified approvals bind independent human issuer/subject identities,
  source finding, target generation, fix and assessment. CAT I/high or unknown severity requires two
  approvers and remains PROPOSED after the first vote. Apply rechecks the saved quorum and current
  authority; apply/rollback retain kill guards. See [SEPARATION_OF_DUTIES.md](SEPARATION_OF_DUTIES.md).
- **AutomationPolicy**: off by default. The typed-signer standing-policy path remains a development
  facility; enabling it in verified mode is refused until verifiable policy signing is implemented.
- **AuditLog**: every edge, including rejections and blocks, with `prev_hash`/`hash`. Head hash is shown
  in the UI and printed on every report so a truncated log is detectable.
  Verified events retain the canonical audit actor and principal evidence; development labels are
  unverified. New principal evidence records `session_id: null` and, when a session identifier exists,
  a `session_fingerprint`: domain-separated SHA-256 over issuer, subject and session ID. This supports
  correlation only; it never grants access. Runtime authentication retains the raw session ID in
  memory, and historical saved records are unchanged. Account-selection evidence omits credentials.
- **Saved artifacts**: findings/proposals retain `authorization_scope`; scans, reports and outbox
  entries retain original `authorization_scopes`. Reads/actions/exports check the saved generation and
  current grants. Moving/deleting/reusing a target or lacking historical ownership cannot reassign
  its old evidence to today's owner. Reports filter before aggregation and preserve contributor scopes.
- **AppContext**: builds store, audit, kill switch, gate, inventory, adapters, fix library, policy,
  scanner, engine, explain, ingest, reports. Everything goes through it.

## 4. Guardrails and where they are enforced

| Rule | Enforced in |
|---|---|
| Only scan, read, propose, apply approved library fixes | `RemediationEngine.execute` runs `FixEntry.payload` only; adapters take a `FixEntry`, never free text |
| Never arbitrary shell from model output | `explain/` returns JSON text fields only; validator strips anything that is not a known identifier; no code path passes model output to a transport |
| Human approval before remediation | Principal human checks, separation-of-duties receipts and `ApprovalGate`; engine refuses incomplete approval |
| Role permission and exact resource grant | `AppContext.authorize`, `control/roles.py`, `control/access.py`; node administration is separate from target administration |
| Current target account on every guarded operation | `AppContext.transport_for`, `security/transport_guard.py`, transport internals and guarded kubeconfig commands |
| Protected policy and credential files | POSIX owner/mode checks; native Windows owner/DACL checks for access policy, selected Kubernetes files and OIDC cache; [Windows limits](WINDOWS_FILE_TRUST.md) |
| Original ownership of saved evidence | `security/resources.py`, service/route filtering and report contributor checks; unclassified legacy ownership denies verified access |
| Rollback for every change | `FixEntry.rollback_kind` required; engine captures `BeforeState` before apply and auto-rolls back on failed verify |
| Never touch hosts outside scope | `Inventory.assert_in_scope()` in Scanner and engine; scope changes are audited |
| Never delete logs or audit | audit log is append-only; no API deletes it; chain verification exposed |
| Everything logged | gate edges, kill switch, scans, explanations, policy, inventory, link and outbox events |
| Kill switch | `KillSwitch.guard()` in gate `APPLYING`/`ROLLED_BACK` edges; file, env `CT_KILL`, or sentinel `KILL` |

Content pulls (`cyberthunder/ingest/content/`) use read-only, certificate-verifying HTTPS to the fixed
DoD hosts, bounded downloads and guarded publication. Their `trusted_https_source` receipts record
transport provenance; offline signature/override rules are in [CONTENT_AUTHENTICITY.md](CONTENT_AUTHENTICITY.md).
Target transports, identity endpoints, configured model services and enabled database updates have
their own network paths. Deployment must provision and constrain those paths explicitly.

## 5. Modes

Authentication mode and execution transport are separate choices:

| Authentication setting | Boundary |
|---|---|
| `CT_AUTH_MODE=dev` | Explicitly unverified typed actors; verified role/account checks are bypassed. Loopback rehearsal with scratch state only. |
| `CT_AUTH_MODE=oidc` | Application validates signed identity and enforces role/resource policy. Non-loopback serving requires configured application TLS. |
| `CT_AUTH_MODE=mesh` | The same application token/policy checks behind operator-enforced authenticated mesh ingress and browser HTTPS. |
| `CT_SECURITY_MODE=fleet` | Requires verified authentication and stricter target trust; it refuses `dev`. |

| Mode | Transport | Use |
|---|---|---|
| live | ssh / winrm / kubeconfig | the event range, the local VM |
| fixture | `FixtureTransport(dir)` | tests; replay of a recorded live session |
| simulated | adapter emulator (stateful) | the demo before the range is reachable: seeded state matches `range/answer_key.json`; applying a fix changes the simulated state so verify and rollback are real state transitions |

`cyberthunder demo load` is a development control and puts one simulated target per adapter into the
inventory. The UI labels them simulated; emulation is not platform or identity-provider acceptance.

The native server and application container use the same guarded `cyberthunder serve` entrypoint.
Browser sessions are process-local: one worker/process is supported, and restart requires login.
Source Kubernetes/UDS manifests retain one replica and require explicit verified configuration plus
an identity/policy preflight. A gateway login or Ready pod does not establish application/realm
acceptance. See [AUTHORIZATION.md](AUTHORIZATION.md), [BROWSER_IDENTITY.md](BROWSER_IDENTITY.md) and
[PACKAGE_IDENTITY.md](PACKAGE_IDENTITY.md) for setup and deployment boundaries.

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
- Tests use isolated fixtures and explicitly controlled loopback services, including HTTPS identity
  and content providers. External/live targets require separate authorized acceptance.
- Paths must work on Windows and Linux (`pathlib`, no `/tmp` literals in library code).
- Each feature area owns its directory, its `tests/<area>/` and `tests/fixtures/<area>/`. Shared files
  (`schema.py`, `base.py`, `context.py`, `cli.py`, `app.py`, requirements, `.gitignore`) change only by
  agreement; new CLI commands go in the module's own `register_cli`, new API areas in `api/routes/<name>.py`.
- Environment variables are prefixed `CT_`. Verified attribution comes from the current principal,
  not a supplied actor string. Typed actors remain unverified in development mode; reserved machine
  labels are also refused on development human-only edges.
- Every finding cites something: a STIG ID, CCI, CVE, IAVM or ATT&CK technique. Hunt findings cite ATT&CK.
- Comments and docs are written for the Sailor or engineer who maintains this later. No tool names,
  assistant names or generation notes anywhere in the repository or in commit messages.
- Commit as yourself on your own branch; the repo hook strips any automated co-author trailers.
