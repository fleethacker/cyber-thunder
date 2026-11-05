# Cyber Thunder

Cyber Thunder finds, explains and fixes misconfigurations and vulnerabilities on isolated, low-bandwidth
networks, with a human approving every change. It takes the output of the scanners the Navy already fields,
adds its own deterministic checks and an intrusion hunt, and turns the result into a queue of cited,
plain-English decisions. An IT Sailor approves or denies each fix; approved fixes are applied from a vetted
library, verified by rescan, and rolled back automatically if verification fails. Everything runs offline and
every action lands in a hash-chained audit log.

**We don't reinvent the Navy's scanners. We turn their output into approved, verified, reversible fixes, offline.**

Built for the Department of the Navy hackathon in Norfolk (FLEETHACKER, 4-6 Nov 2026), use case
*Autonomous Cyber Defender*. Deterministic tools detect; a local model only explains; a human decides.

## What it looks like

The decision queue: each card answers what is wrong, why it matters (with citations), what will change, what could
break, and how to undo it. The kill switch and the audit-chain badge are on every screen.

![Decision queue](docs/images/decisions.jpg)

Discovery proposes what it found on the enclave; a named person accepts a device into scope, with a reason, or ignores it.
The application currently records a typed, self-asserted approver name. UDS gateway SSO does not yet bind that
name to a verified application principal or per-user target credential; see [identity work](docs/BACKLOG.md#1-identity-credentials-and-zero-trust).

![Assets and discovery](docs/images/assets-discovery.jpg)

Every action, including refusals and blocks, lands in the hash-chained audit trail, streamed live.

![Audit trail](docs/images/audit.jpg)

Reports keep searchable history of commander one-pagers, POA&Ms, checklists and target reports, alongside the detection score against the range answer keys.

![Reports](docs/images/reports.jpg)

## Status

The rehearsal in [DEMO](docs/DEMO.md) runs the pipeline end to end on the simulated range.

<!-- validation-status:start -->
Rocky 9 over SSH: 12/12 Linux seeds detected; one fix applied, verified and rolled back.

The same range run detected 6/6 Podman seeds and 10/10 k3s seeds (28/28 across all three targets).

The WSL2 UDS demo cluster was scanned over kubectl: 127 findings and no adapter errors.

These are recorded real-target results, not full benchmark coverage. Windows/WinRM, Cisco device changes and other platform versions still need real testing. See the [validation matrix](docs/VALIDATION.md) for evidence and missing run metadata, and [coverage](docs/COVERAGE.md) for check/fix counts.
<!-- validation-status:end -->

| Module | Path | Status |
|---|---|---|
| Findings schema, XCCDF and CKLB parsers | `cyberthunder/findings/`, `parsers/` | built |
| Hash-chained audit log | `cyberthunder/audit/` | built |
| Kill switch, approval gate, standing-approval policy | `cyberthunder/control/` | built |
| Inventory and scope guardrail | `cyberthunder/inventory/` | built |
| Transports (local, ssh, fixture, winrm) | `cyberthunder/transport/` | built |
| Adapter contract and fix library | `cyberthunder/adapters/base.py`, `remediation/` | built |
| Remediation engine (apply, verify, auto-rollback) | `cyberthunder/remediation/engine.py` | built |
| Scan orchestration | `cyberthunder/scan.py` | built |
| Linux, Cisco, Kubernetes, container, Windows adapters | `cyberthunder/adapters/<type>/` | built |
| DISA SCAP benchmarks run by the tool itself (OVAL evaluator for Windows, DISA datastreams through oscap on Linux) | `cyberthunder/scap/` | built |
| Local-model explanations with citation validation | `cyberthunder/explain/` | built |
| STIG delta ingest, link emulation, outbox | `cyberthunder/ingest/` | built |
| STIG Library (saved product/type subscriptions, catalog versions, validated uploads, resumable downloads and offline manifests) | `cyberthunder/ingest/content/` | built |
| Reports (one-pager, POA&M, checklist, searchable history) | `cyberthunder/report/` | built |
| HTTP API | `cyberthunder/api/` | built |
| Web UI | `cyberthunder/ui/` | built |
| Asset discovery (scoped sweeps, device typing, propose-only inventory, rogue devices) | `cyberthunder/discovery/` | built |
| Local range and answer keys | `range/` | built (six answer keys) |

## Quick start

Python 3.11 or later. Clone outside any synced folder (for example `C:\dev\cyber-thunder`).

Install runtime and test dependencies (online):

```bash
python -m pip install -r requirements-dev.txt
```

Or offline, from the wheels in `vendor/`:

```bash
python -m pip install --no-index --find-links vendor -r requirements-dev.txt
```

Run the tests:

```bash
python -m pytest -q
```

Use a scratch state directory for everything below so a rehearsal never touches real state:

```bash
export CT_STATE_DIR="$(mktemp -d)"
```

Load the simulated range (one simulated asset per adapter: Linux host, switch config, k3s cluster,
container host, Windows host) and check the node:

```bash
python -m cyberthunder demo load
```

```bash
python -m cyberthunder status
```

Scan, then look at what was found:

```bash
python -m cyberthunder scan
```

```bash
python -m cyberthunder scans list
```

```bash
python -m cyberthunder scans show <scan-id>
```

The scan creates a proposal for every finding that has a library fix. List them, and read one (it prints its
`finding_id`; `--help` on each command shows its flags):

```bash
python -m cyberthunder proposals list
```

```bash
python -m cyberthunder proposals show <proposal-id>
```

Explain a finding (needs the local model server, otherwise a template explains) and propose a fix by hand if
a finding has no proposal yet:

```bash
python -m cyberthunder explain <finding-id>
```

```bash
python -m cyberthunder propose <finding-id>
```

Start the server and open the UI at <http://127.0.0.1:8000>:

```bash
python -m cyberthunder serve
```

In the UI, set your name in Settings, open **Decisions**, press **Approve** on a card, then **Apply**. The card
shows the step timeline: scope check, before-state captured, applied, verified.

Open **STIG Library** for uploads, downloads, versions and separate live-check/download/import times.
Subscriptions default to inventory matches; choose manual product/type checkboxes and **Save selections**
before checking or pulling. XML/ZIP uploads work offline (32 MiB per file), as do manifest/folder imports.
Reconnect options apply only on reconnect; periodic checks are server-configured. Bundled references and
installed content are labelled separately, and neither implies full executable scan coverage.
See [content and subscriptions](docs/CONTENT.md).

Force a failure and watch the rollback: in Settings turn on "force verification failure on next apply", then
apply another approved fix. Verification fails, the engine rolls back automatically, and **Diff** shows
before and after. From the CLI the same flow is `proposals approve <id>`, `apply <id> [--simulate-verify-fail]`, `diff <id>`, `rollback <id>`; `apply` refuses a proposal that has not been approved.

Verify the audit chain (also the green badge in the UI header):

```bash
python -m cyberthunder audit verify
```

Other commands: `targets ...` (inventory; `targets discover <id>` reads asset facts), `discover scopes|sweep|list|accept|ignore|findings|applicable`
(network discovery, needs a saved scope first), `scap info|plan|eval|subset` (DISA SCAP benchmarks run by the tool;
[docs/SCAP.md](docs/SCAP.md)), `ingest stig|bulletin` (constrained-link updates by file), `ingest check|pull|updates|content|manifest|fetch-manifest|import-dir`
(STIG content from cyber.mil when the link is up, a manifest round trip when it is not; [docs/CONTENT.md](docs/CONTENT.md)),
`link show|set` (kbps, latency, connected), `outbox list|sync` (reports queued for sync), `verify` and `diff` (a proposal
after apply), `kill engage|release`, `audit verify|tail`, `parse` (scanner output files to findings), `report ...` (one-pager,
POA&M, checklist), `demo reset|run`, `state info|migrate` (where the documents live: json files or SQLite;
[docs/STATE.md](docs/STATE.md)).

## Documentation

| Document | What it is |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | pipeline, contracts, guardrails, how to add an adapter |
| [docs/VALIDATION.md](docs/VALIDATION.md) | real-platform evidence, untested versions and missing run metadata |
| [docs/COVERAGE.md](docs/COVERAGE.md) | implemented checks, benchmark denominators, executable fixes and runbooks |
| [docs/CONFIDENCE.md](docs/CONFIDENCE.md) | evidence-strength grades, provenance, freshness and limits |
| [docs/FINDING_REVIEW.md](docs/FINDING_REVIEW.md) | reasoned reviews, false positives, expiry, history and remediation guards |
| [docs/REPORT_ASSURANCE.md](docs/REPORT_ASSURANCE.md) | raw scanner results and review decisions in commander and POA&M reports |
| [docs/SCAP.md](docs/SCAP.md) | running the DISA SCAP benchmarks ourselves: supported OVAL subset, collection plan, limits |
| [docs/CONTENT.md](docs/CONTENT.md) | STIG Library, saved subscriptions, versions and sync times, uploads/downloads and offline transfers |
| [docs/ADAPTING.md](docs/ADAPTING.md) | taking it to a new environment: inventory, credentials, benchmarks, adapters, checklist |
| [docs/API.md](docs/API.md) | HTTP API v1 |
| [docs/STATE.md](docs/STATE.md) | the state directory: documents (json files or SQLite) and files, `state migrate` and `state info`, WAL on a local volume only, backups |
| [docs/UI.md](docs/UI.md) | screens and behaviour |
| [docs/FINDINGS.md](docs/FINDINGS.md) | finding categories, filters, search, sorting and saved views |
| [docs/DEMO.md](docs/DEMO.md) | 10-minute demo runbook |
| [docs/SUBMISSION.md](docs/SUBMISSION.md) | portal submission draft |
| [docs/BACKLOG.md](docs/BACKLOG.md) | what should be done and is not: identity and zero trust first, then what stands between the prototype and a limited deployment, then every other known gap |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | working in this repo |
| [docs/PLAN.md](docs/PLAN.md), [docs/CONTEXT.md](docs/CONTEXT.md) | build plan and event context |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | UDS cluster deployment: macOS, Linux, and Windows through WSL2 |
| [range/README.md](range/README.md) | local range, link emulation, answer keys |

## Guardrails (enforced in code)

| Question | Answer | Where |
|---|---|---|
| What may it do | Scan, read configs and logs, propose fixes, apply approved fixes from the vetted library, pull public STIG content from two allow-listed DoD hosts when the link is up | `RemediationEngine.execute` runs `FixEntry` payloads only |
| What may it never do | Run shell text from a model, change anything unapproved, touch hosts outside scope, delete logs or audit | `explain/` returns validated JSON text; `Inventory.assert_in_scope()`; audit is append-only |
| What needs human approval | Every state-changing action | `ApprovalGate` human-only edges reject actors `agent`, `llm`, `system` |
| How is it logged | Every scan, finding, proposal, approval, denial, apply, verify, rollback, kill, scope and policy change | hash-chained audit log; head hash shown in the UI and on every report |
| How is it stopped | Kill switch (file, `CT_KILL`, or `KILL` sentinel) blocks every apply, rollback and content pull | `KillSwitch.guard()` |
| Can it be undone | Every library fix declares a rollback; before-state is captured first; failed verify rolls back automatically | `FixEntry.rollback_kind`, `BeforeState` |

## Cluster deployment

Cyber Thunder can run natively with the Python CLI/web server above, or as the same
application in a container. Both deployment paths retain approval, audit and rollback;
both still require the identity and credential work in the backlog before fielding.
See the [application container guide](deploy/kubernetes/README.md) and
[Zarf package](packages/cyberthunder/README.md) for the merged container and UDS SSO configuration.

SQLite stores scan/findings/discovery documents and library preferences/sync metadata. Persist and back up
the **entire state directory**, including raw scanner files, inventory, audit, rollback snapshots and content;
mount the whole directory on the persistent volume. See [state and backups](docs/STATE.md).

Deploy UDS Core and Podinfo with `./deploy.sh`. See
[UDS cluster deployment](docs/DEPLOYMENT.md) for macOS Podman, Linux,
existing Kubernetes clusters, and the optional `./deploy.sh dev` identity setup.

## Keeping a complete local copy

GitHub is the shared copy, not the only one. Before a demo or at the end of a day, make a bundle with the whole
history and a plain zip of the working tree; see [CONTRIBUTING](docs/CONTRIBUTING.md#backups-and-restore).

## Git

Commits carry the human author only. The hook path is per-clone configuration, so every teammate runs this once
after cloning:

```bash
git config core.hooksPath .githooks
```

Work on your own branch (`<name>/<topic>`) under your own identity, then open a pull request. See
[docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).
