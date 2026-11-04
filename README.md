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

## Status

Status reflects the module build in progress. "As designed" means the behaviour is specified in
[ARCHITECTURE](docs/ARCHITECTURE.md), [API](docs/API.md) and [UI](docs/UI.md) but has not been verified
against the merged tree yet.

| Module | Path | Status |
|---|---|---|
| Findings schema, XCCDF and CKLB parsers | `cyberthunder/findings/`, `parsers/` | built |
| Hash-chained audit log | `cyberthunder/audit/` | built |
| Kill switch, approval gate, standing-approval policy | `cyberthunder/control/` | built |
| Inventory and scope guardrail | `cyberthunder/inventory/` | built |
| Transports (local, ssh, fixture; winrm) | `cyberthunder/transport/` | winrm in progress |
| Adapter contract and fix library | `cyberthunder/adapters/base.py`, `remediation/` | built |
| Remediation engine (apply, verify, auto-rollback) | `cyberthunder/remediation/engine.py` | in progress |
| Scan orchestration | `cyberthunder/scan.py` | in progress |
| Linux, Cisco, Kubernetes, container, Windows adapters | `cyberthunder/adapters/<type>/` | in progress |
| Local-model explanations with citation validation | `cyberthunder/explain/` | in progress |
| STIG delta ingest, link emulation, outbox | `cyberthunder/ingest/` | in progress |
| Reports (one-pager, POA&M, checklist, path to fleet) | `cyberthunder/report/` | in progress |
| HTTP API | `cyberthunder/api/` | factory built, routes in progress |
| Web UI | `cyberthunder/ui/` | in progress |
| Local range and answer keys | `range/` | partial |

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
python -m cyberthunder scans
```

Explain a finding and propose a fix (use an id from the findings list; `--help` on each command shows its flags):

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

Force a failure and watch the rollback: in Settings turn on "force verification failure on next apply", then
apply another approved fix. Verification fails, the engine rolls back automatically, and **Diff** shows
before and after. From the CLI the same flow is `apply` (with the simulate-failure flag), `diff`, `rollback`.

Verify the audit chain (also the green badge in the UI header):

```bash
python -m cyberthunder audit verify
```

Other commands, as specified: `targets ...` (inventory), `discover ...` (read-only asset facts), `ingest stig|bulletin`
(constrained-link updates), `link` (kbps, latency, connected), `outbox` (reports queued for sync),
`report ...` (one-pager, POA&M, checklist, path to fleet), `demo reset|run`.

## Documentation

| Document | What it is |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | pipeline, contracts, guardrails, how to add an adapter |
| [docs/API.md](docs/API.md) | HTTP API v1 |
| [docs/UI.md](docs/UI.md) | screens and behaviour |
| [docs/DEMO.md](docs/DEMO.md) | 10-minute demo runbook |
| [docs/SUBMISSION.md](docs/SUBMISSION.md) | portal submission draft |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | working in this repo |
| [docs/PLAN.md](docs/PLAN.md), [docs/CONTEXT.md](docs/CONTEXT.md) | build plan and event context |
| [range/README.md](range/README.md) | local range, link emulation, answer keys |

## Guardrails (enforced in code)

| Question | Answer | Where |
|---|---|---|
| What may it do | Scan, read configs and logs, propose fixes, apply approved fixes from the vetted library | `RemediationEngine.execute` runs `FixEntry` payloads only |
| What may it never do | Run shell text from a model, change anything unapproved, touch hosts outside scope, delete logs or audit | `explain/` returns validated JSON text; `Inventory.assert_in_scope()`; audit is append-only |
| What needs human approval | Every state-changing action | `ApprovalGate` human-only edges reject actors `agent`, `llm`, `system` |
| How is it logged | Every scan, finding, proposal, approval, denial, apply, verify, rollback, kill, scope and policy change | hash-chained audit log; head hash shown in the UI and on every report |
| How is it stopped | Kill switch (file, `CT_KILL`, or `KILL` sentinel) blocks every apply and rollback | `KillSwitch.guard()` |
| Can it be undone | Every library fix declares a rollback; before-state is captured first; failed verify rolls back automatically | `FixEntry.rollback_kind`, `BeforeState` |

## Git

Commits carry the human author only. The hook path is per-clone configuration, so every teammate runs this once
after cloning:

```bash
git config core.hooksPath .githooks
```

Work on your own branch (`<name>/<topic>`) under your own identity, then open a pull request. See
[docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).
