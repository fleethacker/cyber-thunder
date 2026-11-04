# Cyber Thunder — Autonomous Cyber Defender

FLEETHACKER Norfolk, Nov 4–6 2026. Use case: *find, explain and fix misconfigurations and vulnerabilities in
isolated, low-bandwidth networks with a human approving every change.*

**We don't reinvent the Navy's scanners. We turn their output into approved, verified, reversible fixes, offline.**

- Event, rubric, use case, architecture, rules: [docs/CONTEXT.md](docs/CONTEXT.md)
- Build plan, schedule, demo script, what we need: [docs/PLAN.md](docs/PLAN.md)
- Local range (Rocky 9 VM, seeded misconfigs + hidden intrusion): [range/README.md](range/README.md)

## Quick start

```bash
python -m unittest discover -s tests
```

```bash
python -m cyberthunder parse tests/fixtures/sample_results.xccdf.xml tests/fixtures/sample.cklb --out state/findings.json
```

```bash
python -m cyberthunder --actor sailor1 kill engage --reason "demo"
```

```bash
python -m cyberthunder audit verify state/audit.jsonl
```

## Layout

| Path | Purpose |
|---|---|
| `cyberthunder/findings/` | unified `Finding` schema every detector normalizes into |
| `cyberthunder/parsers/` | XCCDF (DISA / SSG / oscap / ARF) and CKLB (Evaluate-STIG, STIG Viewer 3) |
| `cyberthunder/audit/` | append-only hash-chained audit log + verifier |
| `cyberthunder/control/` | kill switch and approval-gated state machine (agent may propose, never approve) |
| `cyberthunder/cli.py` | `python -m cyberthunder ...` |
| `range/` | VM build notes, seed script, answer key for detection-rate scoring |
| `vendor/` | wheels for `pip install --no-index --find-links vendor -r requirements.txt` |

## Guardrails (enforced in code)

| Rule | Where |
|---|---|
| Agent may scan, read, propose, apply approved library fixes | `ApprovalGate`, `fix_ref` only |
| Never arbitrary shell from LLM output | explain layer returns JSON; fixes come from the library |
| Every state change needs human approval | `HUMAN_ONLY` edges reject actor `agent` |
| Every action logged | `AuditLog.append` on every edge, including rejections and blocks |
| Kill switch | `KillSwitch.guard()` before apply/rollback; file, env or sentinel |

## Git

Commits are attributed to the human author only (see docs/CONTEXT.md section 1). `.githooks/commit-msg` strips AI co-author
trailers. The hook path is per-clone config, so **every teammate runs this once after cloning**:

```bash
git config core.hooksPath .githooks
```

Each teammate works on their own branch (`<name>/<topic>`) under their own git identity and opens a PR.

When the team repo already has content, rebase onto it and push your branch for a PR:

```bash
git fetch origin && git rebase origin/main
```

```bash
git push -u origin <name>/<topic>
```

Clone outside OneDrive (for example `C:\dev\cyber-thunder`); git inside a synced folder is unreliable.
