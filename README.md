# Cyber Thunder — Autonomous Cyber Defender (ACD)

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
python -m acd parse tests/fixtures/sample_results.xccdf.xml tests/fixtures/sample.cklb --out state/findings.json
```

```bash
python -m acd --actor sailor1 kill engage --reason "demo"
```

```bash
python -m acd audit verify state/audit.jsonl
```

## Layout

| Path | Purpose |
|---|---|
| `acd/findings/` | unified `Finding` schema every detector normalizes into |
| `acd/parsers/` | XCCDF (DISA / SSG / oscap / ARF) and CKLB (Evaluate-STIG, STIG Viewer 3) |
| `acd/audit/` | append-only hash-chained audit log + verifier |
| `acd/control/` | kill switch and approval-gated state machine (agent may propose, never approve) |
| `acd/cli.py` | `python -m acd ...` |
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

Local work before the team repo exists lives on `joshua/acd-kernel`. First commit:

```bash
git add -A && git commit -m "ACD kernel: findings schema, XCCDF/CKLB parsers, hash-chained audit, kill switch, approval gate"
```

When the team lead posts the GitHub repo:

```bash
git remote add origin <TEAM_REPO_URL>
```

```bash
git fetch origin
```

If `origin/main` already has content, rebase onto it and push the branch for a PR:

```bash
git rebase origin/main
```

```bash
git push -u origin joshua/acd-kernel
```

If the team repo is empty, push this branch as `main` instead:

```bash
git push -u origin joshua/acd-kernel:main
```

Prefer a fresh clone into `C:\dev\FleetHacker` after the push; git inside OneDrive is unreliable.
