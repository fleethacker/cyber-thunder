# Cyber Thunder build plan — Day 1 (Wed 4 Nov 2026)

Companion to [CONTEXT.md](CONTEXT.md). That file is the *what*; this is the *how, on this hardware, in 20 hours*.

## 1. Hack laptop facts (measured 4 Nov 09:20)

| Item | Value | Consequence |
|---|---|---|
| CPU / RAM | i7-6820HQ, 8 threads, 64 GB | Measured 4 Nov: `qwen2.5:3b` 12.3 tok/s, `qwen2.5:7b-instruct` 3.0 tok/s |
| GPU | NVIDIA Quadro M1200, 4 GB (CUDA 5.0) | `qwen2.5:3b` fits fully on GPU; 7B gets partial offload |
| Hypervisor | VMware Workstation 17.5.2 (no VMs yet) | Local range = VMware VMs. No Docker, no WSL distro |
| Python | 3.12 (also 3.13/3.14) | Core is stdlib-only; extras vendored as wheels for offline install |
| Local LLM | Ollama installed 4 Nov (per-user) serving open-weights models | **Default `gemma3:4b`** (Google open weights, 9.6 tok/s), fallback `qwen2.5:3b` (11.4 tok/s); set via `CT_LLM_MODEL`. Bench table in section 9 |
| Admin | local admin, UAC prompt needed | WSL/Hyper-V possible but not required |
| Network | internet OK (pre-venue) | Pull everything now; assume nothing at the venue |
| Repo | `C:\Users\joshu\OneDrive\Desktop\FleetHacker` (git init done, branch `main`) | OneDrive + git is flaky: pause sync on this folder or move to `C:\dev\FleetHacker` |

## 2. Decisions made (change only with a reason)

1. **Python 3.12 core, stdlib-only kernel.** Schema, parsers, audit chain, kill switch, approval gate import nothing outside the standard library. FastAPI/uvicorn only for the UI; wheels in `vendor/`.
2. **LLM never calls tools.** Scanners and hunt checks are deterministic. The LLM gets structured findings and returns `{risk, impact, plan, citations[]}`; a validator rejects any citation not present in `Finding.citations`. That removes tool-calling reliability as a risk on a 3B/7B CPU model.
3. **Explanations are precomputed.** After each scan the explain stage runs in the background; the Sailor never waits on inference during the demo.
4. **Fixes come only from a vetted library** (ComplianceAsCode `<fix system="urn:xccdf:fix:script:sh">` per rule, plus hand-written hunt remediations). The LLM selects a `fix_ref`; it never emits shell.
5. **Range target = Rocky Linux 9 VM** with `openscap-scanner` + `scap-security-guide` (DISA STIG profile ships in the package). Windows target only if a teammate owns PowerSTIG.
6. **Every edge is audit-logged and the chain head hash is shown in the UI** (removing the last record is the one tamper the chain alone cannot catch; publishing the head closes it).

## 3. What exists now

Built and merged on the integration branch:

```
cyberthunder/findings/schema.py     Finding, Severity, Status, references, citation extraction
cyberthunder/parsers/               xccdf.py (DISA, SSG, oscap, ARF), cklb.py (Evaluate-STIG, STIG Viewer 3)
cyberthunder/audit/chain.py         hash-chained JSONL + verify
cyberthunder/control/               killswitch.py, approvals.py (state machine), policy.py (standing approval)
cyberthunder/inventory/targets.py   Target, Inventory, scope guardrail
cyberthunder/transport/             base contract, local, ssh, fixture (replay/record)
cyberthunder/adapters/base.py       Adapter contract, registry, make_finding()
cyberthunder/remediation/           library.py (FixEntry, FixLibrary), models.py; operator-initiated rollback
cyberthunder/store.py, context.py, config.py, cli.py, api/ factory
range/                              Rocky 9 notes, seed scripts per area, six answer keys in answer_key/
scripts/setup_dev.ps1               idempotent dev setup (model server, models, pip, vendor wheels)
```

Also merged since: adapters (linux, cisco, kubernetes, containers, windows), transport/winrm, remediation/engine.py,
scan.py, explain, ingest, report, discovery, the HTTP routes and the React UI. Answer keys:
`range/answer_key/{linux,cisco_ios,kubernetes,containers,windows,discovery}.json`.

Open: the discovery page in the UI is a placeholder, and the UI Diff view does not list every file a fix touches.
The rehearsal in [DEMO.md](DEMO.md) is the end-to-end check.

Run: `python -m pytest -q`, then follow the quick start in the README.

## 4. Schedule

Status (Wed 4 Nov): kernel and modules merged and integrated; the full rehearsal is next. The blocks below are the original plan and stay as the order of work.

### Day 1 — Wed (after team formation, ~6 h)
| Block | Deliverable | Owner |
|---|---|---|
| 0 | Core kernel + tests (done) | Joshua |
| 1 | Rocky 9 VM up, snapshot `clean`, seeded, snapshot `seeded`; first real `oscap` results parsed end-to-end | Joshua |
| 2 | `cyberthunder scan --target acd-target-01`: SSH → run oscap → fetch results → parse → `findings.json` → audit | Joshua |
| 3 | Approval UI (FastAPI + Jinja, no JS framework): findings list, detail with citations, Approve/Deny, audit tail with head hash, kill switch button | teammate A |
| 4 | Explain layer: Ollama client, prompt, JSON output, citation validator, background precompute | teammate B or Joshua |
| EOD | Demo path 1 works: scan → findings → explanation → approve (no apply yet) | all |

### Day 2 — Thu (~10 h)
| Block | Deliverable |
|---|---|
| 1 | Remediation library: SSG fix scripts by rule id; before-state capture (tar of touched files + command output); apply via SSH; rescan verify; auto-rollback on verify failure |
| 2 | Hunt module (Linux): extra uid-0 users, rogue authorized_keys, cron/systemd persistence, unexpected listeners, SUID deltas, timestomped files, auth anomalies; each result is a `Finding` with `source=hunt` |
| 3 | Low-bandwidth story: STIG release delta (old vs new XCCDF → rule-level diff), compress with tc.cpp or zstd, replay over emulated link (`tc qdisc netem` on the VM or a throttling proxy), sync-on-reconnect queue for reports |
| 4 | Commander one-pager + path-to-fleet generator (Jinja → HTML/Markdown) |
| 5 | Forced-failure demo: verification fails → automatic rollback → audit shows it |
| 6 | Two full rehearsals; freeze features |

### Day 3 — Fri AM
Polish, submission fields (mission owner, technical owner, next experiment, resources, 30/60/90), friction log, pitch.

## 5. Demo script (10 min)
1. Link is "down" (netem 56 kbit, 500 ms). New STIG release arrives as a 40 KB delta instead of a 3 MB download; show transfer time both ways.
2. `cyberthunder scan` runs OpenSCAP on the target; findings appear with CAT levels and cited rule IDs.
3. Hunt panel: rogue uid-0 account, `kworkerd.service` listener on 4444, timestomped script in `/usr/local/lib/.cache`.
4. Explanation panel: commander-level risk, every sentence carries a STIG/CCI/CVE citation that links back to the finding.
5. IT Sailor approves "Disable SSH root login" and "Remove rogue uid-0 user"; denies one.
6. Apply → rescan → verified. Then a fix whose verification is rigged to fail → automatic rollback → before/after diff.
7. Kill switch pressed mid-queue; pending actions blocked and logged.
8. Audit view: chain verified, head hash on screen; edit a line in the file live, re-verify, chain breaks at that seq.
9. Commander one-pager + path to fleet.

## 6. Need from you (Joshua)

- **VM:** download Rocky 9 minimal ISO (rockylinux.org/download, ~2 GB) and build `acd-target-01` in VMware per `range/README.md`. Take snapshot `clean`, run `range/seed_misconfig.sh`, take snapshot `seeded`.
- **Repo location:** pause OneDrive sync for this folder (right-click → Free up space / Settings → Sync and backup → Manage backup) or move the repo to `C:\dev\FleetHacker`. Then make the first commit (command in README).
- **Range questions for the organizers:** OS mix and count; SSH/WinRM credentials; emulated link speed; is Evaluate-STIG/SCC present; is "Cyber Thunder" your team.
- **IT Sailor:** recruit as approver. Ask two numbers: hours per STIG release per network today, and days from vuln bulletin to verified fix. Those become the 30% rubric slide.
- **Home GPU (RX 7900 XT):** useful for *development* only (prompt tuning, bigger model comparison). If you want it, install Tailscale on both machines (software VPN, not wireless gear) and run Ollama at home with `OLLAMA_HOST=0.0.0.0`; point `CT_LLM_URL` at it. Test from the venue network early; expect it may be blocked. The judged demo runs on the laptop regardless.
- **Attribution:** repo hook `.githooks/commit-msg` strips any AI co-author/generated-with trailers; `core.hooksPath` is set. Commits carry only `Joshua Ott <Joshua.ott@outlook.com>`.

## 7. Risks

| Risk | Mitigation |
|---|---|
| Range not live or no SSH access | Local VMware range is the primary target; range is a bonus |
| 7B is 3 tok/s on CPU | 3B on GPU is 12 tok/s and is the live model; 7B only for background precompute; stream tokens in UI |
| SSG `stig` profile missing on Rocky | fall back to `ssg-rl9-ds.xml` CIS profile or use upstream `ssg-rhel9-ds.xml` content |
| Venue network blocks pulls | everything (models, wheels, ISO, SSG content) pulled before arriving |
| OneDrive corrupts `.git` | pause sync / move repo |

## 8. Sponsor tools: who uses what (from the 4 Nov access one-pagers)

| Tool | What it is | Our use | Access |
|---|---|---|---|
| Joshua's AI coding assistant | agentic IDE | Joshua: kernel, apply/verify/rollback, compression | already running |
| Google Antigravity (cloud VM) | agentic IDE, Gemini-backed, preinstalled on team VM | teammates: approval UI, hunt module; Google onsite support | team link from team lead/Events |
| Google Antigravity **SDK** (`pip install google-antigravity litert-lm`) | Python agent SDK with an offline mode: `LiteRTAgentConfig` + Gemma 4 26B A4B on LiteRT-LM | stretch runtime path, see section 10 | public PyPI; Windows wheel exists |
| Gemini Enterprise / Agent Builder | no/low-code cloud agents | not in the runtime (cloud); optional for pitch research | same team link |
| Gemini Notebook | research + presentation prep | Friday pitch deck | same team link |
| Cursor + Grok (SpaceXSI) | coding assistant | any teammate who prefers it | redeem QR in PDF |
| Codex (OpenAI) | coding assistant | any teammate who prefers it | key in private file |
| Codename: Ark (Defense Unicorns) | plain-language -> web app; UDS packaging | Day 2: "App packaging" of Cyber Thunder as a UDS package = concrete Speed-to-Fleet artifact | create account + email Events for approval (do today) |
| Ollama + Gemma 3 / Qwen2.5 | local open-weights inference | **the only AI inside Cyber Thunder at runtime** (offline, on the enclave) | installed on the hack laptop |

Rule: the judged system never calls a cloud model. Everything above the last row is for building it.

## 9. Runtime model benchmark (hack laptop, 4 Nov, `scripts/bench_llm.py`, JSON mode, 1 finding)

| Model | tok/s | wall for one explanation | JSON valid | Citation discipline |
|---|---|---|---|---|
| gemma3:4b | 9.6 | 34 s | yes | cited correct IDs but as `key: value` strings; passes once the validator extracts IDs by regex |
| qwen2.5:3b | 11.4 | 25 s | yes | exact STIG/CCI IDs; mangled the `fix_ref` string (dropped by validator) |
| qwen2.5:7b-instruct | 3.0 | 61 s | yes | same as 3b, too slow for live use |
| gemma3:1b | 26.6 | 10 s | yes | wrote `"risk": 2` instead of two sentences; quality too low |

Decision: `gemma3:4b` default (sponsor-aligned, offline, good prose), `qwen2.5:3b` fallback. Explanations are
precomputed after each scan, so 30 s per finding is fine. The validator normalizes citations by regex
(SV-/V-/STIG-ID/CCI/CCE/CVE), drops anything not present in `Finding.citations`, and retries once on an empty set.

## 10. Antigravity offline path (verified 4 Nov against github.com/google-antigravity/antigravity-sdk-python)

Facts from the SDK README:
- "supports local, offline agentic workflows powered by Gemma 4 and LiteRT-LM"; class `LiteRTAgentConfig(model_path=...)`.
- Works best with `gemma-4-26B-A4B-it-gpu.litertlm`; "at least 24GB of VRAM/shared memory"; 64K context recommended.
- Import: `litert-lm import --from-huggingface-repo=litert-community/gemma-4-26B-A4B-it-litert-lm gemma-4-26B-A4B-it-gpu.litertlm gemma4-26b`
- `google-antigravity` 0.1.23 publishes a `win_amd64` wheel (46 MB); `litert-lm` 0.19.0 is pure Python (pulls its runtime).
- README does not mention Ollama / OpenAI-compatible endpoints for the SDK (third-party blogs claim one; unconfirmed).

What that means for us:
- Hack laptop (4 GB VRAM) cannot meet the 24 GB guidance. Joshua's home RX 7900 XT has 20 GB; with shared memory it may run, unverified (and AMD support for LiteRT-LM is unconfirmed).
- Architecturally both paths are "a local Gemma behind a thin explain() interface". Day 1 ships on Ollama + `gemma3:4b` (measured). The Antigravity SDK path is a **Day 2 stretch** for one teammate: if it runs on any box we own, the pitch gains "same Google SDK the Navy is being trained on, running offline". If not, nothing else changes.
- Do not let the stretch path block the demo. The interface is `cyberthunder/explain/llm.py: explain(finding) -> {risk, impact, plan, citations}`; the backend is a config value.
