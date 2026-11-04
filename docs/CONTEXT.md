# FLEETHACKER Norfolk — Cyber Thunder team context

Shared context for the team: event, rubric, use case, architecture, logistics, open items.
Build plan and schedule: [PLAN.md](PLAN.md).

---
## 1. Working rules (read first)

- **Git attribution:** AI coding tools are expected and encouraged, but every commit is attributed to the human author only. No AI co-author or "generated with" trailers. `.githooks/commit-msg` strips them; run `git config core.hooksPath .githooks` once after cloning.
- Each teammate commits under their own git identity, on their own branch (`<name>/<topic>`), and opens a PR.
- **Never touch live Navy networks.** Build only against the event's isolated range or local VMs/containers.
- No CAC-gated government code (Evaluate-STIG, SCC) gets copied into this repo. Call those tools externally and parse their output only.

---
## 2. Event

| Item | Detail |
|---|---|
| Name | Department of the Navy AI Hackathon — Norfolk ("FLEETHACKER") |
| Dates | Nov 4–6, 2026 (Day 1 = Wed Nov 4) |
| Host | Task Force Hopper, with Maximus; endorsed by OSW CDAO |
| Signed by | Justin Fanelli (DON CTO), Dr. Ciro Lopez (DON Acting CDAO) |
| POCs | Tomer Atzili (DON Frontier AI Lead), LT Brandon Del Rosario (Task Force Hopper) |
| Classification | Unclassified |
| Portal | cdao.hackathon.maximus.com (event slug `norfolk`) |
| Joshua's profile | cdao.hackathon.maximus.com/users/joshuaott |

**Build time:** roughly Wed after kickoff/team formation, all day Thu, presentations Fri morning (~20 hrs real build).

**Event focus (memo):** edge-focused software that reduces cognitive and administrative burden on Sailors and Marines. Themes: efficient agentic AI, human-machine teaming, workflow automation.

**Real purpose of the event:** workforce development, a "try-first" rapid-iteration culture, prototypes that transition to formal evaluation, and an AAR / repeatable hackathon playbook. Demonstrate the behavior: talk to real users, iterate fast, ship a working thing, bring a credible transition plan.

---
## 3. Judging rubric (each 0–100, weighted)

| Criterion | Weight | What it means for us |
|---|---|---|
| Warfighting & Deckplate Impact | 30% | Hours saved per network, faster vuln→fix. Get real numbers/anecdote from an IT Sailor |
| Speed to Fleet | 20% | Runs offline on existing hardware, uses tools the Navy already fields, clear authorization path |
| Fleet Scalability | 20% | Works across ships/enclaves, not one bespoke setup |
| Barrier Removal | 15% | Kills manual correlation and paperwork (checklists, reports) |
| Judges' Discretion | 15% | Technical execution, Sailor UX, innovation |

**Submission requirements (Rules tab):** name a mission owner, technical owner, next experiment, required resources, and a 30/60/90-day transition plan. Document friction encountered (policy, data, authority, ATO barriers).

**Naval Agentic AI guardrails (apply to every AI solution):** define what the agent may do, may never do, what requires human approval, how activity is logged, and how it is stopped (kill switch).

---
## 4. Chosen use case: Autonomous Cyber Defender

Category: **Cyber Resilience & Trusted Autonomy**. Posted Oct 21, 2026 by Elsie Hornblum. Two teams on it as of Nov 4: **Cyber Thunder (us)** and **Navy Blue Team Norfolk (competitor)**. The portal's Datasets tab was empty on the morning of Nov 4: the "sample logs and network configurations" listed as resources did not exist yet, so plan on seeding our own data and range.

**Challenge statement:** Find, explain and fix misconfigurations and vulnerabilities in isolated, low-bandwidth networks with a human approving every change.

**Outcome to the fleet:** Isolated and afloat networks close new vulnerabilities faster, with every change approved, logged and reversible.

**Operational problem:** New STIGs and vuln bulletins arrive faster than IT/cyber staff can review them. Engineers manually correlate device configs, logs, firewall and monitoring data to find root causes. Afloat/isolated networks can't rely on normal patching or cloud tooling. Complex cloud identity policies hide insecure combinations no existing tool flags.

**Scenario:** An isolated, shipboard-like enclave receives a new STIG release and a critical vulnerability bulletin over a constrained link. Discover affected assets, explain the risk, propose fixes, apply after approval (or produce steps), verify, report. **A seeded misconfiguration or intrusion is hidden in the environment.**

**Requirements**
- Isolated and low-bandwidth
- Human approval before any change, with rollback
- Full audit trail
- Open interfaces; no live Navy networks

**Fleet-Ready Definition of Done (all solutions):** runs offline; keeps humans in authority; cites sources; logs auditable actions; syncs on reconnect; includes a one-page path to fleet.

**Measures of success**
- Share of seeded misconfigurations and vulnerabilities found
- Time to a correct remediation plan
- Changes applied only with approval, and rolled back cleanly
- Works over the emulated low-bandwidth link
- Complete audit trail

**Expected deliverables:** shorter time from new requirement/vuln to verified remediation; fewer manual hours per network; risk explained in terms commanders, system owners and data owners can act on; every change auditable and reversible.

**Listed resources** (listed, not yet confirmed live):
- Isolated cyber range with deliberately misconfigured hosts and containers
- Public DISA STIGs and NVD/CVE feeds
- Sample logs and network configurations
- Low-bandwidth link emulation
- SMEs: IT and cyber warfare personnel

**Transition hypothesis (from use case):**
- Owner: NAVIFOR / Naval Network Warfare Command, NIWC Atlantic, program cloud operators
- Destination: information warfare training range, then an afloat or shore enclave
- 30d owner confirms target environment → 60d test on training range → 90d authorization path defined → 180d limited deployment decision

**Skills wanted:** cyber/network engineers, DevSecOps, IT ratings. Non-coding Sailor role: **IT acting as approver and judge.**

---
## 5. Architecture

**Core principle: deterministic tools detect, the LLM correlates, explains and plans.** Detection rate is the #1 measure; LLM guessing loses to real checks.

| Stage | Implementation |
|---|---|
| Ingest | Pull new STIG (XCCDF) + CVE bulletin over the constrained link. Deltas only, compressed |
| Discover | Inventory the range: nmap, config pulls via SSH/WinRM, installed packages, containers |
| Check | OpenSCAP + STIG content (Linux), PowerSTIG / PowerShell checks (Windows), Evaluate-STIG/SCC if available in range, CPE matching vs NVD |
| Hunt | Log sweep for the seeded intrusion: new accounts, persistence (cron, systemd, services, run keys, scheduled tasks), odd listeners, auth anomalies |
| Normalize | Parse every scanner's output (CKLB is JSON, XCCDF results XML) into one findings schema |
| Explain | Local LLM turns findings into commander-level risk, citing STIG rule IDs / CVE IDs for every claim |
| Approve | IT Sailor approves/denies each fix individually in a simple UI |
| Apply + verify | Snapshot/backup before-state → apply → rescan → auto-rollback on failed verification |
| Audit | Append-only, hash-chained log of every action (tamper-evident) |
| Report | Commander one-pager + one-page path to fleet; queued to sync on reconnect |

**Agent guardrails (must be explicit in code and pitch)**
- Allowed: scan, read configs/logs, propose fixes, apply approved fixes from the vetted library
- Never: arbitrary shell from LLM output, changes without approval, touching hosts outside the defined scope, deleting logs/audit
- Requires approval: every state-changing action
- Logged: every scan, finding, proposal, approval/denial, apply, verify, rollback
- Stop: kill switch halts the agent and blocks pending actions

**Runtime must be offline.** Cloud AI coding tools are fine for *writing* code; the agent itself runs a local model. Options: Ollama/llama.cpp with a small tool-calling model, or local Gemma via Antigravity. Pick in the first hour; test tool-calling reliability before committing.

### Existing tools to integrate

| Tool | Status | Use |
|---|---|---|
| Evaluate-STIG (NSWC Crane) | CAC-gated (NAVSEA GitLab / Intelink). Do not copy code into repo | Call externally if present in range or Joshua is cleared to bring it; parse CKLB. Bash variant covers RHEL/Ubuntu |
| SCC (SCAP Compliance Checker, NIWC) | CAC-gated | Call externally; parse XCCDF/ARF or CKL |
| OpenSCAP | Open source | Linux STIG scanning |
| ComplianceAsCode / SCAP Security Guide | Open source | STIG profiles + Bash/Ansible remediations mapped to rules — use as the fix library |
| Microsoft PowerSTIG | Open source | Windows STIG check + enforce via DSC; capture before-state for rollback; writes .ckl |

**Where we add value over the scanners:** cross-host correlation with the new CVE bulletin, plain-English cited risk, intrusion hunting, approval-gated apply/verify/rollback, delta sync over the constrained link.

**Pitch line:** "We don't reinvent the Navy's scanners. We turn their output into approved, verified, reversible fixes, offline."

### Differentiators
1. **Low-bandwidth link:** Joshua builds compressors (context-mixing C++ compressor). Show the update payload as a small fraction of a full STIG download and transfer time at the emulated link speed.
2. **Hash-chained audit + live rollback** during the demo.
3. **Navy credibility:** built around tools the Navy already fields; transition owner already named in the use case.

---
## 6. Suggested build order

1. Findings schema + CKLB/XCCDF parsers
2. Scanner wrappers (OpenSCAP first or PowerSTIG first, depending on range OS mix)
3. Audit log (hash-chained) + kill switch
4. Approval gate + minimal UI (findings list, cited explanation, Approve/Deny, audit view, kill switch)
5. Remediation library (ComplianceAsCode / PowerSTIG) with before-state capture, verify, rollback
6. Intrusion hunt module
7. LLM explain/plan layer with mandatory citations
8. Delta ingest + compression over emulated link; sync-on-reconnect queue
9. Commander one-pager + path-to-fleet generator
10. Demo script: new STIG arrives over slow link → findings → hidden intrusion found → Sailor approves fix → verify → forced failure → rollback → audit trail

If the range isn't live, build against local VMs/Docker containers misconfigured on purpose, then switch.

---
## 7. Event logistics

- **Wi-Fi:** `FLEETHACKER` for hack laptop/devices, `FLEETHACKER-guest` for personal. **No hotspots, travel routers, APs, wireless printers, or other wireless gear at the venue.** Wired connections available.
- **IT Ops:** 3rd floor, `#tech-support`, last resort call/text (218) 206-2667. Don't share passwords in reports.
- **OpenAI/Codex:** accept FLEETHACKER invite → API Platform → FLEETHACKER → Default project → create your own project key (keep private) → Codex desktop app or VS Code/Cursor extension, "Use API Key". Codex cloud is out of scope. Help: events@defenseunicorns.com.
- **Google:** team link (from team lead or Events) → Google Cloud console + a browser-based VM with **Antigravity** preinstalled (remote desktop in browser; 6–7 people share team credentials). Also Gemini Enterprise / Agent Builder (no/low-code cloud agents) and Gemini Notebook (research, pitch prep). Antigravity 2.0 can run local Gemma models offline. Help: googlenavseateam-external@google.com.
- **Defense Unicorns "Codename: Ark":** pre-release platform: describe a mission need in plain language → plan → working web app; also "App packaging" to prepare an existing app for UDS. Create account at ark.defenseunicorns.com, then email events@defenseunicorns.com to get access enabled (account alone does not grant access). Code → Download keeps the source snapshot.
- **SpaceXSI (xAI):** Cursor credits (redeem via QR/link in the PDF) + Grok. POCs tate.buffington@x.ai, Johnwhiteiii@x.ai.

**Build-time vs runtime AI (decided 4 Nov):** every sponsor tool above is for *writing* Cyber Thunder (AI coding assistants, Antigravity IDE, Cursor/Grok, Codex, Ark). The model *inside* Cyber Thunder that explains findings to the Sailor runs locally and offline on the enclave hardware behind a thin `explain()` interface; the backend is a config value. Proven on the hack laptop: Ollama + `gemma3:4b` (9.6 tok/s), fallback `qwen2.5:3b`. Stretch (Day 2, one person max): the **Antigravity Python SDK** has a real offline mode (`LiteRTAgentConfig` + Gemma 4 26B A4B on LiteRT-LM, Windows wheel exists) but Google recommends 24 GB VRAM/shared memory, which the hack laptop lacks; details in PLAN.md §10. Gemini Enterprise / Agent Builder are cloud and cannot be the runtime (fails "runs offline"); use them for the pitch deck and research.

---
## 9. Open items

- [x] Team repo created: github.com/fleethacker/cyber-thunder
- [ ] Is the cyber range live? How to connect, OS mix, containers?
- [ ] Emulated link speed (to size update payloads)
- [ ] Is Evaluate-STIG or SCC in the range, or is Joshua cleared to bring his copy?
- [x] Cyber Thunder is our team; Navy Blue Team Norfolk is the competitor. Still needed: roster and roles
- [ ] Datasets tab empty on Nov 4 AM: ask organizers whether sample logs/configs will appear or live only on the range
- [ ] IT Sailor/SME recruited as approver; get real numbers on STIG remediation time
- [x] Local runtime model chosen: `gemma3:4b` default, `qwen2.5:3b` fallback (bench in PLAN.md §9); no tool-calling needed by design
- [ ] Ark access requested (account at ark.defenseunicorns.com + email to events@defenseunicorns.com)
- [ ] Team's Google link obtained; teammates on the Antigravity VM
