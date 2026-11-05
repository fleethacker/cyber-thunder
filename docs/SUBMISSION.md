# Portal submission draft

Event slug `norfolk`. Results below distinguish recorded experiments from unmeasured outcomes.
Confirm the mission owner and missing measurements before submitting; do not infer them from a demo score.

## Team and use case

- **Team:** Cyber Thunder
- **Use case:** Autonomous Cyber Defender (Cyber Resilience and Trusted Autonomy)
- **One line:** Find, explain and fix misconfigurations and vulnerabilities on isolated, low-bandwidth networks
  with a human approving every change. We don't reinvent the Navy's scanners; we turn their output into
  approved, verified, reversible fixes, offline.

## Owners

| Role | Name | Note |
|---|---|---|
| Mission owner | Not confirmed | Proposed: the training-range owner named in the use case (NAVIFOR / Naval Network Warfare Command, NIWC Atlantic). Confirm before submitting |
| Technical owner | Joshua Ott | Builds and maintains through the next experiment |

## What was built

An approval-gated defender for enclave networks:

- **Ingest** a new STIG release as a rule-level delta, compressed for the constrained link, plus IAVM/CVE
  bulletins matched against each host's package inventory.
- **Discover** assets read-only; the inventory is the scope and nothing outside it is touched.
- **Check** with deterministic checks per asset type (Linux host, switch config, k3s cluster, container host,
  Windows host) and by parsing output from the scanners the Navy already fields.
- **Hunt** for intrusion indicators (accounts, keys, persistence, listeners, SUID, timestomping), each cited to
  ATT&CK.
- **Explain** each finding for commanders and system owners with a local model; every claim cites an identifier
  present on the finding, and a template is used if the model is unavailable.
- **Approve** per fix in a simple queue (what is wrong, why it matters, what changes, what could break, how to
  undo). Optional standing approval is off by default and must be signed by a named person.
- **Apply, verify, roll back** from a vetted fix library with before-state capture and automatic rollback on
  failed verification.
- **Audit** every action in a hash-chained log whose head hash is on every report.
- **Report** a commander one-pager, POA&M, updated checklists and a path to fleet, queued until the link returns.

Status of each module is in the [README](../README.md); behaviour is specified in
[ARCHITECTURE](ARCHITECTURE.md), [API](API.md) and [UI](UI.md).

## How it is measured

Run against the local range with the seeded items in `range/answer_key/<type>.json`; the Reports page shows the
detection score.

| Measure | Result | How measured |
|---|---|---|
| Seeded items found (misconfigurations and intrusion indicators combined) | 28/28 scoped items (100%): Linux 12/12, Podman 6/6, k3s 10/10 | [Recorded real-host run, 4 Nov](../range/README.md#results-first-real-host-run-2026-11-04); this is not full STIG coverage |
| Share of seeded intrusion indicators found, separately | Not separately recorded in the run summary | Requires a preserved per-kind score export |
| Time to a correct remediation plan | Not measured | Requires scan-to-plan timing and review of plan correctness |
| Changes applied only with approval | One recorded Linux change was approved before apply; the actor name was self-asserted | Recorded shadow-permissions experiment; no broader approval-rate claim |
| Clean rollback | 1/1 recorded real-host remediation restored its before-state | Shadow mode 0644 -> 0000 -> 0644, verified on the host |
| Works over the emulated low-bandwidth link | No measured transfer result preserved in this submission | Configured-rate estimates are not measured throughput; CON-04 tracks real link measurement |
| Complete audit trail | Chain verification passed for the recorded real-host run; record count and head not preserved here | Run notes report `audit verify` intact; capture a sanitized export for the presentation |
| Hours per network saved | Not measured | Requires an IT Sailor's sourced manual baseline and a timed comparison |

The [validation matrix](VALIDATION.md) records the evidence and missing version/commit metadata.
The [coverage report](COVERAGE.md) separates native checks, SCAP content, executable fixes and runbooks.

## Next experiment

Run Cyber Thunder against an information warfare training-range enclave with the range owner, with real
(non-simulated) assets of each type, an IT Sailor as approver, and a timed comparison against the current
manual process. Success: the measures above, collected by someone other than the builders.

## Required resources

- A training-range enclave (or equivalent isolated lab) with SSH or WinRM access to a representative host of
  each type, and a switch configuration export.
- An IT Sailor or ISSO as approver and judge for two to three sessions.
- A host to run the tool and a local model (any machine with a few GB of memory; a GPU is optional).
- Authority to run the organization's scanners against the lab, and a decision on whether their output may be
  provided to the tool.
- Unclassified STIG content and bulletins delivered over the constrained link.

## Transition plan

| Horizon | Milestone |
|---|---|
| 30 days | Owner confirms the target environment and an approver; list of asset types and STIG versions in use; baseline manual timing collected |
| 60 days | Test on the training range; detection score and rollback evidence measured by the range team; feedback from Sailors folded in |
| 90 days | Authorization path defined with the authorizing official's staff (package scope, data handling, logging and audit retention); open friction items assigned |
| 180 days | Decision on limited deployment to a shore or afloat enclave |

Identity work (verified sign-in, roles, per-user access to targets, signed audit) is planned against these steps in [BACKLOG](BACKLOG.md) section 5; today the approver is a typed name, not a verified person.

Destination: information warfare training range, then an afloat or shore enclave. The one-page path to fleet is
generated by the tool (Reports, path to fleet; `GET /api/v1/reports/fleet`).

## Friction encountered

Recorded as the build proceeded in `docs/friction.yaml` and rendered on the Reports page (friction log). Areas:
policy, data, authority and authorization. Summarize each area from that file at submission time:

- **Policy:** offline model approval and disconnected identity/revocation policy remain open (F2, F10).
- **Data:** the event dataset was unavailable at build start; public benchmarks and a seeded local range supplied test evidence (F4).
- **Authority:** confirm the mission owner, enclave identity/credential issuer, and range access for CAC testing (F9, F11).
- **Authorization (ATO):** confirm the registration sponsor and authorization boundary; no ATO or zero-trust compliance is claimed (F1, BACKLOG section 2.4).

If `docs/friction.yaml` is not yet present on the branch, collect the entries first; do not write them from memory.

## Agentic guardrails statement

| | |
|---|---|
| **May do** | Scan in-scope assets, read configurations and logs, run the vetted checks, propose fixes, and apply approved fixes from the vetted library |
| **Never does** | Run commands built from model output or any free text; change anything without approval; touch hosts outside the inventory; delete logs or audit records; approve its own proposals |
| **Requires human approval** | Every state-changing action. Standing approval is off by default; when enabled it is signed by a named person, narrow in scope, and never covers patches, reboots or service restarts unless stated |
| **How it is logged** | Every scan, finding, explanation, proposal, approval or denial, apply, verify, rollback, kill switch action, scope change and policy change goes to a hash-chained, append-only log; the head hash is printed on each report |
| **How it is stopped** | A kill switch (file, `CT_KILL` environment variable, or `KILL` sentinel) blocks every apply and rollback; the UI has an always-visible button; blocked attempts are logged |
| **How it is undone** | Every library fix declares a rollback; before-state is captured first; failed verification rolls back automatically |

## Fleet-ready definition of done

| Requirement | Answer |
|---|---|
| Runs offline | Local-model or template mode is available and the UI is bundled. PR #20 also adds an optional cloud-generated cluster description; leave that option disabled for disconnected operation |
| Humans keep authority | Approval gate on every change |
| Cites sources | Every finding and explanation cites STIG, CCI, CVE, IAVM or ATT&CK identifiers |
| Auditable actions | Hash-chained log |
| Syncs on reconnect | Outbox queues reports until the link returns |
| One-page path to fleet | Generated by the tool; pointer above |
