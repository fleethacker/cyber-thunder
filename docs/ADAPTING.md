# Adapting Cyber Thunder to a new environment

Can this adapt to any environment? Mostly yes, and the part that does not is small and well fenced. The
pipeline, the approval gate, the audit chain, the kill switch, reports, UI and standing-approval policy know
nothing about a particular network. What changes per environment is data (inventory, credentials, scopes,
benchmark content) and, for a technology family we do not cover yet, one adapter. This guide is what a new
unit needs to do that without us. Commands run from the repository root and use `python -m cyberthunder`.

## 1. What carries over and what does not

| Part | Environment-neutral? | What you do per environment |
|---|---|---|
| Scan, finding, proposal, approval, apply, verify, rollback pipeline | yes | nothing |
| Approval gate, kill switch, audit hash chain, standing-approval policy | yes | sign a policy only if you want one (section 6) |
| Reports, POA&M, checklist, outbox, UI, HTTP API | yes | nothing |
| Inventory and scope | no | write the targets file (section 2) |
| Credentials | no | set `CT_CRED_<ref>` variables or point at key files |
| Transports | no | open the ports in section 3, or use `file` / `fixture` |
| Benchmark content (STIG rules, SCAP data) | no | import or pull current releases (section 4) |
| Organization-defined values (known admins, expected ports, approved syslog) | no | `options` on each target |
| Technology families beyond Linux, Windows, Cisco IOS, Kubernetes, containers | no | write an adapter (section 5) |
| Local model | mostly | pick a backend and model that fit the hardware (section 7) |

## 2. Inventory: the targets file and the scope guardrail

The inventory is `<state dir>/targets.yaml` (JSON is also accepted) and doubles as the scope guardrail: the
agent may touch only targets listed there with `in_scope: true`. Edit it with `targets ...` commands where
you can; scope changes are audited and need a reason. Fields, from `cyberthunder/inventory/targets.py`:

| Field | Meaning |
|---|---|
| `id`, `name` | stable identifier used on every command, and a display name |
| `asset_type` | `linux`, `windows`, `cisco_ios`, `kubernetes` or `containers` |
| `transport` | `ssh`, `winrm`, `local`, `fixture`, `simulated`, `file`, `kubeconfig` |
| `address`, `port`, `username` | where and as whom to connect |
| `credential_ref` | a short name resolved as `CT_CRED_<ref>`, or a key file path. Never the secret |
| `sudo` | elevate through sudo on Linux (default true) |
| `tags` | free labels (enclave, role) |
| `in_scope` | the guardrail. Out-of-scope targets are never scanned or changed |
| `simulated` | marks demo targets; they never become live targets |
| `options` | adapter and transport values (`config_path`, `kubeconfig`, `known_admins`, `expected_ports`, `allow_push`, `critical_services` ...) |
| `last_scan`, `notes`, `added_at` | bookkeeping |

Discovery proposes, a person accepts (rules in [DISCOVERY.md](DISCOVERY.md)). Save the address ranges you
may sweep with `discover scopes`, run `discover sweep`, and review the unknown devices. Only
`discover accept` writes into the inventory, and it needs a named human, an explicit in-scope decision and a
reason. Hosts imported from a Nessus or ACAS export start out of scope. Nothing a sweep finds is scanned
until someone brings it into scope.

Credentials are resolved when a transport connects and are never written to disk, the inventory or the
audit log. Set `CT_CRED_<ref>` in the environment of the process that runs the scan, or give a key file path
(`options.key_file`, or a `credential_ref` that is an existing path). Other variable names are refused.

## 3. Transports and reach

| Transport | Used for | Open on the enclave | Notes |
|---|---|---|---|
| `ssh` | Linux hosts, live Cisco IOS, container hosts | TCP 22 from the node | password via `CT_CRED_<ref>` or key file; sudo on Linux |
| `winrm` | Windows hosts | TCP 5986 (https, preferred) or 5985 | `options.transport`: ntlm (default), kerberos, basic, credssp; PowerShell is sent encoded |
| `kubeconfig` | Kubernetes | the API server port named in the kubeconfig | `options.kubeconfig` names the file; `kubectl` must be on the node |
| `file` | a Cisco running-config saved on disk | nothing | `options.config_path`; review only, steps are handed to the Sailor |
| `fixture`, `local` | recorded sessions, tests, the node itself | nothing | |
| `simulated` | the demo | nothing | stateful emulator on the same code path |

The node (API, CLI, UI and local model) runs on the operator laptop or on a jump host inside the enclave.
Use a jump host where the laptop cannot reach the management VLAN; the operator then reaches the UI over a
forwarded port on `127.0.0.1`. The node needs a route to each target and nothing else: it makes no outbound
connection except to targets and the local model. Where only one management box is reachable, save it as a
discovery `scanner_target` so sweeps start from inside the enclave.

## 4. Benchmarks and content

Cyber Thunder does its own checking, so benchmark content is what it checks against. Two kinds matter:

* **Manual STIG XCCDF** (`U_*_Manual-xccdf.xml`): rule text, severity, check and fix text, CCI and STIG IDs.
  Findings cite it and the release delta compares it.
* **SCAP benchmarks** (`U_*_SCAP_*_Benchmark.xml`): machine-executable OVAL, for where a SCAP scanner runs
  the content. The RHEL 8 and RHEL 9 pairs are in `STIG/`.

On Linux the built-in checks run over SSH everywhere. Where `oscap` is installed on the target, the Linux
adapter also runs OpenSCAP with the SCAP Security Guide datastream (`/usr/share/xml/scap/ssg/content/`) and
merges the results, so put `openscap-scanner` and `scap-security-guide` in the base image for a second
opinion. Windows uses the adapter's own PowerShell checks, with rule text from its catalog. Evaluate-STIG and
SCC are CAC-gated and are never copied into the repository; if a unit already runs them, normalize their
CKLB or XCCDF output with the `parse` command.

The catalog is `<state dir>/ingest/catalog/<benchmark>.xml`, one copy per benchmark. Getting content in:

* **Disconnected (DDIL):** download on a connected machine from public.cyber.mil, carry the `.zip` or `.xml`
  across by approved media, and run `ingest stig <file>`. Import is the baseline and needs no link.
* **Connected:** fetch the same files from public.cyber.mil or the unit's internal mirror and give them to
  the same command. A pull is only a download in front of the import; nothing downstream differs. Run
  `ingest --help` to see whether your build also fetches by itself; this guide does not assume it.
* **Cadence:** DISA publishes quarterly. Import each release when it lands.

Each import diffs the new release against the catalog copy and reports rules added, removed and changed,
and the delta size against the full file with its transfer time at the configured link speed
([API.md](API.md), ingest section). `--rescan` then rescans only the added and changed rules, so a new
release costs minutes, not a full scan. Bulletins work the same way: `ingest bulletin` matches CVEs against
each host's package inventory.

## 5. Adapters: the technology families

Today: **Linux, Windows, Cisco IOS / IOS-XE, Kubernetes, containers.** A new family (another network OS, a
database, a hypervisor, a firewall) needs a new adapter. The contract is [ARCHITECTURE.md](ARCHITECTURE.md)
section 6; the recipe in short:

1. `cyberthunder/adapters/<type>/` with an `Adapter` subclass decorated `@register`.
2. Add the type to `ASSET_TYPES` and the module to `ADAPTER_MODULES`.
3. `collect()` gathers raw facts over a transport; detection is pure Python over the result.
4. Every finding goes through `make_finding` with at least one citation.
5. `fixes()` returns vetted `FixEntry` objects, each with before-state, verify and a rollback kind.
6. `capture_before_state`, `apply`, `verify`, `health_check`, `rollback`.
7. A simulated transport if the asset can be emulated; tests and fixtures under `tests/<type>/`.
8. Seeds and answer-key items in `range/`, so detection rate is measurable.

Realistic effort for a family with a text interface and a published STIG: about two days for read-only
detection with fixtures, and two to three more for reversible fixes and a simulator. Checks are the cheap
part; trustworthy before-state and rollback take the time. Start read-only and ship fixes as runbooks
(section 6) until rollback is proven.

## 6. Remediation policy

* **Vetted fix library.** Fixes come only from the library (`remediation/library.py` plus each adapter's
  `fixes()`): reviewed payloads with before-state, verify and rollback. Nothing a model or a person types is
  ever executed.
* **Runbook fixes.** Where a change cannot be applied safely (a reboot, a vendor patch, a push to a device
  without `allow_push`) the entry is a runbook: the exact steps go to the operator, nothing is run, and
  `verify` re-checks once they are done. Runbooks are proposed only when `CT_AUTO_PROPOSE_RUNBOOKS` is set.
* **A person approves every change.** `proposals approve` needs a named human; `agent`, `llm` and `system`
  are refused. A failed verify rolls back automatically, and the kill switch blocks apply and rollback.
* **Standing approval is off by default.** `PUT /api/v1/policy` lets a named person sign narrow rules (asset
  types, maximum disruption, fix allowlist, target allowlist, time window); approvals under it are recorded
  as `policy:<name>`. Patches, reboots and service restarts are excluded unless the policy says otherwise.
  It is off because authority to change a system belongs to a person until the authorizing official says
  otherwise. Enable it only with that written decision, one narrow rule at a time.

## 7. The local model

The model explains; it never detects, picks a fix or executes anything. It receives structured findings and
returns risk, impact, plan and citations, and the validator drops any citation not already on the finding.
If the model is down or slow, a deterministic template explanation is used, so scans and approvals never
wait on it.

Measured on the hack laptop (i7-6820HQ, 64 GB, 4 GB GPU; [PLAN.md](PLAN.md) sections 1 and 9): `gemma3:4b`
9.6 tok/s and about 34 s per explanation, `qwen2.5:3b` 11.4 tok/s and 25 s, `qwen2.5:7b-instruct` 3.0 tok/s
and 61 s, `gemma3:1b` too weak. Explanations are precomputed after each scan, so 30 s per finding is
acceptable. A larger GPU can run a larger model with the same code.

The backend is configuration (`cyberthunder/config.py`): `CT_LLM_BACKEND` (`ollama`; `openai` for any local
server that speaks the common chat-completions API; `template` for no model), `CT_LLM_URL`, `CT_LLM_MODEL`, `CT_LLM_FALLBACK_MODEL`
and `CT_LLM_TIMEOUT`. `explain-status` shows what is answering.

## 8. Reports and sync

Reports (commander one-pager, POA&M CSV, CKLB checklist, path to fleet, friction log) are rendered on the
node. With `report ... --queue` they go into the outbox as small hashed files instead of leaving at once.
While the link is marked down they wait; on reconnect (`link set --connected true`, or `outbox sync`) the
outbox sends them in order, with bytes and seconds logged in the audit chain. Only reports, STIG deltas and
bulletin receipts travel; raw configs, logs and credentials stay on the enclave. `link set` sets the speed
used to size transfers; real traffic shaping is done by the range or the ship's link, not by this tool.

## 9. Worked example: a shore enclave

Two Windows Server 2022 members, a Cisco access switch and a Linux management host on 10.40.8.0/24. The
Linux host runs the node.

```yaml
# <state dir>/targets.yaml
targets:
- id: ws22-01
  name: File server 1
  asset_type: windows
  transport: winrm
  address: 10.40.8.21
  port: 5986
  username: ctsvc
  credential_ref: ws22
  tags: [shore-enclave, member-server]
  in_scope: false
  options: {known_admins: [Administrator, itadmin], expected_ports: [135, 445, 3389, 5986]}
- id: ws22-02
  name: File server 2
  asset_type: windows
  transport: winrm
  address: 10.40.8.22
  port: 5986
  username: ctsvc
  credential_ref: ws22
  in_scope: false
- id: sw-acc-01
  name: Access switch
  asset_type: cisco_ios
  transport: ssh
  address: 10.40.8.2
  username: ctaudit
  credential_ref: sw
  in_scope: false
  options: {role: switch, known_users: [ctaudit], known_syslog: [10.40.8.10], allow_push: false}
- id: mgmt-01
  name: Management host
  asset_type: linux
  transport: ssh
  address: 10.40.8.10
  username: ctsvc
  credential_ref: mgmt
  in_scope: false
```

Targets start out of scope; a named person brings each one in with a reason. Set the passwords in the shell
that runs the node (`CT_CRED_ws22`, `CT_CRED_sw`, `CT_CRED_mgmt`), or give `mgmt` a key file path.

The first five commands:

```bash
python -m cyberthunder targets list
```
```bash
python -m cyberthunder discover scopes --add 10.40.8.0/24 --reason "shore enclave management VLAN"
```
```bash
python -m cyberthunder discover sweep --mode quick --scope 10.40.8.0/24
```
```bash
python -m cyberthunder ingest stig STIG/U_RHEL_9_STIG_V2R10_Manual-xccdf.xml
```
```bash
python -m cyberthunder scan --targets ws22-01 ws22-02 sw-acc-01 mgmt-01 --wait
```

Between steps 3 and 5, review `discover list`, then bring each target in with
`python -m cyberthunder targets scope ws22-01 in --reason "ISSM approved"`; the scan touches only targets in
scope. Import the Windows Server 2022 and Cisco IOS-XE benchmarks the same way as step 4. Then work the
queue with `proposals list`, `proposals approve <id>` and `apply <id>`.

## 10. Checklist

- [ ] Authorization to scan this enclave is in writing; the mission owner is named
- [ ] Node placed (laptop or jump host) and a route to each target confirmed
- [ ] Ports open: 22 (ssh), 5986 or 5985 (winrm), the API server port (kubeconfig)
- [ ] Service accounts created with the least privilege each adapter needs
- [ ] `CT_CRED_<ref>` set or key files in place; no secret in `targets.yaml`
- [ ] Discovery scopes saved with reasons; sweep run; every device accepted or ignored
- [ ] Targets carry their organization-defined `options`; each brought in scope by a named person
- [ ] Current benchmarks imported (Manual XCCDF, plus SCAP where used); `oscap` in the Linux base image
- [ ] Local model installed and `explain-status` answering, or backend set to `template`
- [ ] First scan read-only; findings compared with any known-good list
- [ ] Fixes start as proposals; rollback tried on one non-critical host before the first real change
- [ ] Standing approval left off unless the authorizing official has said otherwise
- [ ] Kill switch tested (`kill engage`, confirm apply is blocked, `kill release`)
- [ ] Link speed set; outbox tested through one down and up cycle
- [ ] Audit chain verified (`audit verify`) and the head hash recorded off the node
- [ ] Friction (policy, data, authority, ATO) written down as it is hit
