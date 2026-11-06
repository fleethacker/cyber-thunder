# Adapting Cyber Thunder to a new environment

Deployment changes usually concern identity, access grants, inventory, target credentials, trust and
benchmark content. An unsupported technology family also needs an adapter. The scan/remediation pipeline,
audit, reports and UI are shared across environments; their availability is not deployment acceptance.

For multi-user operation, configure signed identity and browser/API access using
[AUTHORIZATION.md](AUTHORIZATION.md), then assign the exact account/environment/action grants in
[ACCOUNT_ACCESS.md](ACCOUNT_ACCESS.md). Native Python and application-container deployments use the same
controls. Source Kubernetes/UDS manifests require verified configuration and a policy/identity preflight;
browser sessions require one process/worker. Follow [PACKAGE_IDENTITY.md](PACKAGE_IDENTITY.md) and the
[container guide](../deploy/kubernetes/README.md), including build and live-acceptance limits.

CLI commands below describe local development/replay where explicitly noted. Verified remote CLI
operations use [device login and the `api` namespace](CLI_AUTH.md); the guide lists supported commands.
Use the authenticated UI/API for other operations. A typed `--actor`
or an SSH-forwarded development port does not establish identity. Keep `CT_AUTH_MODE=dev` on loopback
with scratch state; `CT_SECURITY_MODE=fleet` requires verified authentication.

## 1. What carries over and what does not

| Part | Environment-neutral? | What you do per environment |
|---|---|---|
| Scan, finding, proposal, approval, apply, verify, rollback pipeline | yes | nothing |
| Approval gate, kill switch, audit hash chain | yes | assign authorized human roles/grants; retain approval and rollback requirements |
| Reports, POA&M, checklist, outbox, UI, HTTP API | yes | assign read/export/audit grants for the intended contributors |
| Identity and authorization | no | configure the issuer/client, trusted claims, protected access policy and fresh-authentication policy |
| Inventory and scope | no | register targets with exact environments and reviewed scope (section 2) |
| Credentials | no | provision an account binding per requester/action/target; make its referenced secret or protected file available on the server |
| Transports | no | provision host/TLS trust and reachability (section 3); reserve `file` / `fixture` for development |
| Benchmark content (STIG rules, SCAP data) | no | import or pull current releases (section 4) |
| Organization-defined values (known admins, expected ports, approved syslog) | no | `options` on each target |
| Technology families beyond Linux, Windows, Cisco IOS, Kubernetes, containers | no | write an adapter (section 5) |
| Local model | mostly | pick a backend and model that fit the hardware (section 7) |

## 2. Inventory: the targets file and the scope guardrail

The inventory is `<state dir>/targets.yaml` (JSON is also accepted). Target execution requires a saved,
in-scope target as well as the requester's action grant. Use authenticated inventory controls in verified
mode; development also has `targets ...` commands. Scope changes are audited and need a reason.
Node `admin` and target `admin` are separate grants; changing an environment checks the proposed
resource as well. Fields, from `cyberthunder/inventory/targets.py`:

| Field | Meaning |
|---|---|
| `id`, `name` | stable identifier used on every command, and a display name |
| `asset_type` | `linux`, `windows`, `cisco_ios`, `kubernetes` or `containers` |
| `transport` | `ssh`, `winrm`, `local`, `fixture`, `simulated`, `file`, `kubeconfig`, `vsphere`; not all support delegated verified execution |
| `address`, `port` | target endpoint |
| `environment` | exact authorization dimension, default `default`; tags do not substitute for it |
| `authorization_id` | server-controlled ownership generation; never copy or set it to inherit historical records |
| `username`, `credential_ref`, `sudo` | inventory defaults for development; verified execution replaces them with the selected account-policy binding |
| `tags` | free labels (enclave, role) |
| `in_scope` | the guardrail; out-of-scope targets are not scanned or remediated |
| `simulated` | labels simulated data; only `transport: simulated` selects an emulator without a remote account |
| `options` | adapter and transport values (`config_path`, `kubeconfig`, `known_admins`, `expected_ports`, `allow_push`, `critical_services` ...) |
| `last_scan`, `notes`, `added_at` | bookkeeping |

Discovery proposes, a person accepts (rules in [DISCOVERY.md](DISCOVERY.md)). In verified mode, use the
authenticated discovery controls to save authorized ranges, sweep and review candidates. Acceptance
requires human administrative authority for the node and target, an explicit scope decision and a
reason. The `discover scopes`, `discover sweep` and `discover accept` CLI commands are development
equivalents. Hosts imported from a Nessus or ACAS export start out of scope; a sweep does not itself
authorize target scanning.

Keep secret contents out of inventory and audit. In verified mode the protected
`<CT_STATE_DIR>/auth/access.json` selects the account and credential reference for each action; inventory
credentials, the process account and ambient keys are not fallbacks. Provision the selected protected
credential sources or key/kubeconfig files separately; fleet SSH/WinRM password references require the
[credential resolver](CREDENTIAL_RESOLVERS.md). Legacy range and vSphere environment references have
their separately documented limits. A group approval grant need not share a remote
account: [ACCOUNT_ACCESS.md](ACCOUNT_ACCESS.md#practical-policy-example) shows Alice scanning A while Bob
approves/applies B with his own binding, and an administrator with no automatic target grant.

## 3. Transports and reach

| Transport | Used for | Open on the enclave | Notes |
|---|---|---|---|
| `ssh` | Linux hosts, live Cisco IOS, container hosts | TCP 22 from the node | selected username plus password reference or key; fleet requires provisioned host trust; selected sudo permission is enforced |
| `winrm` | Windows hosts | TCP 5986 by default in fleet | selected explicit NTLM account; validated HTTPS and a CA bundle in fleet; no ambient Kerberos fallback |
| `kubeconfig` | Kubernetes | HTTPS API endpoint in the selected kubeconfig | policy-selected file/context; guarded kubectl and protected credentials; no exec/auth-provider plugins |
| `vsphere` | vCenter/ESXi inventory discovery | configured HTTPS endpoint, normally TCP 443 | discover-only account binding and TLS trust; see [VSPHERE_ACCOUNT_ACCESS.md](VSPHERE_ACCOUNT_ACCESS.md) |
| `file` | a saved Cisco running-config | nothing | development/replay only; no delegated verified account |
| `fixture`, `local` | recorded sessions, tests, the node itself | nothing | development/replay only; no delegated verified account |
| `simulated` | the demo | nothing | stateful emulator on the same code path |

Place the native process or container where it can reach authorized management endpoints. Verified
operators reach its HTTPS UI/API; a mesh deployment must enforce gateway-only reachability. Identity
endpoints, configured model services and explicitly enabled content/database updates also need their
documented routes. Offline operation is bounded by token/session/key-cache expiry. A discovery
`scanner_target` or a Kubernetes server/node inspection needs its own target grant and selected account;
permission on a cluster does not imply host/container access. Provision host/TLS trust using
[TRANSPORT_SECURITY.md](TRANSPORT_SECURITY.md) and protected Windows policy/credential paths using
[WINDOWS_FILE_TRUST.md](WINDOWS_FILE_TRUST.md); its native DACL checks have separate deployment limits.

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
CKLB or XCCDF output through authenticated scanner ingestion (or development `parse`).

The catalog is `<state dir>/ingest/catalog/<benchmark>.xml`, one copy per benchmark. Getting content in:

* **Disconnected (DDIL):** carry a signed operator bundle across approved media and import it through the
  authenticated service. Verified unsigned imports require a current human's explicit authorized override;
  a hash or typed name is insufficient. Local development retains `ingest stig <file>`.
* **Connected:** the authorized updater uses the fixed-host, certificate-verifying HTTPS client. Its
  `trusted_https_source` receipt is transport provenance, not a DISA signature. Arbitrary mirror URLs or
  caller-supplied provenance cannot substitute for that receipt.
* **Procedure:** use [CONTENT_AUTHENTICITY.md](CONTENT_AUTHENTICITY.md) and
  [CONTENT.md](CONTENT.md) for signing/trust configuration, supported ingestion paths and release handling.

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

* **Vetted fix library.** Fixes come only from the library (`cyberthunder/remediation/library.py` plus each adapter's
  `fixes()`): reviewed payloads with before-state, verify and rollback. Nothing a model or a person types is
  ever executed.
* **Runbook fixes.** Where a change cannot be applied safely (a reboot, a vendor patch, a push to a device
  without `allow_push`) the entry is a runbook: the exact steps go to the operator, nothing is run, and
  `verify` re-checks once they are done. Runbooks are proposed only when `CT_AUTO_PROPOSE_RUNBOOKS` is set.
* **Independent human approval.** Verified changes require authorized human issuer/subject identities,
  current target grants and the saved approval/assessment evidence. CAT I/high or unknown severity needs
  two distinct approvers; the proposer cannot count. A typed name is not proof of a person. See
  [SEPARATION_OF_DUTIES.md](SEPARATION_OF_DUTIES.md) and [STEP_UP.md](STEP_UP.md).
  Verification and rollback retain account/scope checks and the kill switch.
* **Standing approval is off.** Verified mode refuses enabling the typed-signer policy until verifiable
  policy signing exists. Its development demonstration is not operational authorization.

## 7. The local model

The model explains; it never detects, picks a fix or executes anything. It receives structured findings and
returns risk, impact, plan and citations, and the validator drops any citation not already on the finding.
If the model is down or slow, a deterministic template explanation is used, so scans and approvals never
wait on it.

Measured on the hack laptop (i7-6820HQ, 64 GB, 4 GB GPU; [PLAN.md](PLAN.md) sections 1 and 9): `gemma3:4b`
9.6 tok/s and about 34 s per explanation, `qwen2.5:3b` 11.4 tok/s and 25 s, `qwen2.5:7b-instruct` 3.0 tok/s
and 61 s, `gemma3:1b` too weak. Explanations are precomputed after each scan, so 30 s per finding is
acceptable. A larger GPU can run a larger model with the same code.

The backend is configuration (`cyberthunder/config.py`): `CT_LLM_BACKEND` (`ollama` by default; a
chat-completions value for any local server that speaks that common API, named in `config.py`; `template`
for no model), `CT_LLM_URL`, `CT_LLM_MODEL`, `CT_LLM_FALLBACK_MODEL` and `CT_LLM_TIMEOUT`. The development
`explain-status` command shows what is answering; verified operators use authorized runtime controls.

## 8. Reports and sync

Reports render from authorized contributors on the node. Verified export requires node `export` and
each contributing target's export grant; lifecycle/audit data additionally needs node `audit`. An
explicit target selection does not pull in inaccessible targets merely because they share a scan.
History, downloads and queued entries retain original target/environment/generation ownership; target
reuse or a missing legacy scope cannot silently transfer those records to a new owner.

The outbox is local staging, not proof that a shore receiver accepted a report. Listing/sync recheck
original contributor grants. Use authenticated report/outbox controls in verified mode; `report ...
--queue`, `link ...` and `outbox sync` are development CLI examples. The link observation/test-mode
controls do not implement enclave traffic shaping. See [IDENTITY_PROVENANCE.md](IDENTITY_PROVENANCE.md)
and the [report guide](REPORT_ASSURANCE.md).

## 9. Worked example: separate A and B accounts

Use the exact policy in [ACCOUNT_ACCESS.md](ACCOUNT_ACCESS.md#practical-policy-example) with these
illustrative SSH targets. Names and addresses are placeholders. These are the equivalent inventory
declarations, not instructions to overwrite a running node's inventory. Register through the authorized
inventory API, which assigns `authorization_id`; do not supply that field or place credentials here.

```yaml
targets:
- id: host-a
  name: A managed host
  asset_type: linux
  transport: ssh
  address: host-a.example
  port: 22
  environment: A
  in_scope: false
  sudo: false
  options: {known_hosts: /etc/cyberthunder/ssh_known_hosts}
- id: host-b
  name: B managed host
  asset_type: linux
  transport: ssh
  address: host-b.example
  port: 22
  environment: B
  in_scope: false
  sudo: false
  options: {known_hosts: /etc/cyberthunder/ssh_known_hosts}
```

1. Configure verified identity, access policy and transport trust. Provision Alice's scan account and
   Bob's change account separately. The example's node-only administrator cannot register or edit these
   targets without the additional required target grants. An inventory administrator with those grants
   registers each target and changes `in_scope` to true with a reason.
2. Sign in as Alice. `GET /api/v1/targets` should expose only `host-a`. Submit the following body to
   `POST /api/v1/scans` through the authenticated client:

   ```json
   {"target_ids": ["host-a"], "modules": ["check"]}
   ```

   Alice has no apply grant and no access to B. If her non-sudo account cannot collect a check's evidence,
   that evidence remains unavailable; there is no privileged inventory-account fallback.
3. An independently authorized analyst for B supplies its scan and proposal. Sign in as Bob to review
   that proposal, complete required fresh authentication and collect the independent approval quorum.
   Bob may apply on B only when all proposal/assessment, scope, kill and credential checks pass. His
   `BOB_B_CHANGE` reference resolves on the server; Alice's account is never reused.
4. Confirm the denied cases as well as the successful ones: Alice cannot apply or read B; Bob cannot
   scan B or read A; Charlie's `admin` role/node grant alone gives no target access. A move of `host-a`
   to B or deletion/recreation invalidates the old saved ownership rather than transferring it.
5. Use a separately authorized auditor for reports: node export, contributor export and any required
   audit permission are independent of scan/apply. Follow [API.md](API.md) for request and CSRF handling.

The sample policy is an access assignment, not proof of a live realm, SSH login, remote privileges or
approval acceptance. Keep the local [DEMO.md](DEMO.md) rehearsal separate from this verified workflow.

## 10. Checklist

- [ ] Authorization to scan this enclave is in writing; the mission owner is named
- [ ] Native/container runtime chosen; verified identity and account policy provisioned; one browser-session worker
- [ ] Authorized target and identity endpoints reachable; SSH host trust / fleet HTTPS CA validation provisioned
- [ ] Per-account/action bindings select the intended remote accounts; both allowed and denied cases checked
- [ ] Referenced secrets/protected files available to the runtime; access.json and ancestors protected; no inventory secrets
- [ ] Discovery scopes saved with reasons; sweep run; every device accepted or ignored
- [ ] Targets carry their organization-defined `options`; each brought in scope by a named person
- [ ] Current benchmarks imported (Manual XCCDF, plus SCAP where used); `oscap` in the Linux base image
- [ ] Model endpoint/model checked through authorized controls, or backend set to `template`
- [ ] First scan read-only; findings compared with any known-good list
- [ ] Fixes start as proposals; rollback tried on one non-critical host before the first real change
- [ ] Standing approval disabled; verified mode does not accept the development typed-signer policy
- [ ] Emergency stop and authorized fresh-authenticated release checked; stop blocks apply/rollback
- [ ] Report/outbox contributor access and local staging checked; no shore-delivery claim from local sync
- [ ] Audit chain checked by an authorized auditor and the head hash recorded off the node
- [ ] Friction (policy, data, authority, ATO) written down as it is hit
