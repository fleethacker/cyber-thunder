# Backlog

What should be done and is not. Every entry here is known work, so nobody mistakes a demo shortcut for a design decision. An item leaves this file in the same pull request that ships it; if it is dropped instead, say why in that PR. Line references were checked against the tree on 4 Nov 2026 and will drift; search for the named function if a line has moved.

**Identity today, in one line:** the approver is a typed name, machine names are refused, and nothing about a person is verified.

Identity items carry the transition-plan step from [SUBMISSION](SUBMISSION.md) (30, 60, 90 or 180 days). Other items carry one of: **now** (before the event ends), **before range** (before the training-range experiment), **before fleet** (before a limited deployment), **later**.

## 1. Identity, credentials and zero trust

### Current state

| Question | Today | Where |
|---|---|---|
| Who is acting? | Whatever the `X-Actor` header says | `cyberthunder/api/deps.py:13-16`, `cyberthunder/api/util.py:36-48` |
| What is checked about the name? | Not empty, no control characters, at most 128 characters, not `agent`/`llm`/`system`-style, not `policy:` | `cyberthunder/control/identity.py:35-48` |
| Where does the UI get the name? | A free-text box kept in browser `localStorage` | `cyberthunder/ui/src/pages/Settings.tsx:25`, `cyberthunder/ui/src/api/client.ts:16,24` |
| CLI identity | `--actor`, defaulting to `CT_ACTOR`, then the OS user name | `cyberthunder/cli.py:113,131` |
| Login, session, token, certificate | None | `cyberthunder/api/` |
| Transport to the UI and API | Plain HTTP, bound to `127.0.0.1:8000` by default | `cyberthunder/api/app.py:50-53`, `cyberthunder/config.py:58-59` |
| Roles, approver roster, two-person rule | None; any accepted name may do anything | `ActorDep` at `cyberthunder/api/util.py:52` |
| Kill switch engage | Allowed with no name ("unidentified operator (address)") | `cyberthunder/api/routes/kill.py:22-25` |
| Standing-policy "signature" | `signed_by` set to the caller's string in a JSON file; an API edit while enabled re-signs under the editor's name; the gate checks the file on disk is enabled and names the same signer, not that its rules are unchanged | `cyberthunder/control/policy.py:54-56`, `cyberthunder/api/routes/policy.py:90`, `cyberthunder/control/approvals.py:184-192` |
| Audit record identity | `actor` as a bare string; checkpoint is unsigned JSON beside the log | `cyberthunder/audit/chain.py:152-184` |
| Access to target systems | One shared account per target, password from `CT_CRED_<ref>`, same account scans and applies | `cyberthunder/transport/ssh.py:24-28,43-55`, `cyberthunder/transport/winrm.py:88-101` |
| Host identity of targets | SSH accepts any host key; WinRM allows HTTP, Basic and `cert_validation=ignore` | `ssh.py:62`, `winrm.py:8-11,26,72-73` |

What is real: machine identities can never take a human edge, and every action is recorded under some name. What is not: that the name belongs to the person at the keyboard, or that they hold authority to approve.

### 1.1 People into the app

**ZT-01 Package Cyber Thunder as a UDS package behind Keycloak SSO.** Pillars: User, Application, Network. Step: 60 days. Effort: 1-2 weeks. Depends: UDS Core cluster ([DEPLOYMENT](DEPLOYMENT.md)), `packages/identity-bootstrap`.
- Today: `packages/` holds only `identity-bootstrap`, `nginx-bad` and `podinfo`; the app is a bare uvicorn process.
- Target: `packages/cyber-thunder` (Zarf package plus UDS Package CR, modeled on `packages/podinfo`) with sidecar injection, tenant-gateway expose, an SSO client, authservice selector, egress limited to inventory CIDRs and the in-namespace model server, state on a PVC. Laptop mode stays, labeled as unverified identity. Also produce an SBOM and pin image digests (`docs/fleet.yaml:16` names Iron Bank onboarding).
- Done when: a request without a session is redirected to Keycloak; a pod outside the mesh cannot reach the app; `uds zarf dev lint packages/cyber-thunder` passes; the UI loads after login as an identity-bootstrap test user.

**ZT-02 Replace the typed X-Actor name with a verified principal.** Pillars: User, Application. Step: 30 days. Effort: 4-6 days. Depends: none for the seam.
- Today: see the table above; the CLI `approve` trusts `--actor` after `require_human` (`cyberthunder/cli.py:113`).
- Target: `control/principal.py` with a frozen `Principal` (issuer, subject, display name, roles, groups, scopes, acr/amr, auth_time, session id, device, kind human|workload|dev). `get_principal` with three modes: `oidc` (validate a bearer token), `mesh` (validate the authservice-forwarded token, never trust headers as such), `dev` (today's header, kind=dev, assurance none, loopback only). `require_actor` becomes `require_principal`; the gate, kill switch and policy keep an actor string (`iss|sub`) plus the principal for audit, so state logic is untouched.
- Done when: in oidc mode `X-Actor: alice` alone gets 401; a valid token records alice's issuer and subject; dev mode refuses a non-loopback bind; a test walks `app.routes` and fails if any non-GET route other than `POST /kill/engage` and `POST /policy/evaluate` lacks `require_principal`; forged-header, wrong-CA and expired cases are tested and each writes an audit record.

**ZT-03 OIDC token validation with an offline-cached JWKS.** Pillars: User, Application. Step: 30 days code, 60 days on the range. Effort: 3-4 days. Depends: ZT-02.
- Today: no token handling; `create_app` registers error handlers and routers and adds no middleware (`api/app.py:23-37`; no CORS, which is correct for same-origin).
- Target: `api/auth.py` validates RS256/ES256 signature, iss, aud, exp/nbf (60 s skew), azp, roles. JWKS cached in the state directory with fetch time, used while Keycloak is unreachable up to `CT_OIDC_JWKS_MAX_AGE`; unknown kid refreshes once, then fails closed. The SSE audit stream takes the same dependency.
- Done when: expired, wrong audience, wrong issuer, `alg=none` and HS256-with-public-key tokens all get 401; a valid token works with Keycloak stopped inside max age and fails after it; the token never appears in logs.

**ZT-04 Browser sessions, idle timeout and sign-out.** Pillars: User, Application. Step: 60 days. Effort: 3-5 days. Depends: ZT-01, ZT-03.
- Today: no session; the name lives in `localStorage` indefinitely and is editable (`Settings.tsx:25`).
- Target: authservice owns the cookie in mesh mode; standalone oidc uses code flow with PKCE, tokens in memory only. Idle and absolute lifetime from the realm (default 15 minutes idle, 8 hours maximum), remaining time shown, sign-out calls end-session, `GET /api/v1/whoami` replaces the name box with a read-only identity and role. Cookies Secure, HttpOnly, SameSite=Strict; cookie-authenticated writes need a custom header.
- Done when: an approve after the idle period gets 401 and redirects; a cross-site form POST to approve is rejected; `localStorage` holds no token or name; sign-out in one tab ends access in another.

**ZT-05 Step-up re-authentication for approve, policy sign, kill-switch release and scope changes.** Pillars: User. Step: 90 days. Effort: 3 days. Depends: ZT-03, ZT-04, a CAC/X.509 authenticator in the enclave realm.
- Today: `approve` (`control/approvals.py:240`), policy signing (`control/policy.py:54`, `api/routes/policy.py:90`) and `release` (`control/killswitch.py:70`) accept any accepted name with no recency check.
- Target: `require_step_up(max_age, min_acr)` on those routes (default 5 minutes); otherwise 401 with a challenge carrying `max_age` and `acr_values`, and the UI re-runs login. auth_time, acr and amr go into the record (ZT-23).
- Done when: a 10-minute-old token cannot approve and the refusal is audited; after re-login it can; a password-only login cannot approve when the floor is set to the CAC level.

**ZT-06 CLI authentication.** Pillars: User, Device. Step: 60 days. Effort: 4-6 days. Depends: ZT-02, ZT-03.
- Today: `--actor` is free text and the CLI writes state and audit directly.
- Target: `cyberthunder login` (OAuth device authorization grant, RFC 8628), token cached 0600 or in the OS store; human-only commands call the API. For a console with no browser: OS peer identity (`SO_PEERCRED` on Linux, named pipe client token on Windows), which is the operator's own smart-card logon. `--actor` survives in dev mode only.
- Done when: `approve <id> --actor bob` in oidc mode exits non-zero naming the login command; after login it records bob's subject; in peer mode another OS user gets their own identity.

**ZT-07 Disconnected operation: cached verified identity with expiry and audited break-glass.** Pillars: User, Visibility. Step: 90 days (range), 180 days (enclave CRL distribution). Effort: 1-2 weeks. Depends: ZT-03, ZT-05, ZT-08.
- Today: the IdP is never needed because nobody is verified; once ZT-02/03 land, a down Keycloak locks everyone out.
- Target: enclave Keycloak is the primary IdP afloat (shore federation optional). If Keycloak itself is down: JWKS cache, offline sessions for named approvers up to `CT_OFFLINE_SESSION_MAX` (default 72 h), CAC checked against a local CRL with a maximum age; past it, view-only. Break-glass: one sealed local account per node, credential split between two people, usable only for kill switch and viewing, banner until reviewed after reconnect.
- Done when: with Keycloak at 0 replicas, an approver signed in within the ceiling can approve and the record shows assurance `cached`; after the ceiling they cannot; with a stale CRL approve is refused; break-glass can release the kill switch but cannot approve, and both are audited. Maximum CRL age is an authorizing-official decision: record it in `docs/friction.yaml`.

### 1.2 Authorization inside the app

**ZT-08 Roles: viewer, analyst, approver, admin, auditor.** Pillars: User, Application. Step: 30 days with dev-mode roles, 60 days with Keycloak groups. Effort: 4-5 days. Depends: ZT-02.
- Today: every mutating route uses the same `require_actor` check, mostly through `ActorDep`: proposals (`api/routes/proposals.py:62-159`), policy PUT (`api/routes/policy.py:76-77`), kill release (`api/routes/kill.py:35-36`), asset accept (`api/routes/discovery.py:124-126`). GET routes take no identity.
- Target: roles from the token's groups claim via config. viewer reads; analyst scans, discovers, proposes; approver approves, denies, signs policy; admin releases the kill switch and changes scope; auditor exports and verifies. Engage stays open to every authenticated user and the machine; network callers without a credential are refused (local console and sentinel engage still work); release needs admin, a reason, and alerts on repeated engage/release. A permissions table in `control/roles.py` serves API and CLI; `ApprovalGate.approve` and `KillSwitch.release` re-check the role. The UI disables actions the user cannot take and says why.
- Done when: a test fails if any non-GET route lacks a role; an analyst approve gets 403 and is audited with reason `role`; a viewer can engage but not release; a role change applies at next token refresh.

**ZT-09 Separation of duties and a two-person rule for CAT I.** Pillars: User, Automation. Step: 30 days. Effort: 3-4 days. Depends: ZT-02 (in dev mode the rule works on typed names, labeled unverified).
- Today: `Proposal.decided_by` is one field (`control/approvals.py:76`); human proposals record their creator (`api/routes/findings.py:51`) but approve never compares; one approval moves any severity; a policy with `max_severity=None` can auto-approve anything (`control/policy.py:31`). The person who accepts a device into scope can approve and apply its first change alone.
- Target: `proposed_by`, `approvals[]` and `required_approvals` (CAT I = 2, otherwise 1, per enclave). APPROVED only when distinct approvers reach the count, none of them the proposer. A policy never satisfies a CAT I or a second approval. Optional rule: the person who accepted a device cannot be sole approver of its first change.
- Done when: alice proposes and approves, refused and audited; for a CAT I, bob approves (1 of 2), bob again (refused), carol (APPROVED); a policy matching a CAT I does not auto-approve; old `proposals.json` loads.

**ZT-10 Scope-based authorization by enclave and host group.** Pillars: User, Network, Data. Step: 60 days. Effort: 4-5 days. Depends: ZT-02, ZT-08.
- Today: `Inventory.assert_in_scope` (`inventory/targets.py:187`) checks the target, not who is asking.
- Target: targets gain `enclave` and `groups`; principals carry scopes from a claim; `control/authz.py authorize(principal, target, action)` beside every `assert_in_scope` call and in the approve path.
- Done when: an approver scoped to enclave A gets 403 on a host in enclave B, audited with both scopes; an out-of-scope scan is refused before any transport is built.

**ZT-11 Policy signing bound to a verified approver and to the policy content.** Pillars: User, Data, Automation. Step: 60 days; PIV signature at 180 days. Effort: 2-3 days, plus 3 for PIV. Depends: ZT-05, ZT-08.
- Today: `sign` and the policy PUT set `signed_by` to the caller's string (`control/policy.py:54-56`, `api/routes/policy.py:90`); `_policy_on_file` (`control/approvals.py:184-192`) checks only `enabled` and `signed_by` in the file on disk, so a hand edit of the rules in that file keeps the signature.
- Target: signing needs approver role plus step-up; the record holds sha256 of the canonical policy, the verified subject and auth_time, and a mandatory expiry. Load recomputes the hash; mismatch is unsigned (fail closed); any edit clears the signature; a policy that allows CAT I needs two signers. At 180 days, a detached CMS signature from the signer's PIV certificate checked against the enclave CA bundle.
- Done when: a hand edit of `signed_by` or any rule makes policy approvals refuse with "policy content does not match signature" in the audit; an analyst signing gets 403.

### 1.3 People to the systems

The goal is that a target's own log names the person who approved the change and the proposal it belongs to, not one standing service account. Today every target has one `username` and `credential_ref` (`inventory/targets.py:35`; `transport/ssh.py:54`, `transport/winrm.py:101`); scan and apply use the same account; the approver's name exists only in our audit log. First step at 30 days, before any of the options below: write `ct-proposal=<id> approver=<subject>` to each host's syslog or event log at apply time.

| Platform | Preferred option | Trade-off | The app does | The enclave must provide |
|---|---|---|---|---|
| Windows (AD) | Resource-based constrained delegation with protocol transition (S4U), plus JEA endpoints exposing only fix-library cmdlets | Per-target AD changes; Protected Users and "cannot be delegated" accounts (often Tier 0) are blocked; single forest unless trusts allow; no second hop | Kerberos with explicit principal, JEA `configuration_name`, refuse Basic and CredSSP | gMSA for the node, delegation rights, JEA role files, LAPS for break-glass |
| Windows (alt.) | Operator-side execution: CLI on the approver's workstation runs the digest-pinned payload with their own CAC-logon ticket | No delegation needed, but execution leaves the node | Ship the payload and digest, verify afterwards from the node | Nothing new |
| Linux | Short-lived SSH user certificates (30 min) from an enclave SSH CA, key id = approver subject, principal = role; sudoers limited per principal | Needs a CA and sshd change on every host (itself a STIG-able change we can propose); no CRL needed, certificates expire | Ephemeral key in memory, `look_for_keys=False`, cert serial in audit; PIV via ssh-agent for interactive shells | SSH CA (offline enclave CA, step-ca or Vault), `TrustedUserCAKeys`, `AuthorizedPrincipalsFile` |
| Cisco | Per-user TACACS+ (ISE where fielded) with command authorization and accounting | Shared privilege-15 login is the usual finding (`range/cisco/README.md:57`); live push unproven on a device | Log in as the approver's TACACS identity | TACACS+/RADIUS, command sets, local fallback in a broker |
| Kubernetes | Impersonation: read-only workload ServiceAccount; approved applies add `--as=<user> --as-group=<role>` | Impersonate verb must be tightly scoped | Impersonation from the lease; refuse `insecure-skip-tls-verify` | RBAC manifests (we ship them); optional API-server OIDC for kubelogin |
| Any | Broker checkout (Vault first, CyberArk CCP/Conjur) with proposal id and approver as metadata | Broker must run on the enclave; PSM session recording forces execution through its proxy | Request, scope, time out, revoke on kill switch, audit the lease | The broker, accounts, rotation, recording |

**ZT-12 Windows per-user remoting.** Pillars: User, Device, Application. Step: 90 days (range domain), 180 days (enclave). Effort: 1 week app, 1-2 weeks enclave with the range owner. Depends: ZT-02, ZT-15 or AD changes, ZT-29.
- Today: password from `CT_CRED_<ref>` (`transport/winrm.py:94-95`), default NTLM (`winrm.py:96`), Basic and CredSSP allowed (`winrm.py:26`). Kerberos and CredSSP are covered only by unit tests with a fake WinRM session (`tests/windows/test_winrm_transport.py`); no run against a domain controller is recorded in the repository.
- Target: options in the table; CredSSP rejected (reusable credentials on the target), Basic rejected outright.
- Done when: in fleet mode a Basic or CredSSP target is refused at `make_transport`; an apply approved by bob shows bob in the target's 4624/4648 events and the JEA transcript; a cmdlet outside the role capability fails on the target; a LAPS checkout writes an audit record naming the admin and host.

**ZT-13 Linux and Cisco: short-lived SSH certificates, PIV for interactive, TACACS+.** Pillars: User, Device. Step: 90 days (range), 180 days (enclave). Effort: 1 week app, 1 week CA and sshd on the range. Depends: ZT-18, ZT-19.
- Today: one username per target with a key file or password (`transport/ssh.py:43-55`); `look_for_keys=True` also tries any key in the process user's `~/.ssh` (`ssh.py:65`); sudo on by default (`docs/ADAPTING.md:37`).
- Target: short-lived SSH certificates issued per approver by an enclave CA that the range sshd trusts, with the approver's identity as the principal; `look_for_keys` off and host keys pinned from the inventory (ZT-30); PIV or CAC over PKCS#11 for interactive console use; Cisco devices authenticate and account per user through TACACS+, so every pushed command carries the approver's name in the device's accounting log.
- Done when: on a range RHEL host sshd logs the approver's key id and serial, matching the audit record; the certificate fails after expiry; a stray key in `~/.ssh` is not offered; Cisco TACACS+ accounting names the approver for each pushed command.

**ZT-14 Kubernetes: impersonation, no shared admin kubeconfig.** Pillars: User, Application. Step: 60 days. Effort: 4-6 days. Depends: ZT-01, ZT-08, ZT-17.
- Today: one kubeconfig per target (`adapters/kubernetes/kubectl.py:219-224`); the demo registers the kubeconfig the k3d deploy writes, with its admin credentials (`docs/DEPLOYMENT.md:226-234`); the range k3s instructions say the same kind of file is cluster-admin (`range/k8s/README.md:53`).
- Target: ClusterRoles `ct-viewer` and `ct-remediator` (kinds in the fix library only), no cluster-admin binding.
- Done when: the API-server audit shows the app's ServiceAccount with `impersonatedUser` equal to the approver; a scan shows no impersonation; `kubectl auth can-i delete namespaces` is no; fleet-mode docs no longer use the admin file.

**ZT-15 Broker checkout of short-lived per-user credentials.** Pillars: User, Automation, Visibility. Step: 90 days (Vault on range), 180 days (enclave broker). Effort: 1-2 weeks per broker. Depends: ZT-18, ZT-19.
- Target: `checkout(target, purpose, principal, proposal_id, ttl)` and `release(lease)`; lease taken at APPLYING, released at APPLIED/FAILED/ROLLED_BACK; the kill switch revokes outstanding leases.
- Done when: a test Vault lease carries proposal id and approver and is revoked within 10 s of APPLIED; engaging the kill switch mid-apply revokes it and the transport fails closed; both audits share the lease id.

**ZT-16 Separate scan, apply and interactive credential references.** Pillars: User, Data. Step: 30 days. Effort: 2-3 days. Depends: ZT-19.
- Today: one `credential_ref` scans, applies and verifies (`inventory/targets.py:35`); the credential that can change hosts is in the process at all times.
- Target: `credentials: {scan, apply, interactive}`; apply refs may be per-principal templates; `make_transport` (`transport/base.py:80`) takes `purpose` and `principal`. A single ref still works in dev mode; fleet mode warns.
- Done when: a scan never resolves the apply ref; an apply resolves it with the approver's principal; the scan account cannot write on a range host.

### 1.4 Workload identity for automation

**ZT-17 The node's own workload identity.** Pillars: Application, Automation. Step: 60 days. Effort: 3-5 days. Depends: ZT-01 or an enclave CA.
- Today: machine actions are recorded as `agent`/`llm`/`system`; the node is a name from `CT_NODE` (`config.py:62`); engine edges default to `actor="agent"` (`control/approvals.py:170,262`).
- Target: `Principal(kind=workload)` with a SPIFFE id from the mesh certificate, or a node certificate (TPM or OS store where available). Scheduled scans, ingest, outbox sync and post-apply verify run as it; it never holds approver roles; outbox bundles are signed with it.
- Done when: a scheduled scan's record shows the workload id; the workload identity gets 403 on approve; a bundle signed by another node is rejected on import.

**ZT-18 Least-privilege scanning; apply privilege only inside an approved window; payload digest binding.** Pillars: Automation, User. Step: 30 days (digest), 60 days (leases). Effort: 4-5 days. Depends: ZT-16; ZT-13 or ZT-15 for leases.
- Today: nothing ties the executed payload to the approved text beyond the proposal id; `start_apply` (`control/approvals.py:262`) needs no fresh credential.
- Target: each approval stores sha256 of (fix_ref, rendered payload, target); `RemediationEngine.execute` refuses on mismatch. Apply lease scoped to target and fix timeout. Record `approved_by`, `executed_by`, `lease_id`, `payload_digest`. The digest alone works on a laptop range today and answers "what exactly did the Sailor approve?"
- Done when: approve, edit the library payload on disk, apply: refused with "payload changed since approval" and state unchanged; the apply record has all four fields.

### 1.5 Credential backend

**ZT-19 Pluggable credential resolver replacing `CT_CRED_<ref>`.** Pillars: Data, Application. Step: 30 days (env, keyring, k8s), 90 days (Vault, CyberArk). Effort: 1 week, plus 3-5 days per broker. Depends: none for the interface.
- Today: `credential_from_env` (`transport/ssh.py:24-28`) is the only lookup, reused by WinRM; docs tell the operator to set variables in the node's shell (`docs/ADAPTING.md:50-52`); `discovery/service.py:710-715` assumes the naming. `credential_from_env` already refuses any variable other than `CT_CRED_<ref>`; the gap is the backend, not the naming rule. Environment values are visible to same-user processes and inherited by children.
- Target: `transport/credentials.py`: `resolve(ref, *, purpose, principal, target) -> Lease`; `Secret` redacts in `repr`/`str` and refuses JSON. Schemes `env:` (dev only), `keyring:` (Credential Manager/DPAPI, Secret Service), `k8s:` (mounted Secret), `vault:`, `cyberark:`; fleet mode forbids `env:`. Every use writes `credential.resolve` (ref, backend, purpose, target, lease id, never the value) and `credential.failed` on logon failure.
- Done when: a scan succeeds with no `CT_CRED_*` set using keyring; fleet mode refuses `env:` at inventory load; a legacy `credential_ref=lab_root` still works in dev mode; no lease or secret prints its value.

**ZT-20 No secrets on command lines, in temp files or picked up implicitly.** Pillars: Data, Device. Step: 30 days. Effort: 2 days. Depends: ZT-19.
- Target: kubectl gets a 0600 kubeconfig in a private temp directory removed after the call, never `--token`; SSH `look_for_keys=False`, `allow_agent=False` outside interactive mode; child processes get an env allowlist with no `CT_CRED_*`.
- Done when: a patched `subprocess.Popen` sees no canary in argv or child env; the temp file is gone after an exception; a key in a fake `HOME/.ssh` is not offered.

**ZT-21 Rotation without restarts.** Pillars: Data, Automation. Step: 90 days. Effort: 2-3 days. Depends: ZT-19.
- Target: resolve per operation; `k8s:` re-reads the mounted file; static scan accounts get a rotation interval and the tool raises its own finding when one is older.
- Done when: changing the mounted Secret between two scans takes effect with no restart; an overdue static credential produces a finding.

**ZT-22 Canary tests: a secret never reaches disk, inventory, audit, logs, the model or the outbox.** Pillars: Data, Visibility. Step: 30 days. Effort: 2-3 days. Depends: ZT-19 (can start with env).
- Target: `tests/security/test_secret_canary.py` runs discover, scan, explain (capturing the model prompt), propose, approve, apply, forced verify failure, rollback, report, outbox and SSE with a canary secret, then searches the state directory, DEBUG logs, exceptions, prompt and responses for it in plain, base64 and percent-encoded form.
- Done when: a deliberately planted leak makes the test fail.

### 1.6 Audit and non-repudiation

**ZT-23 Audit records carry the verified subject, assurance and session.** Pillars: Visibility, User. Step: 30 days. Effort: 2 days, plus hours for reports. Depends: ZT-02.
- Today: records hold `actor` as a string (`audit/chain.py:152-170`); reports print `p.decided_by` (`report/checklist.py:43`, `report/poam.py:74-75`, `report/onepager.py:134,167`), so "approved by IT1 Smith" in a checklist rests on the header.
- Target: `principal` field `{kind, iss, sub, name, roles, acr, amr, auth_time, session_id, device, via}` with `via` one of dev, oidc, mesh, peer, cached, break-glass; record version `v: 2`; old records stay valid. Reports print subject and audit seq for each approval.
- Done when: an oidc approve records the token's sub and acr; hand-editing `principal.name` fails `audit verify`; a mixed v1/v2 log verifies; a report lists subject and seq per approval.

**ZT-24 Signed checkpoints and off-node anchors.** Pillars: Visibility, Data. Step: 90 days; PIV approval signing at 180 days. Effort: 4-5 days, plus 1 week for PIV. Depends: ZT-17, ZT-23.
- Today: hashes are unkeyed and the `.head` checkpoint is plain JSON beside the log (`audit/chain.py:180-184`); anyone who can write the state directory can rewrite both consistently. Recording the head off the node is a manual checklist item (`docs/ADAPTING.md:252`).
- Target: signed checkpoint records (node key) every N records, at every approval and kill-switch event; heads queued in the outbox so shore holds anchors the ship cannot rewrite; `audit verify --keys`.
- Done when: a log and checkpoint rewritten without the key fail `verify --keys` after seq N; a shore import detects a head that disagrees with an earlier anchor.

**ZT-25 Audit rotation, retention and SIEM export with store-and-forward.** Pillars: Visibility. Step: 90 days. Effort: 3-4 days, plus days for rotation. Depends: ZT-23; the SIEM is named by the enclave owner.
- Today: one log that grows without bound; no rotation, archive or forwarding in `cyberthunder/audit/`.
- Target: segment rotation that keeps the chain across files; an export bundling log plus anchor; RFC 5424 syslog over TLS or JSON lines to a collector, with a per-destination high-water mark; structured stdout under UDS.
- Done when: a log over N MB rotates and verify spans segments; 100 events generated while the collector is down arrive exactly once by seq; an untrusted collector certificate is refused.

**ZT-26 Device identity of the approving workstation.** Pillars: Device, Visibility. Step: 180 days. Effort: 3 days plus gateway configuration. Depends: ZT-01, ZT-23, enclave machine PKI.
- Target: optional client machine certificate at the tenant gateway, recorded as `principal.device` verified=true; otherwise the source address, verified=false; `CT_APPROVE_REQUIRE_DEVICE` off by default. Posture checks belong to the enclave.
- Done when: with the flag on, an approval from an unverified device is refused and audited.

### 1.7 Transport security and node trust

**ZT-27 TLS for the API and UI.** Pillars: Network, Data. Step: 30 days. Effort: 1-2 days. Depends: none standalone.
- Today: `uvicorn.run(...)` with no TLS arguments (`api/app.py:50-53`); the `--host` flag can open it to the LAN.
- Target: `CT_TLS_CERT`/`CT_TLS_KEY` from the enclave CA; non-loopback bind without TLS refused unless `CT_ALLOW_PLAINTEXT` in dev mode; HSTS, `frame-ancestors none`, `no-store` on API responses; a strict host allow-list; still no CORS. Under UDS, TLS terminates at the gateway.
- Done when: `serve --host 0.0.0.0` with no certificate exits with an error; TLS 1.0/1.1 fail; HSTS is present.

**ZT-28 Mutual TLS and explicit traffic rules inside UDS.** Pillars: Network, Application. Step: 60 days. Effort: 3-4 days. Depends: ZT-01.
- Today: no package; the model server is reached at `CT_LLM_URL=http://localhost:11434` (`config.py:39`).
- Target: STRICT mTLS; only the app's ServiceAccount may call the model server and only the gateway may call the app; egress generated from the inventory's targets and ports so scope and network policy cannot drift; the model server has no egress.
- Done when: calls from another namespace fail; egress outside inventory CIDRs is blocked; the generated allow list matches the inventory in a unit test.

**ZT-29 WinRM over HTTPS only, with certificate validation.** Pillars: Network, Device. Step: 30 days. Effort: 1 day. Depends: none.
- Today: plain HTTP on 5985 unless the port is 5986 or `options.ssl` is set (`transport/winrm.py:72-73`); `cert_validation=ignore` allowed (`winrm.py:11`).
- Target: fleet mode refuses HTTP, `ignore`, Basic and CredSSP and requires a CA bundle; default auth Kerberos; range mode keeps today's behaviour and raises a warning finding against the target.
- Done when: a 5985 target in fleet mode is refused before connecting; an untrusted target certificate fails; in range mode the same target connects and the warning finding appears.

**ZT-30 SSH host key pinning from the inventory.** Pillars: Network, Device. Step: 30 days. Effort: 2-3 days. Depends: none.
- Today: `paramiko.AutoAddPolicy()` (`transport/ssh.py:62`, commented "pin keys before fleet use"); accepting a device in discovery is a name and a reason (`api/routes/discovery.py:124`) with no device identity bound.
- Target: per-target sha256 fingerprints or an SSH host CA; discovery records the observed key and acceptance pins it; `RejectPolicy`; a mismatch aborts before authentication, raises a high-severity `discovery:identity_changed` finding and an audit record. This doubles as an intrusion indicator for the hunt.
- Done when: a changed key fails before any credential is sent, with a finding and an audit record; a target with no pin is refused in fleet mode.

**ZT-31 Node hardening and state-directory protection.** Pillars: Device, Data. Step: 60 days. Effort: days. Depends: none.
- Today: the node reads every target credential and keeps state, policy and audit in one directory (`state_dir`, `config.py:36`) with no permission checks or hardening guide.
- Target: a hardening guide (service account, directory ACLs, disk encryption, STIG the node itself); startup warns on permissive ACLs; node key (ZT-17) in a TPM where available.
- Done when: startup warns when the state directory is readable by other users; the guide exists in `docs/` and names its ISSO reviewer and review date.

## 2. Other areas

### Scanning and benchmarks

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| SCAN-01 | k3s API-server flag rules report "nothing was collected" without an SSH `node_target` (`docs/DEPLOYMENT.md:241-245`); `config.yaml.d` drop-ins not read (`range/k8s/README.md:86`) | Read the k3d server container directly; read drop-ins in sorted order | A k3d scan gives pass/fail, not `not_reviewed`, for those rules | days | before range |
| SCAN-02 | Six W11 V2R11 rules unsupported plus many OVAL test types, reported `not_reviewed` (`docs/SCAP.md:121-124`) | `fileeffectiverights53` and `ntuser` first, then group/user/process/port as other benchmarks need them | `scap info` shows 0 unsupported for W11 V2R11 on a real host | week+ | before fleet |
| SCAN-03 | Windows collection only run against the simulated host; WinRM exercised through recordings only (`README.md:36-38`) | Run the collector elevated on a real Windows 11 VM over WinRM and diff with the simulator | A recorded real-host collection replays with the same results | days | before range |
| SCAN-04 | DISA RHEL benchmark is `notapplicable` on Rocky (`docs/SCAP.md:155-156`) | Optional per-target CPE alias, audited as an override | A Rocky 9 scan evaluates the DISA RHEL 9 rules and records the override | days | before range |
| SCAN-05 | Larger offline model path (about 24 GB of memory) is an unbuilt stretch; the laptop has 4 GB of VRAM (friction F6, `docs/PLAN.md` section 10) | Only with hardware: a backend behind `explain()` | The setting selects it and the citation validator still gates output | days | later |

### Remediation

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| REM-01 | Container configuration fixes print a runbook, nothing runs (`range/containers/README.md:58`); other kinds return "unsupported fix" (`adapters/containers/adapter.py:270`, `adapters/kubernetes/adapter.py:242`) | Recreate-with-snapshot for containers and Kubernetes patches, with verified rollback | A recreate fix applies on the range, verifies and rolls back to the original | week+ | before fleet |
| REM-02 | Cisco push is off by default (`range/cisco/README.md:50`) and push plus archive rollback are covered by recordings only | Test on one lab switch or emulator image; roll back by `configure replace` | A pushed fix verifies and a forced failure restores the saved config | days | before range |

### Content and link

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| CON-01 | Integrity is checked, authenticity is not: the lock file is unsigned and a folder without one is imported on integrity alone (`docs/CONTENT.md:138-139`) | Sign lock file and manifest with the operator's key; refuse unsigned folders unless a named person overrides with a reason | A tampered or unsigned folder is quarantined unless overridden and audited | days | before fleet |
| CON-02 | The DISA index comes from an anonymous call whose class id changes on redeploy (`docs/CONTENT.md:164-169`) | Keep the snapshot route as supported; clear "index unavailable" state; canary test when connected | With a bad id and changed page the UI says unavailable and the snapshot route works | days | before fleet |
| CON-03 | Link defaults (56 kbps, 500 ms) are assumptions (`range/README.md`); real link speed unknown (`docs/CONTEXT.md:172`) | Ask organizers; update config defaults and demo numbers | The open item has a recorded answer | hours | now |

### Discovery

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| DIS-01 | vCenter/ESXi inventory is a follow-up (`docs/DISCOVERY.md:66`) | vSphere source with a read-only role, same observation shape | A simulated vSphere fixture produces assets with hypervisor evidence | days | before fleet |

Device identity at acceptance is ZT-30.

### Deployment and platform

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| DEP-01 | Linux, fresh-cluster and existing-cluster paths marked untested (`docs/DEPLOYMENT.md:26`); only the WSL2 path has a recorded run | Run and record each, rewrite the status line | Each path has a dated result | days | before fleet |
| DEP-02 | WSL keep-alive is manual (`docs/DEPLOYMENT.md:215-224`) | `scripts/wsl-keepalive.ps1` sets `.wslconfig` and a logon task; bootstrap prints status | After logout and login the cluster is up with no manual step | hours | now |
| DEP-03 | Podinfo pinned by tag, not digest (`docs/DEPLOYMENT.md:381`) | Pin the digest | The package lists the digest | hours | before fleet |
| DEP-04 | DADMS entries for the app and each dependency, and no approved offline model runtime (friction F1, F2) | Open registration and evaluation requests; keep the template path as the fielded default | A sponsor and ticket numbers appear in `docs/fleet.yaml` | week+ | before fleet |

Packaging the app itself is ZT-01.

### UI

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| UI-01 | The chip shows "Acting as IT1 Smith" (`docs/UI.md:22`) and every viewer sees Approve/Deny; no provenance on a card | Show verified identity and role, disable what the user cannot do with the reason, show who approved with which credential | A viewer sees Approve disabled with a reason; provenance appears on proposal detail | days | before range |

The rest of the identity UI is in ZT-04 and ZT-08.

### Testing and range

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| TST-01 | No CI; `scripts/gate.sh` is manual; three deploy test modules ignored on Windows (`tests/conftest.py:33`); others skip without the UDS CLI, bash or Windows (`tests/test_dev.py:119`, `tests/ops/test_gate.py:26`, `tests/report/test_reports.py:99`) | CI on Linux and Windows running pytest, the gate and the UI build; fail if skip counts grow | A pull request runs the full suite on Linux with no ignored modules | days | before fleet |
| TST-02 | Live-model test skips unless `CT_TEST_LLM=1` (`tests/explain/test_service.py:151`); no browser flow test | Browser smoke test against the simulated range; live-model test before each release | A scripted browser run approves, applies and rolls back and the chain stays valid | days | before fleet |
| RNG-01 | SSH and WinRM never run against a real host; the only real target so far is the k3d cluster over kubectl (`README.md:36-39`) | Range access, or the Rocky 9 and optional Windows VM from `range/README.md`; full flow over real SSH/WinRM | Scores against `range/answer_key/` from a live scan appear on the Reports page | days | before range |
| RNG-02 | Event unknowns open: range access, link speed, Evaluate-STIG/SCC, datasets, Ark, Google link (`docs/CONTEXT.md:171-179`) | Ask in `#tech-support` and the portal | Each item is checked or has a recorded answer | hours | now |
| RNG-03 | No IT Sailor recruited as approver and no remediation-time baseline (`docs/CONTEXT.md:176`) | Run the approval flow with one IT Sailor; record today's manual hours per release and network | A sourced hours figure appears in `docs/SUBMISSION.md` | hours | now |

Identity negative tests are part of ZT-02, ZT-03 and ZT-08.

### Docs

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| DOC-01 | `docs/SUBMISSION.md:35,108`, `docs/fleet.yaml:42` and `README.md:22` say "named person" or "named human" without saying the name is self-asserted; SUBMISSION now carries one line under its transition plan | Add the same plain limitations line to the fleet file and the README, pointing at section 1 of this file | `docs/fleet.yaml` and README carry the line | hours | now |
| DOC-02 | Refused actor: `docs/API.md:9` says 400, `docs/DISCOVERY.md:132` says 403; the code raises 400 (`api/util.py:39-47`, `api/routes/discovery.py:56-61`) | Fix DISCOVERY.md | Both say 400 | hours | now |
| DOC-03 | `docs/friction.yaml` ends at F8 with nothing on identity | Add entries: no known enclave IdP or CA, who issues service credentials, CAC middleware on the range, maximum CRL age, ask for a test IdP | `report friction` renders them | hours | now |
| DOC-04 | SUBMISSION still has `[ ]` placeholders for mission owner and every measured result | Fill from the rehearsal, audit log and detection score; say "not measured" where true | No `[ ]` remains | hours | now |
| DOC-05 | `docs/CONTENT.md:107` says benchmark options are "being added on a separate branch"; both adapters already use them | Remove the sentence; add an end-to-end test for the content-store path | CONTENT.md matches the code | hours | now |
| DOC-06 | `docs/DEPLOYMENT.md:26` "Untested" predates the WSL2 run | Update with DEP-01 | Status line matches the evidence | hours | now |

## 3. Already enforced today (for contrast)

From [ARCHITECTURE](ARCHITECTURE.md) section 4:

- No change without approval: the engine refuses `execute` unless the proposal is `APPROVED`, and machine identities can never take a human edge (`ApprovalGate.HUMAN_ONLY`).
- Only vetted fixes run: `RemediationEngine.execute` runs `FixEntry.payload` only; no code path passes model output to a transport.
- Every change is reversible: `FixEntry.rollback_kind` is required, before-state is captured, and a failed verify rolls back automatically.
- Scope is enforced: `Inventory.assert_in_scope()` in the scanner and engine, and scope changes are audited.
- Everything is logged in an append-only hash chain, and the kill switch (`KillSwitch.guard()`, file, `CT_KILL` or sentinel) blocks apply and rollback edges, scans, discovery sweeps and accepts, and content checks and pulls.

## 4. Identity items by transition step

| Item | 30 days | 60 days | 90 days | 180 days |
|---|---|---|---|---|
| ZT-01 UDS package behind Keycloak | | yes | | |
| ZT-02 Verified principal | yes | | | |
| ZT-03 Token validation, cached JWKS | code | range | | |
| ZT-04 Sessions, idle timeout, sign-out | | yes | | |
| ZT-05 Step-up for approvals | | | yes | |
| ZT-06 CLI login | | yes | | |
| ZT-07 Disconnected identity, break-glass | | | range | enclave CRL |
| ZT-08 Roles | dev roles | Keycloak groups | | |
| ZT-09 Two-person rule for CAT I | yes | | | |
| ZT-10 Scope by enclave and host group | | yes | | |
| ZT-11 Policy signing bound to content | | yes | | PIV signature |
| ZT-12 Windows per-user remoting | | | range domain | enclave |
| ZT-13 SSH certificates, TACACS+ | | | range | enclave |
| ZT-14 Kubernetes impersonation | | yes | | |
| ZT-15 Broker checkout | | | Vault on range | enclave broker |
| ZT-16 Scan versus apply credentials | yes | | | |
| ZT-17 Node workload identity | | yes | | |
| ZT-18 Digest binding, apply window | digest | leases | | |
| ZT-19 Credential resolver | env, keyring, k8s | | Vault, CyberArk | |
| ZT-20 No secrets in argv or temp files | yes | | | |
| ZT-21 Rotation without restarts | | | yes | |
| ZT-22 Secret canary tests | yes | | | |
| ZT-23 Verified identity in audit and reports | yes | | | |
| ZT-24 Signed checkpoints, off-node anchors | | | yes | PIV approval signing |
| ZT-25 Audit rotation and SIEM export | | | yes | |
| ZT-26 Approving workstation identity | | | | yes |
| ZT-27 TLS for API and UI | yes | | | |
| ZT-28 mTLS and traffic rules in UDS | | yes | | |
| ZT-29 WinRM HTTPS only | yes | | | |
| ZT-30 SSH host key pinning | yes | | | |
| ZT-31 Node hardening | | yes | | |

Order of the hard dependencies: ZT-02, ZT-03, ZT-01, then ZT-04 and ZT-05, then ZT-07. Separately: ZT-19, ZT-16, ZT-18, then ZT-15, ZT-13 and ZT-12. The 30-day set needs code only, no enclave services: about 4 to 5 weeks for one person.
