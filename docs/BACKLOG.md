# Backlog

What should be done and is not. Every entry here is known work, so nobody mistakes a demo shortcut for a design decision. An item leaves this file in the same pull request that ships it; if it is dropped instead, say why in that PR. Line references were checked against the tree on 4 Nov 2026 and will drift; search for the named function if a line has moved.

**Identity today, in one line:** the application approver is still a typed name; the merged UDS package adds gateway SSO, but the application does not yet bind approvals to that verified user or a per-user target credential.

**What stops this being fielded, in short:** section 2; identity is one of five blockers, not the only one.

Identity items carry the transition-plan step from [SUBMISSION](SUBMISSION.md) (30, 60, 90 or 180 days). Other items carry one of: **now** (before the event ends), **before range** (before the training-range experiment), **before fleet** (before a limited deployment), **later**.

Completed documentation/reporting work: COV-01 now ships as `report coverage`, the Reports view and commander-report counts ([COVERAGE](COVERAGE.md)). DOC-01, DOC-02, DOC-03, DOC-04 and DOC-06 are corrected; unmeasured submission results and the unconfirmed mission owner are explicit. VAL-01 has a generated matrix and README status, while real-platform validation remains open.

## 1. Identity, credentials and zero trust

### Current state

| Question | Today | Where |
|---|---|---|
| Who is acting? | Whatever the `X-Actor` header says | `cyberthunder/api/deps.py:13-16`, `cyberthunder/api/util.py:36-48` |
| What is checked about the name? | Not empty, no control characters, at most 128 characters, not `agent`/`llm`/`system`-style, not `policy:` | `cyberthunder/control/identity.py:35-48` |
| Where does the UI get the name? | A free-text box kept in browser `localStorage` | `cyberthunder/ui/src/pages/Settings.tsx:25`, `cyberthunder/ui/src/api/client.ts:16,24` |
| CLI identity | `--actor`, defaulting to `CT_ACTOR`, then the OS user name | `cyberthunder/cli.py:113,131` |
| Login, session, token, certificate | No application principal/session validation; the UDS gateway has Keycloak SSO configuration | `cyberthunder/api/`, `packages/cyberthunder/uds.yaml` |
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
- Today: PRs #18 and #19 added the application image, PVC, Zarf package (`packages/cyberthunder`, 0.2.2) and UDS ingress/Keycloak SSO restricted to `/UDS Core/Admin`. Native Python operation remains available. App-level principal validation, per-user permissions and target credentials remain open; packaging alone does not close this item.
- Target: `packages/cyber-thunder` (Zarf package plus UDS Package CR, modeled on `packages/podinfo`) with sidecar injection, tenant-gateway expose, an SSO client, authservice selector, egress limited to inventory CIDRs and the in-namespace model server, state on a PVC. Native deployment remains supported with standalone OIDC (ZT-03/04); the optional development identity mode stays explicitly unverified. Also produce an SBOM and pin image digests (`docs/fleet.yaml:16` names Iron Bank onboarding).
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
- Today: `Inventory.assert_in_scope` (`inventory/targets.py:187`) checks the target, not who is asking. Its shared cache can retain authorization when the inventory file disappears. The cluster baseline path now adds its own fail-closed check; other active consumers still need the same missing/unreadable-source protection.
- Target: targets gain `enclave` and `groups`; principals carry scopes from a claim; `control/authz.py authorize(principal, target, action)` beside every `assert_in_scope` call and in the approve path.
- Done when: an approver scoped to enclave A gets 403 on a host in enclave B, audited with both scopes; an out-of-scope scan is refused before any transport is built; every active consumer stops when persisted scope cannot be read or verified, including mid-run removal, without continuing on cached authorization.

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
- Today: `RemediationEngine.execute` refuses when the fix's preview text or the sha256 of its library entry differs from what was approved (`remediation/engine.py:82-84,175-193`), so a library edit after approval is caught; the digest does not cover the target or the payload as rendered for that host, there is no apply lease, and `start_apply` (`control/approvals.py:262`) needs no fresh credential.
- Target: the existing digest grows to cover (fix_ref, rendered payload, target); `RemediationEngine.execute` refuses on mismatch. Apply lease scoped to target and fix timeout. Record `approved_by`, `executed_by`, `lease_id`, `payload_digest`. The digest alone works on a laptop range today and answers "what exactly did the Sailor approve?"
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

## 2. What stands between the prototype and a limited deployment

Verified identity is necessary and not sufficient. Five things stand between this prototype and a limited deployment; any one of them is enough to stop it.

| Blocker | Why it matters | Items |
|---|---|---|
| Identity and credentials | Today an approval proves only that someone typed a name, and one shared account per target does every scan and every change | ZT-01 to ZT-31 (section 1) |
| Proof across real platforms | Only Linux over SSH and a k3s/k3d cluster have met real systems; Windows, Cisco and Active Directory have not, so no detection or fix claim for them is evidence yet | VAL-01 to VAL-03, with RNG-01, SCAN-03, REM-02 |
| Coverage and fix safety | A few dozen natively checked rules per benchmark against hundreds published, and nothing stops an approved sshd or firewall change from cutting off the node that must roll it back | COV-01 to COV-04, with REM-01, SCAN-02 |
| Plumbing for scale | Documents can use JSON files or SQLite on one node; proposals, policy and inventory remain locked files, and scans still walk targets one at a time. Multi-node storage and measured enclave-scale performance remain open | SCL-01 to SCL-05, with ZT-25 |
| Accreditation path | The package includes an image SBOM, but full release evidence, control mapping, node hardening and a confirmed maintaining organization remain open | ATO-01 to ATO-04, with ZT-01, ZT-27, ZT-31, DEP-04 |

### 2.1 Proof across real platforms

**VAL-01 Validation matrix per platform and version.** Step: before fleet (remaining real runs and missing metadata). Effort: days per platform; matrix/generator shipped. Depends: RNG-01, SCAN-03, REM-02, ZT-12 for the domain row.
- Today: `docs/VALIDATION.md` and the README status are generated from `docs/validation.json` by `scripts/validation_status.py`; `--check` detects drift. Recorded runs still lack the exact tested application commit and some component versions. The first real-host run scanned a Rocky 9 VM over SSH, plus podman and k3s on it, and scored 28 of 28 seeded items with one fix applied, verified and rolled back (`range/README.md:126-203`); the UDS demo cluster (k3d) was scanned from Windows over kubectl (`docs/DEPLOYMENT.md:226-245`). Windows over WinRM, Cisco over SSH and an Active Directory domain have never been run against a real system: WinRM and SSH are exercised through recordings and simulated hosts (`README.md:36-38`), Kerberos and CredSSP only against a fake session (ZT-12), Cisco push only through recordings (REM-02).
- Target: `docs/VALIDATION.md` with one row per platform and version: Windows Server 2019, 2022, 2025 and Windows 11; RHEL 8 and 9 with Rocky and Alma; Ubuntu 22.04 and 24.04; Cisco IOS and IOS-XE switch and router; k3s and one conformant distribution; an Active Directory domain. Columns: scanned on a real host (yes/no, date, commit), seeded items found of seeded, false positives reviewed (VAL-02), fixes exercised (apply, verify, rollback), evidence path.
- Done when: the file exists with every row; no row says yes without a dated evidence path under `range/` or `docs/`; the README status line is generated from it, so the two cannot disagree.

**VAL-02 False-positive validation on each real platform.** Step: before fleet. Effort: days per platform. Depends: VAL-01; use VAL-05 for recorded reviews when available.
- Today: no finding class has a recorded disposition. The stock `system:public-info-viewer` binding to `system:unauthenticated` exists on every real cluster and is carried in a test (`tests/kubernetes/test_rbac_names.py:33`), with no recorded decision on whether reporting it is right; on k3s the API-server flag rules report that nothing was collected without a `node_target` (`docs/DEPLOYMENT.md:243-245`, SCAN-01), which a reviewer cannot tell from a pass.
- Target: for each real platform, every finding class reviewed once with a disposition of true, benchmark-not-applicable or check wrong, recorded beside VAL-01. Check wrong means the adapter is fixed with a regression test; not applicable means the rule is marked so for that platform, with the reason, in the adapter's rule data.
- Done when: every class seen on a real host has a disposition; each "check wrong" has a test that fails on the old adapter; a rescan of the same host shows no undispositioned class.
- Measurement: use a labeled set containing both known failures and known clean systems, with reviewer, evaluation unit and rule/content versions recorded. Report true positives, false positives, true negatives and false negatives, precision/recall and false-positive rate where their denominators exist, and the number and share still unreviewed. Unreviewed or unavailable results are not evidence of accuracy; seed detection scores alone do not measure the false-positive rate.

**VAL-03 Benchmark version drift.** Step: before fleet. Effort: 1 week. Depends: DOC-05 (content-store path into the adapters), CON-01.
- Today: each adapter carries its own extract: Linux `RHEL 9 V2R9` (`adapters/linux/rules.py:16`) while `STIG/` holds RHEL 9 V2R10 and RHEL 8 V2R9; Kubernetes says V2R4 (`adapters/kubernetes/checks.py:60`) with V2R6 withdrawals noted in its `stig_rules.json`; Cisco NDM V3R6, L2S V3R1, RTR V3R3 (`adapters/cisco/rules.py:29-31`); Windows 11 Release 11 in `adapters/windows/w11_catalog.json`. A host on any other release is checked against the bundled text and ids. The content pull already keeps one catalog copy per benchmark (`docs/ADAPTING.md:87`), but no adapter reads rule text from it; the nearest open item is DOC-05.
- Target: the catalog copy for the target's benchmark and release drives rule ids, titles, severities and CCIs; the bundled extract is the fallback and is labeled so on the finding; a target may pin a release; a rule the adapter checks that the catalog release dropped is reported as withdrawn, not passed.
- Done when: importing RHEL 9 V2R10 changes the titles and ids on the next scan with no code change; a finding records the benchmark release it was checked against; a test with a renamed rule id shows the catalog id.

**VAL-04 Evidence-based confidence for individual findings.** Step: before range. Effort: days. Depends: VAL-03 for content drift; VAL-02 for measured calibration.
- Today: `findings/schema.py:Finding` records severity, scanner status, source, observation time and evidence, but no detection-confidence assessment. The percentage in `ui/src/components/DiscoveryPanel.tsx` describes an asset-type guess, not the probability that a vulnerability finding is correct. `ui/src/pages/Findings.tsx` does not display finding confidence.
- Target: display High, Medium, Low or Unknown beside severity, with a plain-language reason and the evidence used. Record collection method and authentication/privilege sufficiency, scanner and benchmark/profile versions, package or image identity, observation time and freshness, applicability and corroboration/conflicts when available. Use versioned deterministic grading rules; missing privileges, stale content, version-only matches or contradictory results must remain visible. Unknown/unsupported/collection-error results never become a pass. Explain that grades are evidence-strength categories, not calibrated probabilities; do not show percentages until VAL-02 supplies a measured calibration. The explanation model cannot invent or upgrade a grade.
- Done when: fixtures for direct checks, incomplete collection, stale data, ambiguous matches and conflicting scanners produce documented grades/reasons consistently; API, Findings, detail view and reports expose the same evidence/provenance. A high-severity finding can have low confidence. Detection confidence remains distinct from fix safety/readiness (COV-02 to COV-04), and no confidence grade bypasses approval or authorizes target changes.

**VAL-05 Audited finding review and scoped false-positive decisions.** Step: before range. Effort: days. Depends: VAL-04, ZT-08 for authorized reviewers and ZT-23 for verified identity evidence.
- Today: scanner statuses include `open`, `not_a_finding` (a scanner pass), `not_applicable`, `not_reviewed` and `error`. The Kubernetes known-good API (`api/routes/cluster.py`, `adapters/kubernetes/known_good.py`) now records reasoned, optionally expiring exceptions and applies them to later scans by changing matching open results to `not_applicable`, tagging their evidence and excluding them from new proposals. This is a narrow exception facility, not separate immutable observations and review dispositions; `api/routes/findings.py` and `ui/src/components/FindingDrawer.tsx` still provide no general review workflow. A scanner pass is not a human false-positive decision. VAL-02 covers validating detector classes, not reviewing a specific observation on an asset.
- Target: add Unreviewed, Confirmed, False positive, Not applicable and Needs investigation as review dispositions separate from immutable scanner observations. Every change records reviewer identity/attribution, reason, supporting evidence, time and history; risk acceptance is a separate authorized, time-limited decision, not a false positive. Scope a decision to the asset, rule/detector and benchmark/version plus evidence fingerprint; require review/expiry dates where suppression is allowed. New or changed relevant evidence, detector/content changes or expiry reopen review instead of silently carrying a dismissal forward. Explain when identity is only self-asserted until the ZT work lands.
- Done when: UI/API can record, inspect and reverse a review with a complete audit trail; JSON and SQLite preserve it across restart/rescan, concurrent review cannot silently lose a decision, and historical scanner output is unchanged. Reports show raw, confirmed, unreviewed and suppressed counts with reasons/expiry; filters never conceal those totals. False-positive/not-applicable/risk-accepted records cannot trigger unattended remediation. Uncertain or conflicting observations require investigation before an automatic policy can act; confirming a finding still does not approve its fix. Tests cover unauthorized review, changed evidence, expiry, revocation and rescan reopening.

### 2.2 Coverage and fix safety

**COV-02 Fix safety for lockout-prone changes.** Pillars: Automation, Network. Step: before fleet. Effort: 1-2 weeks. Depends: VAL-01, REM-02.
- Today: `RemediationEngine.execute` (`remediation/engine.py:362-453`) opens one transport, captures before-state, applies and verifies over that same connection; verify includes a health result, and a failure or exception rolls back over the same transport. There is no pre-flight reachability check, no second session, no revert if the control connection itself drops, and no canary option: an approved sshd, firewall, WinRM or management-interface change that cuts the session leaves the rollback with no way in.
- Target: fixes tagged lockout-prone (sshd, PAM, firewall, WinRM listener, Cisco management plane and AAA) get a pre-flight that a second session can be opened; that second session stays open through apply and verify; the change is armed on the host with a timed revert (`at`/systemd timer, scheduled task, Cisco `configure replace` with a rollback timer) cancelled only after verify succeeds from a fresh connection; a policy option applies a fix to one canary host and waits for a human before the rest.
- Done when: on the range, a deliberately bad sshd fix that blocks logins is reverted by the host within the timer and the proposal ends ROLLED_BACK with the cause; a Cisco ACL fix that drops the session is reverted the same way; with canary on, the second host is not touched until a second approval.

**COV-03 Dry run and maintenance windows.** Step: before range. Effort: days. Depends: none.
- Today: `engine.diff` (`remediation/engine.py:579`) shows before and after only once a fix has run; the approver sees the payload verbatim but no per-host render of what apply would touch. Windows exist only on standing-policy auto-approval rules (`control/policy.py:32-33,74-80,104-105`); `execute` applies whenever an approved proposal is run.
- Target: `apply --plan` and a Plan button render, per host, the payload, files and services touched, reboot, before-state to be captured and rollback steps, without connecting for anything but read-only checks; per-target or per-enclave maintenance windows the engine refuses to apply outside of, overridable by an approver with a reason, audited.
- Done when: a plan run makes no change on the host and writes an audit record of kind plan; an apply outside the window is refused with "outside maintenance window" and state unchanged; an override records the person and reason.

**COV-04 Fix library growth from ComplianceAsCode and PowerSTIG.** Step: before fleet, then every release. Effort: ongoing, about a day per ten reviewed fixes. Depends: COV-01, COV-02, VAL-01.
- Today: each fix is a hand-written `FixEntry` (`remediation/library.py:20-40`) loaded from the adapters (`library.py:138`); ComplianceAsCode fix text is used only as built at scan time from the evaluated benchmark (`engine.py:115-125`); nothing is imported from PowerSTIG.
- Target: an import tool turning ComplianceAsCode Bash/Ansible and PowerSTIG DSC remediations into `FixEntry` records with before-state and rollback, each held as unreviewed until a named reviewer signs it off and it has passed apply, verify and rollback on the range for its platform.
- Done when: an unreviewed imported fix cannot be proposed; each reviewed fix lists its reviewer, review date and range run; COV-01 shows the executable-fix count rising per release.

### 2.3 Plumbing for scale

**SCL-01 State store behind the existing interface.** Step: before fleet. Effort: 1 week for PostgreSQL. Depends: none.
- Today: documents (scan runs, findings, explanations, link state, deltas, bulletins, discovery, content index and jobs) sit behind `StateStore` in a backend chosen by `CT_STATE_BACKEND`: json files (the default) or SQLite in WAL mode (`cyberthunder/state/`, [STATE.md](STATE.md)); `state migrate` moves a directory between them and verifies the copy and the audit chain; the suite runs on both and `tests/state/test_concurrency.py` runs two API workers and the CLI against one state with no lost update. Proposals, the policy and the inventory are still files with their own cross-process lock, because `ApprovalGate`, `load_policy` and `Inventory` take a file path (`control/approvals.py:100`, `inventory/targets.py:77`); the default backend is still json.
- Target: proposals, policy and inventory served by the document backend through a store handle instead of a path, with the gate's lock becoming the backend lock; PostgreSQL as a third backend for the UDS deployment (the interface in `cyberthunder/state/__init__.py` is five calls: get, put, delete, list, lock), with the audit chain staying a file on a persistent volume; sqlite made the default once the container image mounts the state directory from local storage.
- Done when: the concurrency test passes with proposals and inventory in the database; a node under UDS runs two API replicas against one PostgreSQL with the test green; migrating the range state directory keeps every proposal and `audit verify` passes.

**SCL-02 Scheduling and queued jobs.** Step: before fleet. Effort: 1 week. Depends: SCL-01, ZT-17.
- Today: manual scans, content pulls and reconnect checks use daemon threads; PR #20 adds opt-in periodic scans/content checks in `cyberthunder/runtime.py`. There is still no durable job queue or restart recovery. Verify runs inside `execute`.
- Target: a persistent job queue for recurring scans, content checks on reconnect and verify-after-apply, with retries and backoff, the kill switch pausing the queue, and a Jobs view showing queued, running, failed and done.
- Done when: a node restarted mid-scan resumes the job; a scheduled scan runs under the workload identity; engaging the kill switch holds queued jobs and the view says so.

**SCL-03 A fleet of hosts per enclave.** Step: before fleet. Effort: 1 week. Depends: SCL-02, ZT-19.
- Today: `Scanner.run` walks targets one at a time (`scan.py:163-170`); SSH has a 20 s connect and 120 s command timeout (`transport/ssh.py:35,72`) but there is no per-host deadline for a whole collection.
- Target: tested at 500 hosts per enclave as the first goal; parallel collection with a configurable concurrency limit; a per-host deadline; partial results saved per host with the host marked incomplete rather than the run failed.
- Done when: a simulated 500-host run finishes within a stated time on the reference node; one host that hangs is marked timed out and the other 499 report; peak connections never exceed the limit.

**SCL-04 Retention and export.** Pillars: Visibility, Data. Step: before fleet. Effort: days. Depends: SCL-01; ZT-25 for audit export to the enclave SIEM.
- Today: scans, explanations, snapshots and reports accumulate under the state directory with no retention (`store.py:55-63`); audit rotation and SIEM forwarding are ZT-25.
- Target: retention per kind (scans, findings, explanations, snapshots, reports) set by the enclave's records schedule; expired data exported to an archive bundle before deletion; deletion audited. Audit-log rotation and retention stay in ZT-25 and are not purged here.
- Done when: with a 30-day scan retention, older runs leave the store and appear in the archive with their hashes; the audit log is untouched by a purge; each purge has an audit record.

**SCL-05 Multi-enclave sync.** Pillars: Data, Network. Step: later. Effort: weeks. Depends: SCL-01, ZT-17, ZT-24, CON-01.
- Today: the outbox queues reports, POA&Ms, audit extracts and scan summaries for shore and moves them to `synced/` on reconnect (`ingest/outbox.py:1-10,93`); it is one way, and nothing syncs inventory, findings or decisions between two nodes.
- Target: a two-node design (ship and shore, or two enclaves) for inventory, findings and approval decisions over the constrained link: signed deltas, conflict rules (a decision on one node is never overwritten by the other), and a size budget per sync at the emulated link speed.
- Done when: a design note is reviewed; a two-node test syncs a day of changes under the link emulator within the budget and both audit chains still verify.

### 2.4 Accreditation path

**ATO-01 The node's own stack, hardened and documented.** Pillars: Device. Step: before fleet. Effort: 1 week. Depends: ZT-31 (state directory and node hardening), ZT-27 (TLS).
- Today: nobody has scanned the node itself; the hardening guide and state-directory checks are ZT-31, TLS is ZT-27.
- Target: the node scanned with Cyber Thunder and with the enclave's own tool against the STIG for its operating system, its findings closed or carried on a POA&M; the ZT-31 guide extended to the model server and listening ports.
- Done when: a checklist for the node itself, dated and attached to the release, shows no open CAT I and every open CAT II on a POA&M.

**ATO-02 SBOM and approved images.** Pillars: Application. Step: before fleet. Effort: days, plus Iron Bank lead time. Depends: ZT-01 (packaging, SBOM, digests), DEP-03, DEP-04.
- Today: the Zarf application package includes an image SBOM; full Python/UI/model-runtime coverage, release dependency scans and approved-image provenance still need verification. ZT-01 and DEP-03 track digest pinning; Iron Bank onboarding is named in `docs/fleet.yaml`.
- Target: beyond ZT-01 (app SBOM, digests) and DEP-03 (podinfo digest): the SBOM also covers the UI bundle and the model runtime, is produced by the release build, base images come from Iron Bank, and the SBOM gets a dependency scan at each release with findings tracked.
- Done when: every release has an SBOM listing the Python package, UI bundle and every image; the dependency scan result is in the release notes; an image not from Iron Bank is listed with its exception.

**ATO-03 Control mapping for the authorizing official.** Step: before fleet (the 90-day authorization step). Effort: days. Depends: ZT-23 for identity evidence.
- Today: guardrails and where each is enforced are in `docs/ARCHITECTURE.md:82-93`; the transition plan puts the authorization path at 90 days (`docs/SUBMISSION.md:82`) and the ATO friction line is still `[ ]` (`docs/SUBMISSION.md:98`). No mapping to NIST SP 800-53 exists.
- Target: `docs/CONTROLS.md` mapping the tool's guardrails to 800-53 families, at least AC (approval gate, roles), AU (hash-chained audit, anchors), CM (vetted fix library, before-state, rollback), IA (section 1) and SI (scans, hunt, bulletin matching), saying for each control what the tool provides, what the enclave must provide and what evidence to pull (audit export, proposal records, reports); written for the authorizing official, not for developers.
- Done when: an ISSO has read it and their questions are answered in the file; every claim points at a code path or a report the tool produces.

**ATO-04 Maintaining organization and release process.** Step: before fleet (the 180-day decision). Effort: days to set up, then ongoing. Depends: ATO-02.
- Today: the technical owner is a person (`docs/SUBMISSION.md:19`) while `docs/fleet.yaml:7-8` names NAVIFOR / Naval Network Warfare Command as mission owner and NIWC Atlantic as technical owner; the mission owner is still to be confirmed (`docs/SUBMISSION.md:18`). There are no signed releases, no vulnerability disclosure path and no update cadence.
- Target: a named maintaining organization with a point of contact; signed releases with the content, fix library and SBOM versions stated; a published disclosure path; a release within a set number of weeks after each DISA quarterly release (`docs/CONTENT.md:21`), plus out-of-band releases for critical fixes.
- Done when: the owner is recorded in `docs/fleet.yaml` and SUBMISSION agrees with it; a release signature verifies on an offline node; the disclosure path is in the README.

## 3. Other areas

### Scanning and benchmarks

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| SCAN-01 | k3s API-server flag rules report "nothing was collected" without an SSH `node_target` (`docs/DEPLOYMENT.md:241-245`); `config.yaml.d` drop-ins not read (`range/k8s/README.md:86`) | Read the k3d server container directly; read drop-ins in sorted order | A k3d scan gives pass/fail, not `not_reviewed`, for those rules | days | before range |
| SCAN-02 | Six W11 V2R11 rules unsupported plus many OVAL test types, reported `not_reviewed` (`docs/SCAP.md:121-124`) | `fileeffectiverights53` and `ntuser` first, then group/user/process/port as other benchmarks need them | `scap info` shows 0 unsupported for W11 V2R11 on a real host | week+ | before fleet |
| SCAN-03 | Windows collection only run against the simulated host; WinRM exercised through recordings only (`README.md:36-38`) | Run the collector elevated on a real Windows 11 VM over WinRM and diff with the simulator | A recorded real-host collection replays with the same results | days | before range |
| SCAN-04 | DISA RHEL benchmark is `notapplicable` on Rocky (`docs/SCAP.md:155-156`) | Optional per-target CPE alias, audited as an override | A Rocky 9 scan evaluates the DISA RHEL 9 rules and records the override | days | before range |
| SCAN-05 | Larger offline model path (about 24 GB of memory) is an unbuilt stretch; the laptop has 4 GB of VRAM (friction F6, `docs/PLAN.md` section 10) | Only with hardware: a backend behind `explain()` | The setting selects it and the citation validator still gates output | days | later |
| SCAN-06 | Implemented in PR #28: audited Nessus results import through the CLI and API, with explicit host-to-inventory mapping, source provenance and deterministic duplicate handling ([SCANNER_IMPORT](SCANNER_IMPORT.md)); imported findings appear in the current view and reports | Preserve parser limits, duplicate handling and historical/current view semantics | JSON and SQLite regressions cover CVE findings, reports, duplicate imports, invalid mappings and refusal to authorize target changes | complete | 2026-11-05 |

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
| CON-04 | The link is a configured model, not a measurement: speed, latency and the connected flag come from `link set` or the environment defaults and are always in effect (`cyberthunder/ingest/link.py:1-6`, `cyberthunder/config.py:48-50`); the transfer times in reports come from those numbers, and pacing a download to the modeled speed is a flag that is off by default (`cyberthunder/ingest/content/service.py:243`). Nothing in the tool shapes traffic; on the range that is `range/link_emulate.sh` | Measured link state: a reachability probe to the shore endpoints drives the connected flag, throughput and latency are taken from the transfers the node actually makes (index and content fetches, outbox sends) and reports quote measured times; `link set` and pacing remain only as a labelled test mode | With no operator input the node flips to disconnected within a minute of the probe failing and back on recovery, queues and flushes the outbox accordingly, and a report shows a measured rate; setting numbers by hand requires the test-mode flag and is audited as such | days | before range |

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
| UI-02 | Implemented: finding filters for category, machine, asset type, severity, scanner result, source and benchmark/release; identifier search, sorting, full-view counts and saved preferences ([FINDINGS](FINDINGS.md)) | Preserve filtering and sorting before pagination on both backends; indexed queries at enclave scale remain in SCL-03 | API regressions and a browser check cover combined filters, current/historical views, stable sorts, missing metadata and reset/persistence | complete | 2026-11-05 |

The rest of the identity UI is in ZT-04 and ZT-08.

### Testing and range

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| TST-01 | No CI; `scripts/gate.sh` is manual; three deploy test modules ignored on Windows (`tests/conftest.py:33`); others skip without the UDS CLI, bash or Windows (`tests/test_dev.py:119`, `tests/ops/test_gate.py:26`, `tests/report/test_reports.py:99`) | CI on Linux and Windows running pytest, the gate and the UI build; fail if skip counts grow | A pull request runs the full suite on Linux with no ignored modules | days | before fleet |
| TST-02 | Live-model test skips unless `CT_TEST_LLM=1` (`tests/explain/test_service.py:151`); no browser flow test | Browser smoke test against the simulated range; live-model test before each release | A scripted browser run approves, applies and rolls back and the chain stays valid | days | before fleet |
| RNG-01 | Linux over SSH has met a real host (the Rocky 9 range VM: 28 of 28 seeded items, one fix applied and rolled back, `range/README.md` "First real-host run") and the k3d cluster was scanned over kubectl; WinRM and Cisco over SSH have never run against a real system | The Windows VM from `range/windows/README.md` over real WinRM, and a Cisco device or emulator over SSH | Scores against `range/answer_key/` from a live scan appear on the Reports page | days | before range |
| RNG-02 | Event unknowns open: range access, link speed, Evaluate-STIG/SCC, datasets, Ark, Google link (`docs/CONTEXT.md:171-179`) | Ask in `#tech-support` and the portal | Each item is checked or has a recorded answer | hours | now |
| RNG-03 | No IT Sailor recruited as approver and no remediation-time baseline (`docs/CONTEXT.md:176`) | Run the approval flow with one IT Sailor; record today's manual hours per release and network | A sourced hours figure appears in `docs/SUBMISSION.md` | hours | now |

Identity negative tests are part of ZT-02, ZT-03 and ZT-08.

### Docs

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| DOC-05 | CONTENT.md now describes the shipped benchmark options and distinguishes node-side Windows content from target-side Linux paths | Add an end-to-end content-store-to-adapter test | Imported content is used by each adapter in a regression test | hours | before range |

### Cluster MVP path (team plan of 5 Nov)

The team's MVP plan (Cyber Thunder running inside the UDS cluster, fixing `nginx-bad`) mapped to what exists. Done already: file-based state, the UI, the configurable model backend, approval, apply with verify and automatic rollback, the Cisco simulation, the Linux VM run from the node. Pointer rows name the item that carries the work.

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| MVP-01 | Application packaging and UDS gateway SSO shipped in PRs #18/#19 (`packages/cyberthunder`); end-to-end validation of the intended cluster scan/fix flow remains open | Validate the existing package and PVC with the intended model service and target access; verified application principals remain in ZT-02/03 | `uds zarf dev lint` passes and the UI loads inside the cluster behind the tenant gateway | 1-2 weeks | before range |
| MVP-02 | Keycloak sign-in (item 1.3) | Covered by ZT-01 to ZT-03 | see those items | - | 30-60 days |
| MVP-03 | PR #20 adds cluster image enumeration and Trivy baseline scans through `cyberthunder/cluster/service.py`; results are namespace profiles and baseline JSON, separate from normalized findings. The Containerfile installs Trivy but does not preload its database; skipping database updates alone does not establish disconnected operation | Connect image CVEs to the existing findings/approval/report flow and validate nginx-bad; package and version the required databases/images, expose stale or missing data, and apply MVP-11 guardrails | Image CVEs have identifiers and image references in the normal findings queue, backed by a recorded cluster run with egress blocked; missing database/image content is reported as unavailable, never a clean scan | days | before range |
| MVP-04 | PR #20 adds `scripts/scan-container-os.sh` for mounted root filesystems and oscap-podman targets, plus an XCCDF converter; application integration and the nginx-bad result are not established here | Integrate the script output as normalized findings and validate UBI/RHEL profile applicability | A recorded nginx-bad image evaluation lands in the findings workflow with unsupported/not-applicable outcomes preserved | days | before fleet |
| MVP-05 | Implemented: optional `CT_LLM_API_KEY` authentication is read for each compatible-backend request, including probes and format fallback; credentialed redirects are refused and diagnostics omit secrets ([MODEL_AUTH](MODEL_AUTH.md)). A separate agent harness remains a team decision | Keep regression coverage for authenticated and unauthenticated local endpoints | Mocked tests cover rotation, auth failure, redirect refusal and decoded secret reflection; no live endpoint was required | complete | 2026-11-05 |
| MVP-06 | CVE remediation by newer image (items 4.1 and 6.2): nothing pulls container images or bumps image tags; the resumable, allow-listed downloader exists for STIG content only (`cyberthunder/ingest/content/fetch.py`) | a newer-image check against the pinned tag or digest; a durable registry pull over the slow link reusing the downloader's resume and caps (Zarf air-gap packages as the carrier in UDS); a fix entry that bumps the deployment image with before-state and rollback | nginx-bad's image is updated through approve, apply, verify and rollback, with the pull surviving a dropped link | 1 week | before range |
| MVP-07 | GitOps-style Kubernetes remediation (item 4.2.1): fixes patch live objects with before-state (`cyberthunder/adapters/kubernetes/fixes.py`), so a chart or ArgoCD sync would undo them | emit the fix as a chart or manifest change to the package repository when a GitOps controller owns the workload, with the live patch as the immediate action | a fix survives an ArgoCD sync | 1 week | before fleet |
| MVP-08 | STIG-hardened RHEL 9 image pipeline (item 4.2.2): nothing rebuilds a hardened container image pinned by the chart or Zarf package | a build that applies the RHEL 9 STIG content to the UBI base, scans it, and pins the result by digest in the package | the rebuilt nginx-bad image scans clean and the package pins its digest | 1-2 weeks | later |
| MVP-09 | Velero as cluster-wide rollback (item 7): every fix restores its own before-state; there is no cluster-level snapshot | an optional Velero backup before a batch apply and a restore path in the engine for cluster targets | a batch of Kubernetes fixes is reverted by a Velero restore recorded in the audit log | days | later |
| MVP-10 | Linux VM STIG changes from inside the cluster (parallel item 2): done from the operator node (`range/README.md`); from a pod it needs MVP-01, egress to the host and credentials (ZT-12, ZT-13, ZT-19) | depends on MVP-01 | the Rocky range run repeats from a pod | - | after MVP-01 |
| MVP-11 | Implemented: active cluster survey and baseline scans require a named actor and an explicitly scoped inventory target; kill, scope and pinned configuration are rechecked around external calls and publication. Opt-in bootstrap registers new targets out of scope and preserves operator edits ([CLUSTER_GUARDRAILS](CLUSTER_GUARDRAILS.md)) | Preserve these guards on new cluster entry points; verified identity remains in ZT-02/03 | Regressions cover killed, missing, revoked or changed target configuration, interrupted baselines and bootstrap preservation; a running subprocess stops at its next boundary or timeout | complete | 2026-11-05 |

## 4. Already enforced today (for contrast)

From [ARCHITECTURE](ARCHITECTURE.md) section 4. Cluster survey, baseline and bootstrap guards are also implemented as described in [CLUSTER_GUARDRAILS](CLUSTER_GUARDRAILS.md); typed actor names remain unverified identity:

- No change without approval: the engine refuses `execute` unless the proposal is `APPROVED`, and machine identities can never take a human edge (`ApprovalGate.HUMAN_ONLY`).
- Only vetted fixes run: `RemediationEngine.execute` runs `FixEntry.payload` only; no code path passes model output to a transport.
- Every change is reversible: `FixEntry.rollback_kind` is required, before-state is captured, and a failed verify rolls back automatically.
- Scope is enforced: `Inventory.assert_in_scope()` in the scanner and engine, and scope changes are audited.
- Everything is logged in an append-only hash chain, and the kill switch (`KillSwitch.guard()`, file, `CT_KILL` or sentinel) blocks apply and rollback edges, scans, discovery sweeps and accepts, and content checks and pulls.

## 5. Identity items by transition step

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

Section 2 items by step:

| Step | Items |
|---|---|
| before range | VAL-04 finding confidence, VAL-05 audited finding review, COV-03 dry run and windows |
| before fleet | VAL-01 (every row), VAL-02 triage, VAL-03 version drift, COV-02 lockout safety, COV-04 fix library growth, SCL-01 state store, SCL-02 job queue, SCL-03 500 hosts, SCL-04 retention, ATO-01 node hardening, ATO-02 SBOM, ATO-03 control mapping (90 days), ATO-04 maintainer and releases (180 days) |
| later | SCL-05 multi-enclave sync |
