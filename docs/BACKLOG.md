# Backlog

What should be done and is not. Every entry here is known work, so nobody mistakes a demo shortcut for a design decision. An item leaves this file in the same pull request that ships it; if it is dropped instead, say why in that PR. Line references were checked against the tree on 4 Nov 2026 and will drift; search for the named function if a line has moved.

**Identity today, in one line:** configured OIDC/mesh mode verifies the acting account, enforces roles and target/environment/action grants, and selects that account's configured target credentials. Local development mode remains explicitly unverified. Live enclave identity integration and the remaining controls below are still required.

**What stops this being fielded, in short:** section 2; identity is one of five blockers, not the only one.

Identity items carry the transition-plan step from [SUBMISSION](SUBMISSION.md) (30, 60, 90 or 180 days). Other items carry one of: **now** (before the event ends), **before range** (before the training-range experiment), **before fleet** (before a limited deployment), **later**.

Completed documentation/reporting work: COV-01 now ships as `report coverage`, the Reports view and commander-report counts ([COVERAGE](COVERAGE.md)). DOC-01, DOC-02, DOC-03, DOC-04 and DOC-06 are corrected; unmeasured submission results and the unconfirmed mission owner are explicit. VAL-01 has a generated matrix and README status, while real-platform validation remains open.

## 1. Identity, credentials and zero trust

### Current state

| Question | Today | Where |
|---|---|---|
| Who is acting? | Verified issuer/subject in OIDC or mesh mode; caller-supplied names cannot replace it | `control/principal.py`, `api/auth.py` |
| Login and sessions | Signed access tokens or server-held browser sessions with PKCE, CSRF, idle/absolute expiry and local logout | [AUTHORIZATION](AUTHORIZATION.md), [BROWSER_IDENTITY](BROWSER_IDENTITY.md) |
| UI identity | Verified name, roles and permission explanations; development name remains labeled unverified | `ui/src/state/Identity.tsx`, `components/ActorChip.tsx` |
| CLI identity | Human device login and authenticated API commands preserve server authorization; local typed-actor operations remain development-only | ZT-06, [CLI_AUTH](CLI_AUTH.md) |
| Roles and human decisions | Viewer, analyst, approver, admin and auditor; workload accounts cannot approve/apply/rollback | `control/roles.py` |
| Resource authorization | Exact account/group grants by target, environment and operation; node administration is separate | [ACCOUNT_ACCESS](ACCOUNT_ACCESS.md) |
| Global history | Unfiltered node views require explicit `read.all`; audit is an explicit node-wide permission; target export is separate | `api/access.py`, `control/access.py` |
| Historical evidence | Recorded target generation and environment prevent reassignment when IDs are reused or targets move; legacy unclassified records are unavailable in verified mode | `security/resources.py` |
| Target credentials | Explicit account/action bindings for SSH, WinRM and protected static Kubernetes configs; no ambient/shared-admin fallback in verified mode | `security/credentials.py`, `security/kube_credentials.py` |
| Standing policy | Enabled automatic approval is refused in verified mode pending content-bound signing | ZT-11 |
| Audit identity | Version 2 records hash-cover verified principal evidence; old version 1 records remain unverified | `audit/chain.py` |
| Transport trust | Fleet SSH requires trusted host identity; fleet WinRM requires HTTPS and CA validation; acknowledged range exceptions are recorded | [TRANSPORT_SECURITY](TRANSPORT_SECURITY.md) |
| Remaining trust boundaries | Protected files enforce native Windows SID/DACL or POSIX ownership/mode checks. Whole-state provisioning, realm claim mappings, target-side privileges and actual enclave connectivity still need deployment validation | ZT-01/12/13/14/19/31 |

Implementation tests use isolated identity and transport fixtures. Actual local Keycloak browser acceptance also covers four roles with JSON and SQLite ([OIDC_REVIEW](OIDC_REVIEW.md)). These checks do not establish CAC acceptance, AD delegation, an enclave deployment, a production broker, or zero-trust compliance. The remaining acceptance criteria below are retained deliberately.

### 1.1 People into the app

**ZT-01 Package Cyber Thunder as a UDS package behind Keycloak SSO.** Pillars: User, Application, Network. Step: 60 days. Effort: 1-2 weeks. Depends: UDS Core cluster ([DEPLOYMENT](DEPLOYMENT.md)), `packages/identity-bootstrap`.
- Today: The image, PVC, Zarf package and gateway SSO exist. The app now has explicit OIDC/mesh validation and browser login, but the deployed UDS token forwarding, client/claim mappings, network restrictions and live login acceptance must still be configured and demonstrated. Native operation remains supported.
- Target: `packages/cyber-thunder` (Zarf package plus UDS Package CR, modeled on `packages/podinfo`) with sidecar injection, tenant-gateway expose, an SSO client, authservice selector, egress limited to inventory CIDRs and the in-namespace model server, state on a PVC. Native deployment remains supported with standalone OIDC (ZT-03/04); the optional development identity mode stays explicitly unverified. Also produce an SBOM and pin image digests (`docs/fleet.yaml:16` names Iron Bank onboarding).
- Done when: a request without a session is redirected to Keycloak; a pod outside the mesh cannot reach the app; `uds zarf dev lint packages/cyber-thunder` passes; the UI loads after login as an identity-bootstrap test user.

**ZT-02 Replace the typed X-Actor name with a verified principal.** Pillars: User, Application. Step: 30 days. Effort: 4-6 days. Depends: none for the seam.
- Today: Implemented: immutable verified principals, strict authentication on API routes, canonical actor binding at approval/kill/resource boundaries, and loopback-only unverified development mode. Forged names and workload human actions are rejected. Verified CLI login is separate ZT-06 work.
- Target: `control/principal.py` with a frozen `Principal` (issuer, subject, display name, roles, groups, scopes, acr/amr, auth_time, session id, device, kind human|workload|dev). `get_principal` with three modes: `oidc` (validate a bearer token), `mesh` (validate the authservice-forwarded token, never trust headers as such), `dev` (today's header, kind=dev, assurance none, loopback only). `require_actor` becomes `require_principal`; the gate, kill switch and policy keep an actor string (`iss|sub`) plus the principal for audit, so state logic is untouched.
- Done when: in oidc mode `X-Actor: alice` alone gets 401; a valid token records alice's issuer and subject; dev mode refuses a non-loopback bind; a test walks `app.routes` and fails if any non-GET route other than `POST /kill/engage` and the read-only `POST /policy/evaluate` and `POST /discovery/scopes/preview` lacks `require_principal`; forged-header, wrong-CA and expired cases are tested and each writes an audit record.

**ZT-03 OIDC token validation with an offline-cached JWKS.** Pillars: User, Application. Step: 30 days code, 60 days on the range. Effort: 3-4 days. Depends: ZT-02.
- Today: Implemented: bounded RS256/ES256 validation, issuer/audience/party/expiry checks and protected offline JWKS caching. Mixed signing/encryption key handling and explicit scope configuration passed actual local Keycloak 26.7.4 browser acceptance. Signed test-provider, cache replacement/expiry, clock and TLS failure cases are covered. Real enclave Keycloak outage/recovery acceptance remains open.
- Target: `api/auth.py` validates RS256/ES256 signature, iss, aud, exp/nbf (60 s skew), azp, roles. JWKS cached in the state directory with fetch time, used while Keycloak is unreachable up to `CT_OIDC_JWKS_MAX_AGE`; unknown kid refreshes once, then fails closed. The SSE audit stream takes the same dependency.
- Done when: expired, wrong audience, wrong issuer, `alg=none` and HS256-with-public-key tokens all get 401; a valid token works with Keycloak stopped inside max age and fails after it; the token never appears in logs.

**ZT-04 Browser sessions, idle timeout and sign-out.** Pillars: User, Application. Step: 60 days. Effort: 3-5 days. Depends: ZT-01, ZT-03.
- Today: Implemented: PKCE browser login, server-memory tokens, opaque Secure/HttpOnly/SameSite=Lax cookies, Origin/CSRF checks, idle/absolute limits and logout that revokes copied background contexts. Passive status polling does not renew idle time. Actual local Keycloak acceptance passed 54 JSON and 70 SQLite browser checks across four roles. Sessions are single-process and do not survive restart; IdP-wide logout and live enclave acceptance remain open.
- Target: authservice owns the cookie in mesh mode; standalone oidc uses code flow with PKCE, tokens in memory only. Idle and absolute lifetime from the realm (default 15 minutes idle, 8 hours maximum), remaining time shown, sign-out calls end-session, `GET /api/v1/whoami` replaces the name box with a read-only identity and role. Cookies Secure, HttpOnly, SameSite=Lax for the authorization-code callback; cookie-authenticated writes need a custom header.
- Done when: an approve after the idle period gets 401 and redirects; a cross-site form POST to approve is rejected; `localStorage` holds no token or name; sign-out in one tab ends access in another.

**ZT-05 Step-up re-authentication for approve, policy sign, kill-switch release and scope changes.** Pillars: User. Step: 90 days. Effort: 3 days. Depends: ZT-03, ZT-04, a CAC/X.509 authenticator in the enclave realm.
- Today: Implemented signed authentication-age and exact configured assurance checks, monotonic freshness, bounded reauthentication challenges, retained browser assurance across refresh and deliberate UI re-login without mutation replay ([STEP_UP](STEP_UP.md)). Bulk outcomes preserve earlier decisions if assurance expires mid-batch. Explicitly admitted content/database transfers can continue beyond the freshness window while the original credential, session, account, policy and job remain valid; admission never extends token expiry or permits a new administrative decision. Live realm mapping, authenticator/CAC acceptance and longer delegation remain open. Enabled standing approvals are refused in verified mode.
- Target: `require_step_up(max_age, min_acr)` on those routes (default 5 minutes); otherwise 401 with a challenge carrying `max_age` and `acr_values`, and the UI re-runs login. auth_time, acr and amr go into the record (ZT-23).
- Done when: a 10-minute-old token cannot approve and the refusal is audited; after re-login it can; a password-only login cannot approve when the floor is set to the CAC level.

**ZT-06 CLI authentication.** Pillars: User, Device. Step: 60 days. Effort: 4-6 days. Depends: ZT-02, ZT-03.
- Today: Implemented `auth login/status/logout` using human device authorization and an explicit verified `api` command namespace. Protected per-OS-user token files, rotating refresh, logout generations and bounded HTTPS retain server role/resource/step-up/approval enforcement ([CLI_AUTH](CLI_AUTH.md)). Native Windows/Linux fixtures pass; actual realm/public-client acceptance, peer-OS-user isolation and immediate bearer revocation remain open. Ordinary local state-changing commands still refuse verified mode.
- Target: `cyberthunder login` (OAuth device authorization grant, RFC 8628), token cached 0600 or in the OS store; human-only commands call the API. For a console with no browser: OS peer identity (`SO_PEERCRED` on Linux, named pipe client token on Windows), which is the operator's own smart-card logon. `--actor` survives in dev mode only.
- Done when: `approve <id> --actor bob` in oidc mode exits non-zero naming the login command; after login it records bob's subject; in peer mode another OS user gets their own identity.

**ZT-07 Disconnected operation: cached verified identity with expiry and audited break-glass.** Pillars: User, Visibility. Step: 90 days (range), 180 days (enclave CRL distribution). Effort: 1-2 weeks. Depends: ZT-03, ZT-05, ZT-08.
- Today: Existing signed tokens can be validated with bounded cached JWKS. Browser sessions remain bounded and in memory. Expiry is never bypassed; disconnected refresh/login, CRL distribution and reviewed break-glass remain open.
- Target: enclave Keycloak is the primary IdP afloat (shore federation optional). If Keycloak itself is down: JWKS cache, offline sessions for named approvers up to `CT_OFFLINE_SESSION_MAX` (default 72 h), CAC checked against a local CRL with a maximum age; past it, view-only. Break-glass: one sealed local account per node, credential split between two people, usable only for kill switch and viewing, banner until reviewed after reconnect.
- Done when: with Keycloak at 0 replicas, an approver signed in within the ceiling can approve and the record shows assurance `cached`; after the ceiling they cannot; with a stale CRL approve is refused; break-glass can release the kill switch but cannot approve, and both are audited. Maximum CRL age is an authorizing-official decision: record it in `docs/friction.yaml`.

### 1.2 Authorization inside the app

**ZT-08 Roles: viewer, analyst, approver, admin, auditor.** Pillars: User, Application. Step: 30 days with dev-mode roles, 60 days with Keycloak groups. Effort: 4-5 days. Depends: ZT-02.
- Today: Implemented: explicit viewer/analyst/approver/admin/auditor permissions on API and core decisions, workload restrictions, and disabled UI actions with reasons. An admin role does not imply approval or target access. Trusted role-claim mapping and actual realm changes still need enclave acceptance.
- Target: roles from the token's groups claim via config. viewer reads; analyst scans, discovers, proposes; approver approves, denies, signs policy; admin releases the kill switch and changes scope; auditor exports and verifies. Engage stays open to every authenticated user and the machine; network callers without a credential are refused (local console and sentinel engage still work); release needs admin, a reason, and alerts on repeated engage/release. A permissions table in `control/roles.py` serves API and CLI; `ApprovalGate.approve` and `KillSwitch.release` re-check the role. The UI disables actions the user cannot take and says why.
- Done when: a test fails if any non-GET route lacks a role; an analyst approve gets 403 and is audited with reason `role`; a viewer can engage but not release; a role change applies at next token refresh.

**ZT-09 Separation of duties and a two-person rule for CAT I.** Pillars: User, Automation. Step: 30 days. Effort: remaining range acceptance and optional first-device rule. Depends: ZT-02 (optional development enforcement uses typed names, labeled unverified).
- Today: Implemented verified proposer exclusion, account quorums and explicit v2 person-association quorums. CAT I or unknown severity requires two approvers; other severities require one. Account roles, grants and credentials remain separate even when aliases map to one person. Server-derived requirements, payload, assessment and association evidence are checked against original audit records and current facts before approval and mutation. UI/reports identify the quorum basis; legacy records cannot gain authority ([SEPARATION_OF_DUTIES](SEPARATION_OF_DUTIES.md), [PERSON_ASSOCIATION](PERSON_ASSOCIATION.md)). Local Keycloak account-decision/freshness acceptance passed on JSON and SQLite; that earlier exercise did not test person mappings. Intended enclave acceptance, trusted association provisioning and the optional first-device-registrar restriction remain open.
- Target: `proposed_by`, `approvals[]` and `required_approvals` (CAT I = 2, otherwise 1, per enclave). APPROVED only when distinct approvers reach the count, none of them the proposer. A policy never satisfies a CAT I or a second approval. Optional rule: the person who accepted a device cannot be sole approver of its first change.
- Done when: alice proposes and approves, refused and audited; for a CAT I, bob approves (1 of 2), bob again (refused), carol (APPROVED); a policy matching a CAT I does not auto-approve; old `proposals.json` loads.
- Separate-account acceptance: v2 requires a protected explicit stable person association and rejects aliases as another vote or as a way to approve one's own proposal. Missing/ambiguous mappings fail closed; names/email are not inferred. Provision and validate those associations in the actual environment. v1 still proves distinct accounts only. Policy byte changes require new proposals and approvals; trusted whole-policy restoration remains a documented limit.

**ZT-10 Per-user and per-account authorization by environment, target and operation.** Pillars: User, Network, Data. Step: 60 days. Effort: 4-5 days. Depends: ZT-02, ZT-08.
- Today: Implemented: fresh fail-closed account/group policy, separate node grants, exact target/environment/action grants, account-specific credential bindings and copied-principal guards. Stored findings, proposals, scans and exports retain their original ownership; moved/deleted/reused IDs do not grant historical access. Live multi-user enclave acceptance remains open.
- Target: each verified issuer/account and trusted group receives explicit permissions for particular environments and targets. Read, discover, scan, propose, approve, apply, verify and rollback can differ per user and per environment. An application administrator does not automatically receive target administrator rights. Enforce these permissions beside scope checks, on direct object reads, before list counts/facets/exports, in background jobs and in the approval gate. Node-wide administration is a separate explicit grant.
- Done when: an approver scoped to environment A gets 403 on a host in B; a user who can scan A but only approve B cannot swap those permissions; users cannot retrieve another environment's findings, histories or counts. Select target credentials by authenticated account, target and operation (ZT-16/19), with no shared-admin fallback. Denials are audited, revocation applies before the next operation, and missing/unreadable policy or scope stops every active consumer before transport access, including mid-run removal.

**ZT-11 Policy signing bound to a verified approver and to the policy content.** Pillars: User, Data, Automation. Step: 60 days; PIV signature at 180 days. Effort: 2-3 days, plus 3 for PIV. Depends: ZT-05, ZT-08.
- Today: Verified mode refuses enabled standing approval policies until content-bound signing is implemented. Local development retains the existing typed signer behavior. Human approval is still required for verified changes.
- Target: signing needs approver role plus step-up; the record holds sha256 of the canonical policy, the verified subject and auth_time, and a mandatory expiry. Load recomputes the hash; mismatch is unsigned (fail closed); any edit clears the signature; a policy that allows CAT I needs two signers. At 180 days, a detached CMS signature from the signer's PIV certificate checked against the enclave CA bundle.
- Done when: a hand edit of `signed_by` or any rule makes policy approvals refuse with "policy content does not match signature" in the audit; an analyst signing gets 403.

### 1.3 People to the systems

The goal is that a target's own log names the person who approved the change and the proposal it belongs to, not one standing service account. Verified mode selects account- and operation-specific credentials from protected policy. Proving that the selected target account maps to the intended human, adding short-lived credentials, and host-side approval correlation remain open. First step at 30 days, before any of the options below: write `ct-proposal=<id> approver=<subject>` to each host's syslog or event log at apply time.

| Platform | Preferred option | Trade-off | The app does | The enclave must provide |
|---|---|---|---|---|
| Windows (AD) | Resource-based constrained delegation with protocol transition (S4U), plus JEA endpoints exposing only fix-library cmdlets | Per-target AD changes; Protected Users and "cannot be delegated" accounts (often Tier 0) are blocked; single forest unless trusts allow; no second hop | Kerberos with explicit principal, JEA `configuration_name`, refuse Basic and CredSSP | gMSA for the node, delegation rights, JEA role files, LAPS for break-glass |
| Windows (alt.) | Operator-side execution: CLI on the approver's workstation runs the digest-pinned payload with their own CAC-logon ticket | No delegation needed, but execution leaves the node | Ship the payload and digest, verify afterwards from the node | Nothing new |
| Linux | Short-lived SSH user certificates (30 min) from an enclave SSH CA, key id = approver subject, principal = role; sudoers limited per principal | Needs a CA and sshd change on every host (itself a STIG-able change we can propose); no CRL needed, certificates expire | Ephemeral key in memory, `look_for_keys=False`, cert serial in audit; PIV via ssh-agent for interactive shells | SSH CA (offline enclave CA, step-ca or Vault), `TrustedUserCAKeys`, `AuthorizedPrincipalsFile` |
| Cisco | Per-user TACACS+ (ISE where fielded) with command authorization and accounting | Shared privilege-15 login is the usual finding (`range/cisco/README.md:57`); live push unproven on a device | Log in as the approver's TACACS identity | TACACS+/RADIUS, command sets, local fallback in a broker |
| Kubernetes | Impersonation: read-only workload ServiceAccount; approved applies add `--as=<user> --as-group=<role>` | Impersonate verb must be tightly scoped | Impersonation from the lease; refuse `insecure-skip-tls-verify` | RBAC manifests (we ship them); optional API-server OIDC for kubelogin |
| Any | Broker checkout (Vault first, CyberArk CCP/Conjur) with proposal id and approver as metadata | Broker must run on the enclave; PSM session recording forces execution through its proxy | Request, scope, time out, revoke on kill switch, audit the lease | The broker, accounts, rotation, recording |

**ZT-12 Windows per-user remoting.** Pillars: User, Device, Application. Step: 90 days (range domain), 180 days (enclave). Effort: 1 week app, 1-2 weeks enclave with the range owner. Depends: ZT-02, ZT-15 or AD changes, ZT-29.
- Today: Verified mode selects an explicit per-account NTLM credential under the fleet HTTPS/CA rules. Protected mounted-file and Windows Credential Manager sources now supply bounded password leases; fleet password references require a resolver. AD Kerberos delegation, JEA, protected-user behavior and real domain acceptance remain unimplemented/unvalidated ([CREDENTIAL_RESOLVERS](CREDENTIAL_RESOLVERS.md)).
- Target: options in the table; CredSSP rejected (reusable credentials on the target), Basic rejected outright.
- Done when: in fleet mode a Basic or CredSSP target is refused at `make_transport`; an apply approved by bob shows bob in the target's 4624/4648 events and the JEA transcript; a cmdlet outside the role capability fails on the target; a LAPS checkout writes an audit record naming the admin and host.

**ZT-13 Linux and Cisco: short-lived SSH certificates, PIV for interactive, TACACS+.** Pillars: User, Device. Step: 90 days (range), 180 days (enclave). Effort: 1 week app, 1 week CA and sshd on the range. Depends: ZT-18, ZT-19.
- Today: Selected SSH keys and password references are explicit and bound to account and operation; fleet host identity checks and sudo policy are enforced. Protected mounted-file and Windows Credential Manager sources can provide password leases; environment passwords are limited to range compatibility. SSH certificate issuance, PIV and TACACS+ integration remain open.
- Target: short-lived SSH certificates issued per approver by an enclave CA that the range sshd trusts, with the approver's identity as the principal; `look_for_keys` off and host keys pinned from the inventory (ZT-30); PIV or CAC over PKCS#11 for interactive console use; Cisco devices authenticate and account per user through TACACS+, so every pushed command carries the approver's name in the device's accounting log.
- Done when: on a range RHEL host sshd logs the approver's key id and serial, matching the audit record; the certificate fails after expiry; a stray key in `~/.ssh` is not offered; Cisco TACACS+ accounting names the approver for each pushed command.

**ZT-14 Kubernetes: impersonation, no shared admin kubeconfig.** Pillars: User, Application. Step: 60 days. Effort: 4-6 days. Depends: ZT-01, ZT-08, ZT-17.
- Today: Verified scans and baseline commands use a protected, explicitly selected single-context static kubeconfig for the acting account. Plugins, impersonation flags, extra identities and ambient credential fallback are rejected. Secondary node collection uses its own authorized credential binding. Short-lived issuance, Kubernetes impersonation and live RBAC acceptance remain open.
- Target: ClusterRoles `ct-viewer` and `ct-remediator` (kinds in the fix library only), no cluster-admin binding.
- Done when: the API-server audit shows the app's ServiceAccount with `impersonatedUser` equal to the approver; a scan shows no impersonation; `kubectl auth can-i delete namespaces` is no; fleet-mode docs no longer use the admin file.

**ZT-15 Broker checkout of short-lived per-user credentials.** Pillars: User, Automation, Visibility. Step: 90 days (Vault on range), 180 days (enclave broker). Effort: 1-2 weeks per broker. Depends: ZT-18, ZT-19.
- Target: `checkout(target, purpose, principal, proposal_id, ttl)` and `release(lease)`; lease taken at APPLYING, released at APPLIED/FAILED/ROLLED_BACK; the kill switch revokes outstanding leases.
- Done when: a test Vault lease carries proposal id and approver and is revoked within 10 s of APPLIED; engaging the kill switch mid-apply revokes it and the transport fails closed; both audits share the lease id.

**ZT-16 Separate scan, apply and interactive credential references.** Pillars: User, Data. Step: 30 days. Effort: 2-3 days. Depends: ZT-19.
- Today: Implemented account/target/action credential selection separates scan, discovery, plan, apply, verify and rollback bindings. Each operation rechecks the selected binding and policy; missing bindings fail closed. Short-lived brokers, interactive access and proof of least privilege on actual target systems remain open.
- Target: `credentials: {scan, apply, interactive}`; apply refs may be per-principal templates; `make_transport` (`transport/base.py:80`) takes `purpose` and `principal`. A single ref still works in dev mode; fleet mode warns.
- Done when: a scan never resolves the apply ref; an apply resolves it with the approver's principal; the scan account cannot write on a range host.

### 1.4 Workload identity for automation

**ZT-17 The node's own workload identity.** Pillars: Application, Automation. Step: 60 days. Effort: 3-5 days. Depends: ZT-01 or an enclave CA.
- Today: Verified workload principals cannot take human decision edges. User-started jobs preserve the initiating principal and expire/revoke with it; verified-mode schedules are disabled until a real node workload identity exists. SPIFFE/node certificates and signed bundles remain open.
- Target: `Principal(kind=workload)` with a SPIFFE id from the mesh certificate, or a node certificate (TPM or OS store where available). Scheduled scans, ingest, outbox sync and post-apply verify run as it; it never holds approver roles; outbox bundles are signed with it.
- Done when: a scheduled scan's record shows the workload id; the workload identity gets 403 on approve; a bundle signed by another node is rejected on import.

**ZT-18 Least-privilege scanning; apply privilege only inside an approved window; payload digest binding.** Pillars: Automation, User. Step: 30 days (digest), 60 days (leases). Effort: 4-5 days. Depends: ZT-16; ZT-13 or ZT-15 for leases.
- Today: Approved fix digests and target/configuration guards already bind execution to reviewed content, with fresh account/action authorization. Just-in-time privilege leases, maintenance-window enforcement and final rendered-payload binding remain open.
- Target: the existing digest grows to cover (fix_ref, rendered payload, target); `RemediationEngine.execute` refuses on mismatch. Apply lease scoped to target and fix timeout. Record `approved_by`, `executed_by`, `lease_id`, `payload_digest`. The digest alone works on a laptop range today and answers "what exactly did the Sailor approve?"
- Done when: approve, edit the library payload on disk, apply: refused with "payload changed since approval" and state unchanged; the apply record has all four fields.

### 1.5 Credential backend

**ZT-19 Pluggable credential resolver replacing `CT_CRED_<ref>`.** Pillars: Data, Application. Step: 30 days (env, keyring, k8s), 90 days (Vault, CyberArk). Effort: 1 week, plus 3-5 days per broker. Depends: none for the interface.
- Today: Implemented a protected source registry, bounded account/target/action password leases, private mounted files, explicitly selected Kubernetes projections and native Windows Credential Manager lookup for SSH/WinRM ([CREDENTIAL_RESOLVERS](CREDENTIAL_RESOLVERS.md)). Fleet password references refuse environment fallback; registry changes invalidate existing use and audit events identify the actual backend without secret values. Native Windows/Linux fixtures pass, but service-logon provisioning, actual kubelet mounts and real target authentication remain acceptance work. Linux Secret Service, Vault and CyberArk remain open.
- Target: `transport/credentials.py`: `resolve(ref, *, purpose, principal, target) -> Lease`; `Secret` redacts in `repr`/`str` and refuses JSON. Schemes `env:` (dev only), `keyring:` (Credential Manager/DPAPI, Secret Service), `k8s:` (mounted Secret), `vault:`, `cyberark:`; fleet mode forbids `env:`. Every use writes `credential.resolve` (ref, backend, purpose, target, lease id, never the value) and `credential.failed` on logon failure.
- Done when: a scan succeeds with no `CT_CRED_*` set using keyring; fleet mode refuses `env:` at inventory load; a legacy `credential_ref=lab_root` still works in dev mode; no lease or secret prints its value.

**ZT-20 No secrets on command lines, in temp files or picked up implicitly.** Pillars: Data, Device. Step: 30 days. Effort: 2 days. Depends: ZT-19.
- Today: Verified SSH disables ambient key/agent fallback and bound Kubernetes subprocesses use a minimal environment. Local tool and dependency subprocesses now exclude server credentials and startup hooks, with a real-child regression. Other subprocess/provider paths and temporary credential handling still need platform-specific coverage ([SECRET_BOUNDARIES](SECRET_BOUNDARIES.md)).
- Target: kubectl gets a 0600 kubeconfig in a private temp directory removed after the call, never `--token`; SSH `look_for_keys=False`, `allow_agent=False` outside interactive mode; child processes get an env allowlist with no `CT_CRED_*`.
- Done when: a patched `subprocess.Popen` sees no canary in argv or child env; the temp file is gone after an exception; a key in a fake `HOME/.ssh` is not offered.

**ZT-21 Rotation without restarts.** Pillars: Data, Automation. Step: 90 days. Effort: 2-3 days. Depends: ZT-19.
- Today: Resolver-backed passwords are read at each new authentication lease. WinRM creates a new session per operation; SSH reads the rotated value on its next connection, while a cached authenticated connection continues to use current authorization guards. Protected registry mapping changes invalidate old uses. Static-credential age findings and broker-side revocation remain open.
- Target: resolve per operation; `k8s:` re-reads the mounted file; static scan accounts get a rotation interval and the tool raises its own finding when one is older.
- Done when: changing the mounted Secret between two scans takes effect with no restart; an overdue static credential produces a finding.

**ZT-22 Canary tests: a secret never reaches disk, inventory, audit, logs, the model or the outbox.** Pillars: Data, Visibility. Step: 30 days. Effort: 2-3 days. Depends: ZT-19 (can start with env).
- Today: Implemented a calibrated lifecycle canary through account-bound SSH discovery, scanning, explanation, approval, failed verification, rollback, reports, outbox and audit SSE on JSON and SQLite. It found and now guards against local discovery subprocess credential inheritance. WinRM/Kubernetes paths, real remote authentication and broader failure branches remain open ([SECRET_BOUNDARIES](SECRET_BOUNDARIES.md)).
- Target: `tests/security/test_secret_canary.py` runs discover, scan, explain (capturing the model prompt), propose, approve, apply, forced verify failure, rollback, report, outbox and SSE with a canary secret, then searches the state directory, DEBUG logs, exceptions, prompt and responses for it in plain, base64 and percent-encoded form.
- Done when: a deliberately planted leak makes the test fail.

### 1.6 Audit and non-repudiation

**ZT-23 Audit records carry the verified subject, assurance and session.** Pillars: Visibility, User. Step: 30 days. Effort: 2 days, plus hours for reports. Depends: ZT-02.
- Today: Version 2 audit events hash-cover principal issuer/subject, roles and available assurance claims; new session correlation uses a scoped fingerprint rather than a raw issuer session identifier. Commander HTML/Markdown/JSON, POA&M and CKLB exports preserve every independent approval, its recorded principal, audit association and quorum evidence ([APPROVAL_REPORT_EVIDENCE](APPROVAL_REPORT_EVIDENCE.md)). Report validation does not grant current apply permission. Legacy records remain explicitly unverified; live realm assurance acceptance and external signed anchors remain separate, with no hardware non-repudiation claim.
- Target: `principal` field `{kind, iss, sub, name, roles, acr, amr, auth_time, session_id, device, via}` with `via` one of dev, oidc, mesh, peer, cached, break-glass; record version `v: 2`; old records stay valid. Reports print subject and audit seq for each approval.
- Done when: an oidc approve records the token's sub and acr; hand-editing `principal.name` fails `audit verify`; a mixed v1/v2 log verifies; a report lists subject and seq per approval.

**ZT-24 Signed checkpoints and off-node anchors.** Pillars: Visibility, Data. Step: 90 days; PIV approval signing at 180 days. Effort: 4-5 days, plus 1 week for PIV. Depends: ZT-17, ZT-23.
- Today: Implemented an explicit protected operator utility for Ed25519 checkpoint export/verification, full-chain comparison and monotonic local anchor import ([AUDIT_ANCHORS](AUDIT_ANCHORS.md), [native review](AUDIT_ANCHORS_REVIEW.md)). Ordinary `.head` files remain unsigned. Automatic app-event signing, outbox integration, acknowledged independent off-node retention and hardware key custody remain open; local imports explicitly do not claim delivery or resistance to privileged whole-store rollback.
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
- Today: Non-loopback development binds are refused. Verified network binds require TLS cert/key or mesh mode, and authenticated API responses are no-store. Full HSTS/CSP/host allow-list policy and live protocol/ingress validation remain open.
- Target: `CT_TLS_CERT`/`CT_TLS_KEY` from the enclave CA; non-loopback bind without TLS refused unless `CT_ALLOW_PLAINTEXT` in dev mode; HSTS, `frame-ancestors none`, `no-store` on API responses; a strict host allow-list; still no CORS. Under UDS, TLS terminates at the gateway.
- Done when: `serve --host 0.0.0.0` with no certificate exits with an error; TLS 1.0/1.1 fail; HSTS is present.

**ZT-28 Mutual TLS and explicit traffic rules inside UDS.** Pillars: Network, Application. Step: 60 days. Effort: 3-4 days. Depends: ZT-01.
- Today: A UDS package and gateway configuration exist; app verification does not establish mesh isolation by itself. Actual strict mTLS, workload allow-lists and inventory-bound egress acceptance remain open.
- Target: STRICT mTLS; only the app's ServiceAccount may call the model server and only the gateway may call the app; egress generated from the inventory's targets and ports so scope and network policy cannot drift; the model server has no egress.
- Done when: calls from another namespace fail; egress outside inventory CIDRs is blocked; the generated allow list matches the inventory in a unit test.

**ZT-29 WinRM over HTTPS only, with certificate validation.** Pillars: Network, Device. Step: 30 days. Effort: 1 day. Depends: none.
- Today: Implemented fleet rejection of HTTP, ignored certificates, Basic and CredSSP, with explicit CA trust. Insecure range choices require acknowledgement and produce trust findings. Real Windows HTTPS/AD acceptance remains open.
- Target: fleet mode refuses HTTP, `ignore`, Basic and CredSSP and requires a CA bundle; default auth Kerberos; range mode keeps today's behaviour and raises a warning finding against the target.
- Done when: a 5985 target in fleet mode is refused before connecting; an untrusted target certificate fails; in range mode the same target connects and the warning finding appears.

**ZT-30 SSH host key pinning from the inventory.** Pillars: Network, Device. Step: 30 days. Effort: 2-3 days. Depends: none.
- Today: Implemented fleet SSH pin/known-host verification before authentication, changed/untrusted identity refusal, and audited trust findings. Discovery-driven pin enrollment, host CA lifecycle and real Cisco acceptance remain open.
- Target: per-target sha256 fingerprints or an SSH host CA; discovery records the observed key and acceptance pins it; `RejectPolicy`; a mismatch aborts before authentication, raises a high-severity `discovery:identity_changed` finding and an audit record. This doubles as an intrusion indicator for the hunt.
- Done when: a changed key fails before any credential is sent, with a finding and an audit record; a target with no pin is refused in fleet mode.

**ZT-31 Node hardening and state-directory protection.** Pillars: Device, Data. Step: 60 days. Effort: days. Depends: none.
- Today: Protected policy, static Kubernetes credentials, SSH private keys and JWKS files enforce POSIX ownership/mode checks or native Windows SID/DACL checks with pinned handles; unsafe or unavailable protection fails closed. Local Windows fixtures and native Linux regressions have dated evidence. A read-only `node-hardening` command now observes bounded state-tree permission metadata without initializing the application or reading file contents ([NODE_HARDENING](NODE_HARDENING.md)); its independent review covers native DACLs, descriptor traversal, races and incomplete observations. Whole-state enforcement, startup integration, actual service/domain/SMB/ReFS deployment, encryption, node STIG evidence and an actual ISSO review remain open.
- Target: a hardening guide (service account, directory ACLs, disk encryption, STIG the node itself); startup warns on permissive ACLs; node key (ZT-17) in a TPM where available.
- Done when: startup warns when the state directory is readable by other users; the guide exists in `docs/` and names its ISSO reviewer and review date.

## 2. What stands between the prototype and a limited deployment

Verified identity is necessary and not sufficient. Five things stand between this prototype and a limited deployment; any one of them is enough to stop it.

| Blocker | Why it matters | Items |
|---|---|---|
| Identity and credentials | Verified application identity and account-scoped access exist; live realm/target acceptance, step-up, brokers and the remaining controls are still required | ZT-01 to ZT-31 (section 1) |
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
- Today: versioned deterministic High/Medium/Low/Unknown assessments, reasons and provenance are implemented in `findings/confidence.py` and exposed by the API, Findings/detail view and reports. Legacy missing metadata stays explicit; simulations, stale and version-only evidence cannot become High. See `docs/CONFIDENCE.md`. Measured real-platform calibration, richer per-check collector provenance and automatic cross-scanner corroboration remain open; grades are not probabilities.
- Target: display High, Medium, Low or Unknown beside severity, with a plain-language reason and the evidence used. Record collection method and authentication/privilege sufficiency, scanner and benchmark/profile versions, package or image identity, observation time and freshness, applicability and corroboration/conflicts when available. Use versioned deterministic grading rules; missing privileges, stale content, version-only matches or contradictory results must remain visible. Unknown/unsupported/collection-error results never become a pass. Explain that grades are evidence-strength categories, not calibrated probabilities; do not show percentages until VAL-02 supplies a measured calibration. The explanation model cannot invent or upgrade a grade.
- Done when: fixtures for direct checks, incomplete collection, stale data, ambiguous matches and conflicting scanners produce documented grades/reasons consistently; API, Findings, detail view and reports expose the same evidence/provenance. A high-severity finding can have low confidence. Detection confidence remains distinct from fix safety/readiness (COV-02 to COV-04), and no confidence grade bypasses approval or authorizes target changes.

**VAL-05 Audited finding review and scoped false-positive decisions.** Step: before range. Effort: days. Depends: VAL-04, ZT-08 for authorized reviewers and ZT-23 for verified identity evidence.
- Today: general reasoned review, expiry, evidence scoping, reversal and append-only history are implemented separately from scanner results, persisted through JSON/SQLite and exposed in the API, UI and reports (`docs/FINDING_REVIEW.md`). Active suppression blocks remediation; Low/Unknown confidence and Needs investigation withhold standing-policy approval. Verified reviewer identity, role and original-target authorization are enforced; live realm acceptance remains ZT-08/ZT-23 work. Risk acceptance is not implemented. Kubernetes known-good exceptions remain a separate legacy mechanism that changes matching scanner output and should eventually use the common review model. VAL-02 still covers real-platform validation.
- Target: add Unreviewed, Confirmed, False positive, Not applicable and Needs investigation as review dispositions separate from immutable scanner observations. Every change records reviewer identity/attribution, reason, supporting evidence, time and history; risk acceptance is a separate authorized, time-limited decision, not a false positive. Scope a decision to the asset, rule/detector and benchmark/version plus evidence fingerprint; require review/expiry dates where suppression is allowed. New or changed relevant evidence, detector/content changes or expiry reopen review instead of silently carrying a dismissal forward. Explain when identity is only self-asserted until the ZT work lands.
- Done when: UI/API can record, inspect and reverse a review with a complete audit trail; JSON and SQLite preserve it across restart/rescan, concurrent review cannot silently lose a decision, and historical scanner output is unchanged. Reports show raw, confirmed, unreviewed and suppressed counts with reasons/expiry; filters never conceal those totals. False-positive/not-applicable/risk-accepted records cannot trigger unattended remediation. Uncertain or conflicting observations require investigation before an automatic policy can act; confirming a finding still does not approve its fix. Tests cover unauthorized review, changed evidence, expiry, revocation and rescan reopening.

### 2.2 Coverage and fix safety

**COV-02 Fix safety for lockout-prone changes.** Pillars: Automation, Network. Step: before fleet. Effort: 1-2 weeks. Depends: VAL-01, REM-02.
- Implemented support: [change-impact assessment](CHANGE_IMPACT.md) collects bounded Linux/Windows service and Kubernetes workload dependency facts, explains them with the configured model, preserves deterministic risks/unknowns and binds the reviewed receipt to the pending change. It identifies possible access loss but does not establish a second connection or install an independent revert mechanism. Live-platform validation and complete dependency coverage remain open.
- Today: `RemediationEngine.execute` (`remediation/engine.py:362-453`) opens one transport, captures before-state, applies and verifies over that same connection; verify includes a health result, and a failure or exception rolls back over the same transport. There is no pre-flight reachability check, no second session, no revert if the control connection itself drops, and no canary option: an approved sshd, firewall, WinRM or management-interface change that cuts the session leaves the rollback with no way in.
- Target: fixes tagged lockout-prone (sshd, PAM, firewall, WinRM listener, Cisco management plane and AAA) get a pre-flight that a second session can be opened; that second session stays open through apply and verify; the change is armed on the host with a timed revert (`at`/systemd timer, scheduled task, Cisco `configure replace` with a rollback timer) cancelled only after verify succeeds from a fresh connection; a policy option applies a fix to one canary host and waits for a human before the rest.
- Done when: on the range, a deliberately bad sshd fix that blocks logins is reverted by the host within the timer and the proposal ends ROLLED_BACK with the cause; a Cisco ACL fix that drops the session is reverted the same way; with canary on, the second host is not touched until a second approval.

**COV-03 Dry run and maintenance windows.** Step: before range. Effort: days. Depends: none.
- Implemented support: explicit read-only dependency collection and time-bound assessment receipts supplement the static preview. The UI surfaces evidence, model/fallback provenance, risk, unknowns and required checks; direct legacy and standing-policy approvals remain explicitly unassessed when no receipt is attached. Assessment is advisory and never grants execution authority. Maintenance-window enforcement remains open.
- Today: `apply <proposal> --plan` and **Preview change** now provide an audited static preview of the bound fix, target identity, declared capture/verification metadata, service/reboot impact and rollback ([REMEDIATION_PLAN](REMEDIATION_PLAN.md)). They never connect to the target or mutate a proposal. This is not a host-validated dry run, and declared capture paths are not a complete touched-file list. Per-host rendering/read-only preflight and maintenance-window enforcement remain open. Windows exist only on standing-policy auto-approval rules; `execute` still applies whenever an approved proposal passes its existing guards.
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
- Today: [CONTROLS](CONTROLS.md) maps application contributions to NIST SP 800-53 families, separates deployment responsibilities and evidence, and records unassigned review/authorization roles. Exact control selection, organization-defined parameters, actual deployment acceptance and ISSO review remain open; the mapping makes no compliance or authorization claim.
- Target: `docs/CONTROLS.md` mapping the tool's guardrails to 800-53 families, at least AC (approval gate, roles), AU (hash-chained audit; external anchors remain open), CM (vetted fix library, before-state, rollback), IA (section 1) and SI (scans, hunt, bulletin matching), saying for each family/assessment concern what the tool provides, what the enclave must provide and what evidence to pull (audit export, proposal records, reports). Exact control IDs and assessment objectives belong to the system's tailored assessment; this document remains a family-level contribution map for the authorizing official.
- Done when: an ISSO has read it, with the actual reviewer, review date and source/deployed revision recorded or linked; their questions and dispositions are retained in the file or assessment record, and every implementation claim points at a code path or a report the tool produces. Source review alone does not close this item or establish deployment acceptance.

**ATO-04 Maintaining organization and release process.** Step: before fleet (the 180-day decision). Effort: days to set up, then ongoing. Depends: ATO-02.
- Today: the technical owner is a person (`docs/SUBMISSION.md:19`) while `docs/fleet.yaml:7-8` names NAVIFOR / Naval Network Warfare Command as mission owner and NIWC Atlantic as technical owner; the mission owner is still to be confirmed (`docs/SUBMISSION.md:18`). There are no signed releases, no vulnerability disclosure path and no update cadence.
- Target: a named maintaining organization with a point of contact; signed releases with the content, fix library and SBOM versions stated; a published disclosure path; a release within a set number of weeks after each DISA quarterly release (`docs/CONTENT.md:21`), plus out-of-band releases for critical fixes.
- Done when: the owner is recorded in `docs/fleet.yaml` and SUBMISSION agrees with it; a release signature verifies on an offline node; the disclosure path is in the README.

## 3. Other areas

### Scanning and benchmarks

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| SCAN-01 | Implemented guarded k3d server collection and sorted k3s drop-ins with CLI precedence and explicit missing-data states ([SCANNER_COVERAGE](SCANNER_COVERAGE.md)). Direct Docker collection is development-only; verified mode requires authorized node credentials | Validate against the running range cluster and retain per-server evidence | A dated k3d scan gives measured pass/fail for collected rules, preserving unavailable outcomes | range validation | before range |
| SCAN-02 | Six W11 V2R11 rules unsupported plus many OVAL test types, reported `not_reviewed` (`docs/SCAP.md:121-124`) | `fileeffectiverights53` and `ntuser` first, then group/user/process/port as other benchmarks need them | `scap info` shows 0 unsupported for W11 V2R11 on a real host | week+ | before fleet |
| SCAN-03 | Windows collection only run against the simulated host; WinRM exercised through recordings only (`README.md:36-38`) | Run the collector elevated on a real Windows 11 VM over WinRM and diff with the simulator | A recorded real-host collection replays with the same results | days | before range |
| SCAN-04 | Implemented explicit range-only CPE alias with benchmark validation, preserved source bytes, provenance and persistent warnings ([SCANNER_COVERAGE](SCANNER_COVERAGE.md)); fleet mode refuses the override | Execute the DISA RHEL 9 benchmark on the isolated Rocky 9 host and retain the actual engine result | Evaluated rules and the recorded override appear in a dated scan; no unsupported platform certification is implied | range validation | before range |
| SCAN-05 | A larger offline model and an optional stronger workstation endpoint remain unvalidated on the available hardware; configurable local/compatible endpoints already exist | Validate the operator-supplied workstation or enclave model, approved network path, resource use, timeouts and offline fallback; retain citation and assessment validation | A dated run records hardware, model/configuration, latency, fallback and bounded valid output without changing targets | days | later |
| SCAN-06 | Implemented in PR #28: audited Nessus results import through the CLI and API, with explicit host-to-inventory mapping, source provenance and deterministic duplicate handling ([SCANNER_IMPORT](SCANNER_IMPORT.md)); imported findings appear in the current view and reports | Preserve parser limits, duplicate handling and historical/current view semantics | JSON and SQLite regressions cover CVE findings, reports, duplicate imports, invalid mappings and refusal to authorize target changes | complete | 2026-11-05 |

### Remediation

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| REM-01 | Container recreation remains manual. Kubernetes heuristic findings now select owner-review guidance; retired deletion fixes are blocked while saved historical restoration remains available ([KUBERNETES_FIX_SAFETY](KUBERNETES_FIX_SAFETY.md)) | Add reviewed service-preserving RBAC/exposure changes, staged workload migration and container recreation with application/data checks and recovery; review guidance alone cannot close an investigation | Range evidence shows approve/apply/verify/restore without losing unrelated subjects, workloads or data; absence of an object is not accepted as application-health proof | week+ | before fleet |
| REM-02 | Cisco push is off by default (`range/cisco/README.md:50`) and push plus archive rollback are covered by recordings only | Test on one lab switch or emulator image; roll back by `configure replace` | A pushed fix verifies and a forced failure restores the saved config | days | before range |
| REM-03 | [CHANGE_HISTORY](CHANGE_HISTORY.md) supplies historical rollback links, current finding lifecycle, later-change guards and supported Linux file drift checks. Other platforms, external writers and application/data recovery remain limited | Extend live drift comparison and restore verification per platform; combine snapshot retention (SCL-04), independent recovery (COV-02) and cluster/data backup (MVP-09) | A retained week-old change can be assessed and safely refused or restored on each tested platform; changed resources/data and uncertain outcomes never appear as confirmed success | week+ | before fleet |

### Content and link

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| CON-01 | Implemented protected Ed25519 operator attestations, signed request/lock validation, direct-import enforcement, exact signed browser downloads and audited verified-human exceptions in Import / transfer. The library labels stored provenance; authorized cyber.mil pulls retain HTTPS provenance without claiming a publisher signature ([CONTENT_AUTHENTICITY](CONTENT_AUTHENTICITY.md)) | Validate operational key custody/distribution/revocation; add release anti-rollback and interrupted-publication recovery. Signing-key provisioning remains a host administration task | Known-invalid signatures, wrong scope and changed bytes cannot be overridden; unsigned content requires authorized human justification; operational key and recovery evidence is recorded | remaining operational acceptance and recovery | before fleet |
| CON-02 | Implemented deployment-ID recovery, explicit index-unavailable state, preserved successful state and snapshot fallback. A bounded connected canary on 2026-11-06 UTC accounted for all 417 live publications ([CATALOG_ACCOUNTING](CATALOG_ACCOUNTING.md)) | Preserve guarded fallback and rerun compatibility checks when the public deployment changes | Fixture failures preserve the saved catalog; recorded live metadata reconciliation covers every returned entry | complete | 2026-11-06 UTC |
| CON-03 | Real event/enclave link characteristics remain unconfirmed. Production no longer assumes 56 kbps or 500 ms; those values belong to explicit test mode | Obtain the organizers' measured link constraints and record the demonstration configuration separately from operational observations | The open question has a sourced answer; no configured demonstration number is presented as measured bandwidth | hours | now |
| CON-04 | Implemented support: default unknown reachability/rate, observed request bytes and times, explicit audited test mode and operator-offline control, plus bounded opt-in probes. These are application observations, not physical bandwidth; local outbox moves are not shore delivery | Validate operational endpoints and cancellation in the range; design persistent opt-in monitoring and an actual authenticated remote outbox receiver | A real transfer and disconnect/recovery have dated evidence; delivery is acknowledged by the destination. Temporary 15-minute monitoring and local copies do not satisfy continuous monitoring or remote delivery | days | before range |
| CON-05 | Implemented full catalog accounting, searchable publication metadata, explicit supported/unsupported/sunset classification and malformed/duplicate-row retention ([CATALOG_ACCOUNTING](CATALOG_ACCOUNTING.md)) | Preserve reconciliation and safe selection/download behavior as publication formats change | Snapshot regressions account for every raw entry without claiming scanner support for unsupported content | complete | 2026-11-05 |

### Discovery

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| DIS-01 | Implemented bounded, read-only vSphere collection with explicit account bindings, original target/collector-owned history, sanitized failures and a searchable paged Assets view ([account access](VSPHERE_ACCOUNT_ACCESS.md), [UI](VSPHERE_UI.md)). JSON/SQLite source fixtures and native browser fixtures pass | Validate a provisioned read-only account against actual vCenter/ESXi; review permanent history revocation when remote-account mappings are retired | Dated live collection confirms host/VM evidence and unequal account visibility; failed/partial collection never establishes an empty inventory or guest reachability | remaining live acceptance and revocation policy | before fleet |

Device identity at acceptance is ZT-30.

### Deployment and platform

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| DEP-01 | Linux, fresh-cluster and existing-cluster paths marked untested (`docs/DEPLOYMENT.md:26`); only the WSL2 path has a recorded run | Run and record each, rewrite the status line | Each path has a dated result | days | before fleet |
| DEP-02 | WSL keep-alive is manual (`docs/DEPLOYMENT.md:215-224`) | `scripts/wsl-keepalive.ps1` sets `.wslconfig` and a logon task; bootstrap prints status | After logout and login the cluster is up with no manual step | hours | now |
| DEP-03 | Implemented: Podinfo's package image and chart values use the same verified multi-platform digest ([package evidence](../packages/podinfo/README.md)); actual chart rendering and package lint passed | Rebuild existing packages before deployment; review later image/chart updates separately | The rendered Deployment and package image list match the downloaded registry manifest digest | complete | 2026-11-06 UTC |
| DEP-04 | DADMS entries for the app and each dependency, and no approved offline model runtime (friction F1, F2) | Open registration and evaluation requests; keep the template path as the fielded default | A sponsor and ticket numbers appear in `docs/fleet.yaml` | week+ | before fleet |

Packaging the app itself is ZT-01.

### UI

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| UI-01 | Implemented: verified account/role display, disabled role actions with reasons, and saved reviewer/approver provenance. Legacy decisions remain labeled unverified. Account-scoped target credentials are recorded in audit | Finish live realm/target acceptance and show execution credential provenance beside the decision where useful | Actual limited-user login, approval and target account evidence agree; UI never upgrades old records using the current session | partial | before range |
| UI-02 | Implemented: filters by category, machine, type, severity, scanner result, source and benchmark/release; search, stable sorting and saved preferences. Finding rows now open by click or keyboard, with nested controls independent ([FINDINGS](FINDINGS.md)) | Preserve full-view counts and filtering before pagination; indexed queries at scale remain SCL-03 | API and UI regressions cover combinations, historical/current views, reset/persistence and row interaction | complete | 2026-11-05 |
| UI-03 | Implemented: editable include/exclude recipes persist across reload, with per-range policies, revision conflicts, preview fingerprints and explicit broadening acknowledgement | Preserve recipe round trips and authorization when adding discovery sources | Tests cover saved expressions, heterogeneous policies, stale previews and explicit updates | complete | 2026-11-05 |

The rest of the identity UI is in ZT-04 and ZT-08.

### Testing and range

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| TST-01 | Hosted Windows/Linux JSON and SQLite regression jobs have passed, including PR #34; UI builds, normal gate and exact skip policy are in `.github/workflows/regression.yml` ([CI](CI.md)). Windows deployment-module omissions and Linux UDS-dependent skips remain documented | Add reviewed UDS tooling and remove the remaining deployment coverage gaps; retain exact-head hosted evidence | Both hosted jobs pass without unexpected omissions; UDS-dependent deployment checks execute on Linux | days | before fleet |
| TST-02 | Repeatable real-browser rehearsal now covers reviewed approval, kill refusal, apply/verify, manual rollback and forced-verification-failure recovery on both JSON and SQLite ([BROWSER_REHEARSAL](BROWSER_REHEARSAL.md)). It uses template explanations and explicitly unverified loopback identity; a prior real local-model receipt is separate evidence | Run the rehearsal and selected live-model smoke against each release candidate; add live verified-login acceptance with the intended realm | Release receipts name the tested commit and preserve proposal/finding transitions, failure recovery and valid audit chain; simulator, model and realm evidence remain distinct | remaining live-model and realm acceptance | before fleet |
| RNG-01 | Linux over SSH has met a real host (the Rocky 9 range VM: 28 of 28 seeded items, one fix applied and rolled back, `range/README.md` "First real-host run") and the k3d cluster was scanned over kubectl; WinRM and Cisco over SSH have never run against a real system | The Windows VM from `range/windows/README.md` over real WinRM, and a Cisco device or emulator over SSH | Scores against `range/answer_key/` from a live scan appear on the Reports page | days | before range |
| RNG-02 | Event unknowns open: range access, link speed, Evaluate-STIG/SCC, datasets, Ark, Google link (`docs/CONTEXT.md:171-179`) | Ask in `#tech-support` and the portal | Each item is checked or has a recorded answer | hours | now |
| RNG-03 | No IT Sailor recruited as approver and no remediation-time baseline (`docs/CONTEXT.md:176`) | Run the approval flow with one IT Sailor; record today's manual hours per release and network | A sourced hours figure appears in `docs/SUBMISSION.md` | hours | now |

Identity negative tests are part of ZT-02, ZT-03 and ZT-08.

### Docs

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| DOC-05 | [SCAN_CONTENT](SCAN_CONTENT.md) now exposes missing/unconfigured/stale content, distinguishes manual guides from executable SCAP, and preserves unassessed historical findings. Downloaded Linux content is not automatically staged on the host; Windows content still needs an explicit local datastream path | Add an explicit reviewed content-store-to-adapter configuration/staging workflow with release/applicability validation, plus end-to-end tests; any optional scan-triggered download must be opt-in, audited and DDIL-aware | Imported or selected content is actually used by each intended adapter; missing/unsupported content remains visible and no implicit download or clean result is invented | days | before range |

### Cluster MVP path (team plan of 5 Nov)

The team's MVP plan (Cyber Thunder running inside the UDS cluster, fixing `nginx-bad`) mapped to what exists. Done already: file-based state, the UI, the configurable model backend, approval, apply with verify and automatic rollback, the Cisco simulation, the Linux VM run from the node. Pointer rows name the item that carries the work.

| ID | Gap and today | Target | Done when | Effort | Step |
|---|---|---|---|---|---|
| MVP-01 | Application packaging and UDS gateway SSO shipped in PRs #18/#19 (`packages/cyberthunder`); end-to-end validation of the intended cluster scan/fix flow remains open | Validate the existing package and PVC with the intended model service and target access; verified application principals remain in ZT-02/03 | `uds zarf dev lint` passes and the UI loads inside the cluster behind the tenant gateway | 1-2 weeks | before range |
| MVP-02 | Keycloak sign-in (item 1.3) | Covered by ZT-01 to ZT-03 | see those items | - | 30-60 days |
| MVP-03 | Managed public Trivy database updates, freshness/provenance, opt-in schedules and offline bundles are implemented, with cluster image CVEs in normal findings and scoped reconciliation ([VULNERABILITY_DATA](VULNERABILITY_DATA.md)). The container pins a patched scanner; source changes do not rebuild previously published packages. Target images are not in a database bundle | Validate the rebuilt package against nginx-bad with egress blocked and provision the actual image content; retain MVP-11 guards. Remote Linux/container-host adapters still need their own target-side databases | A recorded disconnected cluster run identifies image CVEs in Findings/reports; missing database/image content remains unavailable, never clean; immutable generations and offline transfer pass regression and real-engine checks | days for remaining real cluster validation | before range |
| MVP-04 | PR #20 supplies `scripts/scan-container-os.sh`; a bounded [SCAP result importer](SCAP_RESULTS.md) now persists its XCCDF observations through the API or development CLI, with explicit target/container provenance, account ownership, repeat protection and visible incomplete coverage. Fixture evidence covers JSON and SQLite; live nginx-bad evaluation and platform applicability remain unverified | Validate the actual image/profile and retain the engine output, explicit mapping and imported findings | A recorded nginx-bad image evaluation lands in the findings workflow with unsupported/not-applicable outcomes preserved and an applicability decision | range validation | before fleet |
| MVP-05 | Implemented: optional `CT_LLM_API_KEY` authentication is read for each compatible-backend request, including probes and format fallback; credentialed redirects are refused and diagnostics omit secrets ([MODEL_AUTH](MODEL_AUTH.md)). A separate agent harness remains a team decision | Keep regression coverage for authenticated and unauthenticated local endpoints | Mocked tests cover rotation, auth failure, redirect refusal and decoded secret reflection; no live endpoint was required | complete | 2026-11-05 |
| MVP-06 | CVE remediation by newer image (items 4.1 and 6.2): nothing pulls container images or bumps image tags; the resumable, allow-listed downloader exists for STIG content only (`cyberthunder/ingest/content/fetch.py`) | a newer-image check against the pinned tag or digest; a durable registry pull over the slow link reusing the downloader's resume and caps (Zarf air-gap packages as the carrier in UDS); a fix entry that bumps the deployment image with before-state and rollback | nginx-bad's image is updated through approve, apply, verify and rollback, with the pull surviving a dropped link | 1 week | before range |
| MVP-07 | GitOps-style Kubernetes remediation (item 4.2.1): fixes patch live objects with before-state (`cyberthunder/adapters/kubernetes/fixes.py`), so a chart or ArgoCD sync would undo them | emit the fix as a chart or manifest change to the package repository when a GitOps controller owns the workload, with the live patch as the immediate action | a fix survives an ArgoCD sync | 1 week | before fleet |
| MVP-08 | STIG-hardened RHEL 9 image pipeline (item 4.2.2): nothing rebuilds a hardened container image pinned by the chart or Zarf package | a build that applies the RHEL 9 STIG content to the UBI base, scans it, and pins the result by digest in the package | the rebuilt nginx-bad image scans clean and the package pins its digest | 1-2 weeks | later |
| MVP-09 | Velero as cluster-wide rollback (item 7): every fix restores its own before-state; there is no cluster-level snapshot | an optional Velero backup before a batch apply and a restore path in the engine for cluster targets | a batch of Kubernetes fixes is reverted by a Velero restore recorded in the audit log | days | later |
| MVP-10 | Guided deployment-host registration and explicit guarded connection tests are implemented ([HOST_SCOPE](HOST_SCOPE.md)). Container-local collection is not host collection; physical host address/OS are operator declarations. No live pod-to-host scan/apply/rollback is claimed | Repeat the Rocky range flow from the deployed pod using authorized SSH/WinRM, intended egress and credentials; keep native operation available | A dated pod-to-host scan, approved fix, verification and restore succeed with recorded target identity and package version | days | after MVP-01 |
| MVP-11 | Implemented: active cluster survey and baseline scans require a named actor and an explicitly scoped inventory target; kill, scope and pinned configuration are rechecked around external calls and publication. Opt-in bootstrap registers new targets out of scope and preserves operator edits ([CLUSTER_GUARDRAILS](CLUSTER_GUARDRAILS.md)) | Preserve these guards on new cluster entry points; verified identity remains in ZT-02/03 | Regressions cover killed, missing, revoked or changed target configuration, interrupted baselines and bootstrap preservation; a running subprocess stops at its next boundary or timeout | complete | 2026-11-05 |

## 4. Already enforced today (for contrast)

From [ARCHITECTURE](ARCHITECTURE.md) section 4. Cluster survey, baseline and bootstrap guards are also implemented as described in [CLUSTER_GUARDRAILS](CLUSTER_GUARDRAILS.md); development actor names remain unverified; configured OIDC/mesh principals are verified:

- No change without approval: the engine refuses `execute` unless the proposal is `APPROVED`, and machine identities can never take a human edge (`ApprovalGate.HUMAN_ONLY`).
- Only vetted fixes run: `RemediationEngine.execute` runs `FixEntry.payload` only; no code path passes model output to a transport.
- Fixes declare rollback capabilities and capture before-state; failed verification attempts recovery. Persistent change history, same-target change guards and supported Linux file drift checks are implemented ([CHANGE_HISTORY](CHANGE_HISTORY.md)); unsupported platforms, external races and control-connection loss still limit recovery.
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

## 6. Requested capabilities at the testing checkpoint

This section records the earlier testing checkpoint. Development has resumed; remaining work stays in the existing items below. Implementation or fixture tests do not establish production readiness.

| Request | Implemented boundary | Remaining work |
|---|---|---|
| Native or container deployment, including scanning the deployment host | Native execution and the UDS package remain supported; guided host registration distinguishes container-local from remote host collection | MVP-01, MVP-10, VAL-01, ZT-12/13/19/29/30 |
| Intuitive addresses and scan scope | Bounded IP/CIDR/range/exclusion preview, explicit normalization acknowledgment, separate search and target authorization | UI-03, ZT-10, live IPv6/range validation in VAL-01 |
| Find Windows, Linux, network devices, clusters and VMs across environments | Adapter/transport extension points and existing discovery sources | VAL-01/02/03, SCAN-01/02/03/04, DIS-01, REM-02, RNG-01 |
| Scan STIGs directly and explain missing content | Native checks, configured SCAP evaluation, local preflight and per-run coverage; incomplete scans preserve older unassessed observations | DOC-05, VAL-03, SCAN-02/04; complete coverage is not claimed |
| One place to upload, browse, maintain and update STIGs | Downloaded, Maintained, Updates, Browse all and Import/transfer views; versions, selected types and actual available sync/import timestamps | CON-01/02/05, DOC-05; saved catalogs and downloaded guides are not live freshness or scanner readiness |
| CVE scanning and updates without licensed scanning tools | Public Trivy database management, offline bundles and normalized cluster CVEs; bulletin and Nessus imports remain available | MVP-03/04 for intended real cluster/image evidence; MVP-06 for patched-image discovery, durable registry pulls and approved image changes |
| Confidence, false positives, filtering and sorting | Deterministic evidence grades, audited scoped review, filters/sorts and row details | VAL-02/04/05, UI-01, SCL-03; grades are not calibrated probabilities |
| Model explanations and dependency/breakage advice before approval | Configurable explanation backend plus bounded change-impact evidence and immutable advisory receipts | COV-02/03, SCAN-05; full dependency knowledge, maintenance windows and independent lockout recovery remain open |
| Verify fixes, show current status, and roll back older changes from history | Adapter verification, history/audit links, conservative rollback finding state and supported restore guards | REM-01/03, COV-02, SCL-04, MVP-09; saved configuration does not restore all application/runtime data |
| Avoid destructive Kubernetes fixes by default | Heuristic indicators select owner-review guidance; retired deletion actions cannot execute; migration/removal guidance states service/data checks | REM-01, VAL-02, MVP-07/09; no automatic investigation closure or service-health guarantee |
| Persist discovery/scans and run offline with a database | StateStore documents persist through JSON or SQLite; inventory/proposals and hash-chain audit retain their protected file formats | SCL-01/02/03/04/05; PostgreSQL, multi-node operation and measured scale remain open |
| No default slow-link demonstration behavior in normal use | Unknown/measured production observations; explicit test mode and offline override | CON-03/04; real delivery and continuous monitoring are not supplied by simulation |
| Verified per-user app and system access | Signed account identity, explicit role and target/environment/action grants, account-bound target credentials and independent human approvals; original artifact ownership survives target reassignment | ZT-01 through ZT-31 for live realm/target acceptance and remaining controls; packaging alone does not establish application identity or target authorization |
| Complete local recovery copy and a judging checkpoint | Source archive, all-ref Git bundle, restore/hash checks and local mirrored evidence are refreshed for merged checkpoints | Runtime state, credentials, VM disks and offline scanner/image caches are separate; retain/restore them under SCL-04 and TST-02. Rehearsal and field evidence remain RNG-01/02/03 and ATO-01 through ATO-04 |

No deferred item in this table is an instruction to start new feature work before the operator resumes.
