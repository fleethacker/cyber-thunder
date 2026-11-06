# Verified vSphere inventory accounts

This extends the reviewed vSphere source with explicit requester-to-account
authorization. The verified-mode refusal described in the original
`VSPHERE_DISCOVERY.md`, `VSPHERE_REVIEW.md`, and initial handoff is now replaced
by a dedicated `vsphere` binding. Legacy SSH-shaped source records still refuse
verified HTTPS access. This does not complete real vCenter/ESXi acceptance.

## Inventory and access policy

Register the endpoint explicitly with `transport: vsphere`, its management IP,
environment and TLS trust. A saved discovery range must contain that IP. The
normal inventory model assigns an authorization generation; do not copy an old
generation when registering a replacement endpoint.

```yaml
id: vc-a
name: vCenter inventory A
asset_type: linux
transport: vsphere
address: 10.20.0.2
environment: lab-a
in_scope: true
sudo: false
options:
  hypervisor: vsphere
  vsphere:
    endpoint: https://vc-a.example.test/sdk
    tls_trust: ca_file
    ca_file: /run/trust/vcenter-ca.pem
```

`tls_trust: system` explicitly selects runtime system trust and requires no
`ca_file`. Custom trust must be a local, absolute PEM CA file of at most 1 MiB.
UNC/device paths, final-component symlinks/reparse points and non-regular files
are refused. Protect the configured directory, ancestors and mounts against
replacement. TLS verifies the endpoint hostname against the configured IP
connection, without DNS, proxy discovery, redirects or insecure exceptions.
If the inventory `port` is set, it must match the HTTPS endpoint port.

The existing server-managed `auth/access.json` selects the account. For example:

```json
{
  "version": 1,
  "entries": [{
    "issuer": "https://identity.example.test",
    "subject": "operator-a",
    "node_actions": ["discover"],
    "grants": [{
      "target_ids": ["vc-a"],
      "environments": ["lab-a"],
      "actions": ["discover"],
      "credential": {
        "username": "operator-a-inventory@lab",
        "credential_ref": "OPERATOR_A_VC",
        "sudo": false,
        "options": {"transport": "vsphere"}
      }
    }]
  }]
}
```

Provision the synthetic example's real equivalent through the deployment's
protected credential mechanism as `CT_CRED_OPERATOR_A_VC`. Never put the value
in inventory, policy, command arguments, observations or documentation. The
reference must be a plain name, beginning with an ASCII letter, digit or
underscore, followed by at most 63 letters, digits, underscores, dots or hyphens.
The source reads exactly that prefixed variable when logging in. A missing
value fails; bare variables, top-level inventory credentials, nested development
credentials, SSH keys, agent credentials and other accounts are not alternatives.

Use `group` instead of `subject` only for an explicitly trusted issuer group.
Both selectors cannot appear in one entry. Existing policy semantics apply:
target and environment selectors intersect; distinct matching credential
bindings fail as ambiguous, with no subject-over-group precedence. The immutable
binding records issuer, subject, operation, selectors, policy digest, endpoint
declaration digest and target authorization generation.

Roles are an additional check. An analyst with the explicit node/resource grants
can discover; an admin or approver role alone cannot. An analyst workload can
perform this read-only collection with its own matching account grant. No human
approval, apply or rollback permission is added. A vSphere binding is valid only
for `discover`; it cannot be repurposed for SSH, WinRM, Kubernetes, scan or apply.
Discovery read APIs retain their existing global-read authorization requirements;
this change does not grant API visibility through a credential binding. The
parent-owned `api/access.py:authorize_request` additionally requires read access
to every current inventory target for `POST /discovery/sweep`, even when only
one vSphere source is accessible to that account. This is an explicit remaining
HTTP integration constraint for limited users. A source-only scoped API entry
point or a reviewed global-preflight change belongs to the parent; this patch
does not bypass that policy. API tests assert the existing 403, then explicitly
grant the fixture global/resource read rights to test serialized responses.

## Request, TLS and publication checks

The source captures one principal, account binding, target configuration and
exact range grants at collection start in the copied worker context. That same
selection is used for requests and candidate publication; a later policy edit
cannot silently select a different account. Other accounts' source endpoints
are skipped. A source introduced after the sweep captures its grants cannot be
contacted by that sweep.

Before and after requests, and around candidate/run publication, the source
checks current principal/session validity, `discover` operation and role,
issuer/account/resource policy, inventory ownership generation and scope, kill
state, exact saved range grants and connection configuration. Changing the
endpoint, address, port, trust, selected account, environment or target generation
aborts the retained grant. Reusing a target ID or widening a range cannot renew it.
Custom CA bytes are loaded into the TLS context from the captured snapshot and
their digest is rechecked on later operations. System trust is loaded once into
that source's TLS context. Updating a credential variable alone is not session
revocation: revoke the policy grant or authenticated application session to stop
an already logged-in collection.

Each publication is checked immediately before and after its state write.
Revocation after an authorized write stops subsequent publication/return; it
does not erase historical evidence already published while authorized. The JSON
and SQLite writes are not a distributed transaction with the external policy
file or identity provider. Failed pre-publication checks retain prior candidates.
The source never auto-accepts candidates, assigns guest credentials, broadens a
saved range, or authorizes active scans of reported guest addresses.

`credential.use` records account, requester, action, policy/credential references
as digests, target generation, endpoint and custom-CA digest. It never records
the password, session cookie or CA file path. SOAP faults and transport failures
expose fixed errors. Successful metadata that echoes the password/session is
rejected, including XML-decoded literals and common base64/percent envelopes
with up to two decoding layers. No arbitrary-transformation secrecy claim is made.
Cookies are local to one client and cleared during cleanup. Revocation also
blocks cleanup requests; the endpoint must expire abandoned sessions/views.

The protocol remains the reviewed fixed session/view/property-read sequence.
[SessionManager](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.SessionManager.html)
defines login/logout, and the
[PropertyCollector API](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vmodl.query.PropertyCollector.html)
binds retrieval continuation to the same session and collector. No remote
permission, role or realm is modified. Deployment must separately establish
effective Read-only rights over the intended remote inventory hierarchy.

## Offline validation and remaining acceptance

Tests use actual principal checks, access policies, immutable credential
selection, persisted inventory, discovery service, SOAP parsing, audit and
JSON/SQLite state. Only remote I/O and local passive observations are fixtures;
no remote connection or real credential is used. Controlled token claims also
exercise actual discovery/audit API serialization. TLS-material tests load real
fixture CA certificates but do not perform a remote handshake.

Coverage includes per-account endpoints, subject/group/issuer isolation,
workload and role constraints, conflicting bindings, absent and wrong-transport
credentials, target-ID reuse, policy/session/scope/kill revocation during a
response and before publication, copied worker contexts, CA replacement,
Unicode/invalid input, powered-off/addressless VMs, and credential-echo rejection
in saved state, logs and API output. Existing discovery and account transport
regressions are included in the validation command:

```powershell
$env:PYTHONPATH='C:/Users/joshu/.codex/worktrees/scope-recipes/cyber-thunder'
& 'C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe' -m pytest -o addopts= -q tests/discovery tests/security/test_credential_binding.py tests/security/test_account_transports.py --tb=short --show-capture=no
```

Measured on Windows with the shared Python 3.12 interpreter:

- Broad run: **590 passed, 2 failed** in 409.40 seconds. Both failures were the
  API test's missing global/resource read grants, not credential disclosure.
  The fixture now asserts those refusals before explicitly granting read access.
- Final focused follow-up: **8 passed** in 28.63 seconds. This includes both
  corrected API cases and six added session/publication/Unicode cases. Production
  code is identical to the broad run. Together these runs cover **598 distinct
  passing discovery/account cases**, including **144 new account-access cases**;
  the complete command was not repeated after the test-only fixture correction.
- Shared Kubernetes credential regression: **199 passed, 3 skipped** in 7.62
  seconds. The three skips require real POSIX permission modes, unavailable on
  Windows. Existing framework deprecation warnings remain.

Exact follow-up commands, with the same `PYTHONPATH`:

```powershell
& 'C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe' -m pytest -o addopts= -q tests/discovery/test_vsphere_account_access.py -k 'credential_echo_never_reaches_authenticated or session_revoked_during_reconciliation or revocation_after_authorized_asset_write or unicode_account_name' --tb=short --show-capture=no
& 'C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe' -m pytest -o addopts= -q tests/security/test_kube_credentials.py --tb=short --show-capture=no
```

No production dependency, configuration, context, UI or role-map change is
needed. The narrow inventory transport allowlist addition is included. This
transport is source-only; it does not implement an OS scanner transport.
The parent may link this document and update historical backlog/umbrella claims.

External acceptance remains open for live vCenter and standalone ESXi versions,
effective remote Read-only permissions and inventory visibility, actual
certificate-chain/name failures, large-inventory timing/pagination, and native
and container deployment with provisioned per-account credentials. Application
session cryptographic validation remains covered by its owning subsystem,
not by these controlled-claims fixtures.
