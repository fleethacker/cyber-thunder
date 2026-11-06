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
    "node_actions": [],
    "grants": [{
      "target_ids": ["vc-a"],
      "environments": ["lab-a"],
      "actions": ["discover", "read"],
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

Roles are an additional check. An analyst with the explicit resource grants
can discover; an admin or approver role alone cannot. An analyst workload can
perform this read-only collection with its own matching account grant. No human
approval, apply or rollback permission is added. A vSphere binding is valid only
for `discover`; it cannot be repurposed for SSH, WinRM, Kubernetes, scan or apply.
The source-specific HTTP routes below require target grants without a node grant.
The global discovery views retain their global-read requirements, and
`POST /discovery/sweep` still requires the node discover grant and read access to
every current inventory target. Its `require_all` check is unchanged. A credential
binding does not itself grant either source-history or global API visibility.

## Limited-account HTTP collection

All paths are under `/api/v1`. The application derives the verified actor from
authentication; development requests use the existing `X-Actor` header.

| Method and path | Permission and response |
| --- | --- |
| `POST /discovery/vsphere/{target_id}/collect` | Target `discover` plus an explicit discover credential binding; no body; synchronous run result |
| `GET /discovery/vsphere/{target_id}/runs?limit=20` | Target `read`; newest-first summary array; limit 1–100 |
| `GET /discovery/vsphere/{target_id}/runs/{run_id}` | Target `read`; one run with observations |

The POST invokes only the explicitly selected source through the existing
guarded account/client. It never invokes global sweep, passive collection, CIDR
probes, inventory-wide reconciliation or acceptance. It does not match guest IPs
against other inventory targets or infer missing assets. Existing global assets,
global run history and inventory declarations remain unchanged.

POST and single-run responses use this shape (the observations are the existing
`DiscoveredAsset` dictionaries):

```json
{
  "version": 1,
  "id": "vsphere-0123456789abcdef0123456789abcdef",
  "source": "vsphere",
  "target_id": "vc-a",
  "authorization_scope": {
    "version": 1,
    "target_id": "vc-a",
    "environment": "lab-a",
    "authorization_id": "original-target-generation"
  },
  "requested_by": "human:requester-digest",
  "requested_principal": {
    "kind": "human",
    "iss": "https://identity.example.test",
    "sub": "operator-a",
    "name": "Operator A",
    "roles": ["analyst"],
    "via": "oidc",
    "verified": true
  },
  "started_at": "2026-11-05T12:00:00+00:00",
  "finished_at": "2026-11-05T12:00:01+00:00",
  "status": "finished",
  "collection_started": true,
  "complete": true,
  "observation_count": 0,
  "error": null,
  "observations": []
}
```

History summaries omit `observations`; other public fields are identical.
`requested_principal` can be null in development and contains no application
session identifier or token. An observation's `inventory_target_id` remains
null: reported objects are source claims for explicit inventory review, not
authorized new targets. Powered-off and addressless VMs remain metadata-only
observations, with no claim of guest reachability.

HTTP 200 means the attempt produced a run record. Clients must inspect `status`
and `complete`. A complete empty inventory is `finished`, `complete: true`,
`observation_count: 0`. A transport, parser, limit or later-page error is `failed`,
`complete: false`, with a fixed `vsphere:*` error code and no observations. The
client requires a complete bounded snapshot: partial pages are discarded, never
reported as complete or as an empty success. `collection_started: false` means
the collector was not invoked (for example a missing local credential).
`collection_started: true` does not prove that a connection succeeded; no
connectivity inference is made on failed attempts.

Missing account bindings deny with 403 before client creation. Mid-operation
authorization revocation returns 403, kill returns 423, and publication failure
returns a fixed 503. Previously started runs are closed as `stopped`, incomplete
and without observations. History may show `running` during collection or after
an abrupt process exit; it must not be treated as completed evidence. There is
no detached source worker or automatic retry, and no process-restart recovery
claim. Calls retain the source's 60-second collection deadline and other wire
limits; local authorization, storage and audit overhead is additional.

Each UUID run lives under
`discovery/vsphere/<original-ownership-digest>/<run-id>.json`, through StateStore
on both JSON and SQLite. Concurrent requests write distinct documents; no
shared latest-result document can overwrite another run. The original owner is
the target ID, environment and authorization generation captured at start. The
record also retains private digests of the source configuration and exact saved
range grants. These digests and global range declarations are not returned by
the API. Address filtering uses the saved ranges, but no scanner is invoked.
Replacing a captured range, even with a broader range or identical CIDR under a
new grant, invalidates the old run for these source-history routes. Adding an
unrelated range does not extend an in-flight collection's captured grants.

History reads require a fresh valid identity/session and current target read
grant. They also check the original generation, unchanged source configuration,
in-scope target and retained range grants. Inaccessible/obsolete runs are filtered
before limiting; a direct obsolete run request is denied or not found. Reusing a
target ID cannot reassign its old runs. Removing discover credentials while
retaining read rights permits reading historical evidence; it cannot authorize
a new collection. Original ownership is never inferred from today's inventory.

Publication is checked before and after each state write and after audit, using
the captured source guard. A detected stop clears this run's observations and
retains only fixed stop metadata under its original owner. State, access policy,
inventory and identity-provider state are not one distributed transaction. A
crash or storage failure during revocation cleanup can retain an earlier write;
history still performs its own current ownership/read/scope checks.

The authenticated HTTP fixture exercises actual middleware, target authorization,
account selection, source/client parsing and StateStore. It deliberately gives
the alpha account no node permissions and no rights over beta inventory. The
new routes work for alpha while beta and the global sweep/views remain denied.
Remote vSphere inventory visibility is still determined by the provisioned
remote account. The application does not grant access to newly reported guests.
UI selection/review/registration wiring remains an integration seam; there is no
new automatic acceptance endpoint.

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

No new runtime dependency, configuration, context or UI change is needed. The
source-specific HTTP routes add only exact collect/read entries to the existing
role map. The narrow inventory transport allowlist addition is included. This
transport is source-only; it does not implement an OS scanner transport.
The parent may link this document and update historical backlog/umbrella claims.

External acceptance remains open for live vCenter and standalone ESXi versions,
effective remote Read-only permissions and inventory visibility, actual
certificate-chain/name failures, large-inventory timing/pagination, and native
and container deployment with provisioned per-account credentials. Application
session cryptographic validation remains covered by its owning subsystem,
not by these controlled-claims fixtures.

## Source-route validation with protected session evidence

Run with the same shared interpreter and checkout `PYTHONPATH` as above:

```powershell
& 'C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe' -m pytest -o addopts= -q tests/discovery/test_vsphere_runs.py tests/security/test_session_evidence.py --tb=short --show-capture=no
& 'C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe' -m pytest -o addopts= -q tests/discovery/test_api_cli.py tests/discovery/test_vsphere_source.py tests/discovery/test_scope_principal_context.py tests/security/test_identity_boundary.py --tb=short --show-capture=no
```

After integrating the shared session-evidence correction, the first command
measured **85 passed, zero skipped** on Windows in **268.24 seconds**. This includes
all **75 source-route cases** and **10 session-evidence cases**, with JSON and
SQLite persistence exercised. The source implementation and all source-route
tests are unchanged from `8a2867d`.

The original six credential-echo cases had caught raw OIDC session identifiers
in the shared audit principal evidence. The parent correction `3075f54`, applied
here as `ad215c2`, fixes that shared boundary: newly exported/stored principal
evidence has `session_id: null` and an issuer/subject-scoped SHA-256
`session_fingerprint`. The fingerprint supports correlation; it does not
authenticate an operation. Existing recorded evidence remains readable and is
not rewritten. Source-run responses retain their narrower principal fields and
do not add either session field, so the HTTP contract is unchanged.

All six formerly failing cases now pass without changing their assertions or
excluding any application output or state file. They continue checking the
credential, vSphere session cookie and application session identifier across
responses, logs and persisted state. Malformed saved-range errors also remain
fixed messages rather than echoes of global configuration.

Existing API/CLI, source, copied-worker and identity regressions measured
**86 passed** in 54.80 seconds. No tests were skipped; existing FastAPI/Starlette
deprecation warnings remain. The source-route cases exercise JSON and SQLite,
limited alpha versus beta accounts, unchanged global restrictions, absence of a
discover binding before client construction, role/workload constraints,
original-owner history after ID reuse, revocation during calls/publication/read,
concurrent persistence, no-connect failures, partial pagination failure, real
credential-echo rejection and fixed publication errors. Wire I/O uses only
fixtures and sockets are blocked during application requests. No live vCenter,
remote trust handshake or newly accepted target is part of this evidence.
