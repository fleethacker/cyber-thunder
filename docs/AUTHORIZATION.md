# Identity and authorization

Verified access requires a valid token or browser session, an application role permitting the action,
and a matching server-owned access policy. Target operations also require inventory scope and an
explicit account binding for that operation. Signing in alone grants neither target access nor approval rights.

## Choose the authentication mode

| Setting | Behavior |
|---|---|
| `CT_AUTH_MODE=dev` (default) | Native loopback rehearsal only. Typed `X-Actor` names are explicitly unverified; they do not authenticate a person. Non-loopback server binds are refused. |
| `CT_AUTH_MODE=oidc` | The application validates signed access tokens and enforces roles and access policy. Browser login is optional configuration below. |
| `CT_AUTH_MODE=mesh` | The same application JWT and authorization checks, behind an authenticated gateway. The operator must enforce gateway-only reachability and browser-facing HTTPS. |
| `CT_SECURITY_MODE=fleet` | Requires verified authentication and stricter target transport trust; `dev` is refused. The default `range` profile does not itself authenticate users. |

Native and container deployments use the same application controls. A network-accessible container
needs verified configuration with TLS, or the configured mesh boundary; publishing a port does not
make development mode safe. Direct non-loopback `oidc` serving requires both `CT_TLS_CERT` and
`CT_TLS_KEY`. UDS gateway SSO does **not** automatically configure application JWT validation, map
roles, provision target credentials, or establish an application browser session. See the
[container guide](../deploy/kubernetes/README.md) and [transport rules](TRANSPORT_SECURITY.md).

## Configure verified identity

Configure these values on the server. URLs are explicit HTTPS endpoints; the application does not
discover an issuer from a request or token. Register one exact callback, with no wildcard redirects.

| Environment variable | Meaning |
|---|---|
| `CT_OIDC_ISSUER` | Exact trusted token issuer. |
| `CT_OIDC_AUDIENCE` | API access-token audience; distinct from the browser client ID. |
| `CT_OIDC_JWKS_URL` | Trusted signing-key endpoint. Only RS256 and ES256 are accepted. |
| `CT_OIDC_AUTHORIZED_PARTY` | Required `azp` when set; browser login requires this to equal `CT_OIDC_CLIENT_ID`. |
| `CT_OIDC_ROLES_CLAIM` | Role claim name, default `ct_roles`; a list of application role names. |
| `CT_OIDC_JWKS_MAX_AGE` | Maximum cached-key age in seconds, default `86400`; expired tokens or stale keys are not accepted indefinitely offline. |
| `CT_OIDC_CLIENT_ID` | Browser client ID and ID-token audience. |
| `CT_OIDC_AUTHORIZATION_ENDPOINT` | Provider authorization endpoint for Authorization Code + PKCE S256. |
| `CT_OIDC_TOKEN_ENDPOINT` | Provider token endpoint; exchanges are bounded and do not follow redirects. |
| `CT_OIDC_REDIRECT_URI` | Fixed HTTPS callback ending exactly in `/auth/callback`, for example `https://thunder.example/auth/callback`. Request Host/Forwarded headers cannot choose it. |
| `CT_OIDC_CLIENT_SECRET_REF` | Optional reference for a confidential client: `BROWSER_CLIENT` reads server environment variable `CT_CRED_BROWSER_CLIENT`. Omit for a public PKCE client. Never put the secret itself in this setting. |
| `CT_OIDC_SCOPE` | Requested browser scope, default `openid`. |
| `CT_SESSION_IDLE_SECONDS`, `CT_SESSION_ABSOLUTE_SECONDS` | Idle and absolute session limits, default `900` and `28800`. |

All four browser settings (client ID, authorization endpoint, token endpoint, redirect URI) must be
present together. Leaving all four absent disables browser login while preserving verified Bearer API
authentication; `/auth/status` reports `login_available: false`. Browser login checks ID-token nonce,
issuer and client binding, and separately validates the access token for the API audience.

A principal is the application's authenticated human or workload identity; target accounts are
separate credential bindings. The signed `ct_kind` claim distinguishes `human` from `workload`;
absence defaults to `workload`.
An issuer must control who receives human identity and role claims. A display name, a valid signature,
or an `approver` role on a workload token cannot establish a human approver. Verified audit actors
are stable fingerprints of issuer and subject; `X-Actor` cannot impersonate a different account.

Roles are additive: `viewer` reads, `analyst` can scan/discover/propose, `approver` can approve/apply/
rollback, `admin` manages configuration/policy, and `auditor` can audit/export. `admin` does not inherit
every other role. Human-only actions are removed from workload permissions. Roles still require the
matching policy grants below. Standing approval cannot be enabled in verified mode until verifiable
policy signing is implemented.

New persisted principal evidence keeps session correlation as an issuer/account-scoped
`session_fingerprint` (SHA-256), with `session_id` set to null. Raw issuer session identifiers
stay in the authenticated in-memory principal; the fingerprint never grants access or renews
a session. Existing audit and historical decision records remain unchanged, including legacy
session metadata, so apply the node's existing access and retention controls to those records.

## Protect and assign access.json

Provision `<CT_STATE_DIR>/auth/access.json` through server administration, not a browser upload.
The file and every parent directory must be protected against untrusted writes, replacement and ACL
changes. POSIX ownership/write permissions and native Windows owner/DACL permissions are checked;
symlinks and Windows reparse points are rejected. Windows checks conservatively reject untrusted
mutation grants and pin file/ancestor handles; see [WINDOWS_FILE_TRUST](WINDOWS_FILE_TRUST.md).
Service-account provisioning and operational acceptance must still validate that protection
on the host. Missing, malformed or nonmatching policy fails closed.

Example for a human with the `analyst` role, one SSH target `host-a` in environment `range`:

```json
{
  "version": 1,
  "entries": [{
    "issuer": "https://id.example/realms/operators",
    "subject": "operator-subject-id",
    "node_actions": ["read", "kill.engage"],
    "grants": [{
      "target_ids": ["host-a"],
      "environments": ["range"],
      "actions": ["read", "scan"],
      "credential": {
        "username": "ctscan",
        "credential_ref": "HOST_A_SCAN",
        "sudo": false,
        "options": {}
      }
    }]
  }]
}
```

Replace the issuer and subject with exact validated `iss` and `sub` values. An entry may use
`"group": "operators"` **instead of** `subject`, matching an exact trusted `groups` claim under that
issuer. Names and role labels are not policy selectors. Target IDs, environments and actions match
exactly; when both target and environment are listed, both must match. A whole-selector `["*"]` is
an explicit broad grant, not a pattern; partial wildcards and wildcard actions are refused. Prefer
named resources. This example grants no approve, apply or rollback action.

`node_actions` apply to node operations; they never grant access to every target. Node-wide read
views and unfiltered history require node `read` **and** `read.all`, plus read access to current
inventory. The example leaves out global-history permission, so the account uses scoped views.
Grant `read.all` separately only to an account authorized to see node-wide historical evidence,
including evidence outside its current target grants. Targets, findings and proposals are filtered by resource
access before aggregation/pagination. A per-target `read` or `export` grant does not unlock global
history. Report-history and global report exports require node `export` and read access across current
inventory; query filters do not reduce these checks. Audit has a separate node `audit` permission.
All of these checks also require the corresponding role permission.

Each connection selects credentials from grants matching the current principal, exact target and
operation (`scan`, `discover`, `plan`, `apply`, `rollback`, `verify`). The example resolves
`CT_CRED_HOST_A_SCAN` on the server for a scan; an apply grant must independently supply its account.
SSH requires an explicit username and password reference or absolute key path; WinRM requires an
explicit account and password reference. Kubernetes requires a selected kubeconfig file and context.
No inventory credential, ambient SSH agent/key search, process account or default kubeconfig is a
fallback in verified mode. Unsupported delegated transports are refused. Bindings are rechecked
before target commands; secrets are not stored in policy or audit. This is explicit account selection,
not automatic delegation of the browser user's AD/CAC identity to a target.

## Browser and command-line use

Open the HTTPS application and choose **Sign in**. The UI displays the verified account and role
permissions; target/environment policy remains enforced by the server. Root `/auth/status`,
`/auth/login`, `/auth/callback` and `/auth/logout` implement the browser flow. `/api/v1/whoami`
reports authenticated API identity and role permissions. See [API](API.md) and [UI](UI.md).

The session cookie is opaque, Secure, HttpOnly and SameSite=Lax. Access/refresh tokens stay only in
bounded process memory, never browser storage or responses. The UI keeps the CSRF value in memory;
every cookie-authenticated unsafe method requires it and the configured origin. Run one application
process for browser sessions: there is no shared session store, and restart requires a new login.
Passive status/audit polling and token refresh do not extend idle time. Absolute expiry still applies.

**Sign out** clears the local cookie and invalidates the local session lease. Background work carries
that lease and must pass it before the next sensitive operation or target command. Logout/expiry
cannot cancel a command already issued. Provider logout/revocation is not implemented; independent
Bearer tokens remain bounded by token expiry and current authorization checks.

Verified mode currently permits only CLI `serve` and emergency `kill engage`. Other commands require
the authenticated API until CLI login is implemented; a typed `--actor` is not a substitute. The local
development CLI rehearsal remains available on loopback with `CT_AUTH_MODE=dev`.

## Evidence and deployment limits

Automated tests use real signed tokens and isolated HTTPS providers for token/claim failures, PKCE,
state/nonce replay, CSRF, session expiry and refresh. [Browser/API integration tests](../tests/security/test_browser_api_identity.py)
exercise signed approval, logout invalidation of copied request context and passive polling idle expiry. Access and
transport tests exercise denied scopes, account substitution and policy changes. These establish
fixture behavior, not acceptance against a live organization identity service.

Live Keycloak configuration/claim mapping, Windows service-account ACL acceptance, AD/CAC/PKI integration and target
account provisioning remain deployment work. Gateway reachability/TLS and real provider logout or
revocation have not been validated by the fixture tests. See [token validation](OIDC_VALIDATION.md),
[browser protocol details](BROWSER_IDENTITY.md) and [transport security](TRANSPORT_SECURITY.md).
