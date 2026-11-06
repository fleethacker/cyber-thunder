# Browser identity sessions

## Parent integration contract

The parent supplies `ctx.session_config` as a `SessionConfig`, or `None` to keep
sessions disabled. Register routes before the UI catch-all using
`install_sessions(app, ctx, access_validator)` from `api.session_routes`; retain
the returned `SessionService` (or `None`). This change does not modify settings,
authentication middleware, principal mapping, routes registration or the UI.

```python
SessionConfig(
    issuer, client_id, authorization_endpoint, token_endpoint, redirect_uri,
    id_token_config,
    client_secret_ref=None, scope="openid",
    idle_timeout_s=900, absolute_timeout_s=28800, login_timeout_s=300,
    max_sessions=256, max_pending=128,
)
```

`id_token_config` is an `OIDCConfig` with the configured issuer and
`audience=client_id`. Its authorized party is absent or equal to `client_id`.
The separate access validator must use the same issuer, a different API audience,
and `authorized_party=client_id`. Give the two validators distinct JWKS cache
files in pre-provisioned protected directories.

The service exposes:

- `resolve_session(headers, *, touch=True) -> dict | None`: validated access-token claims;
  `None` only when the session cookie is absent. Invalid, unknown and expired
  cookies raise the fixed `AuthenticationError`. Never fall back to a typed actor
  after that failure. Reject mixed cookie and Authorization credentials.
- `resolve_session_with_lease(headers, *, touch=True) -> (claims, guard) | None`:
  the atomic form, binding validated claims to their local session guard.
- `session_guard(headers) -> Callable[[], None]`: compatibility hook after
  resolution. Invoking the guard succeeds with `None` or raises a fixed,
  sanitized `PermissionError`; it is not a boolean-returning protocol.
- `csrf_check(method, headers) -> None`: for cookie authentication, call this
  **before** resolving unsafe requests, and before any action. It requires a live
  session, configured-origin `Origin`, and matching `X-CSRF-Token` for every
  method other than GET, HEAD and OPTIONS. Bearer-only callers do not call it.
- `start_login(headers)`, `complete_login(query_string, headers)`,
  `session_info(headers)`, and `logout(headers)` serve the installed routes.

Routes are `GET /auth/login`, `GET /auth/callback`,
`GET /auth/status`, and `POST /auth/logout`. Login and callback must
be reachable before authentication. The status route returns a CSRF token for
the UI's in-memory use. Every cookie-authenticated unsafe application route
requires the parent's CSRF check; these modules cannot enforce routes they do
not own. The logout route also checks CSRF itself.

Status is installed even when sessions are disabled and returns
`{mode, authenticated, login_available, permissions}` plus `csrf_token` when
authenticated. The optional parent hook `ctx.session_status_identity(claims)`
supplies `{principal, permissions}` from the parent's identity/policy mapping.
Without that hook principal is omitted and permissions are empty. Disabled
sessions report unauthenticated status, never an implicitly verified typed actor.
`session_info()` and `/auth/status` always resolve with `touch=False`. Parent
middleware must also use `touch=False` for passive API polling, including
`GET /api/v1/status` and `GET /api/v1/audit/verify/stream`. Token refresh does not
itself change the idle timestamp. Only successful resolution with `touch=True`
records user activity; repeatedly checking status cannot keep a passive tab alive.

Dependency addition: **OAuthLib 4.0.0**, wheel
`oauthlib-4.0.0-py3-none-any.whl`, with no transitive requirements. It supplies
authorization-code request formatting and PKCE S256. Existing pinned PyJWT and
cryptography verify signed tokens. The HTTP exchange uses a bounded isolated
standard-library helper so library HTTP retries, redirects or debug logging
cannot expose credentials. The parent owns manifests and wheel vendoring.

The downloaded wheel's SHA-256 is
`624c28c13a0a59cabf9747dfa52af63be3e512a7f2714df16e91b5b3a145e6cd`.

## Flow and browser boundary

The flow uses authorization code, `response_mode=query`, and PKCE S256 through
[OAuthLib's authorization-code client](https://oauthlib.readthedocs.io/en/latest/oauth2/clients/webapplicationclient.html).
The server generates independent 256-bit state, nonce and browser-binding
cookie values, plus an 86-character random PKCE verifier. Transaction secrets
stay in memory. The authorization URL contains the challenge, never the verifier.
The callback consumes its transaction before checking the response or making a
token request; retries and concurrent replay cannot redeem the same transaction.
Both state and the independent browser cookie are required. Duplicate query
parameters, unsolicited fields, provider errors and mismatched response `iss`
are rejected. With one explicitly configured issuer, response `iss` is optional;
signed token issuer/client checks remain mandatory.

All configured URLs require HTTPS without credentials, query strings, fragments,
backslashes or wildcards. The callback path must be exactly `/auth/callback`.
No discovery or user-selected provider is supported. The callback origin is
derived only from configuration. Successful login returns to that origin's `/`;
request Host/Forwarded headers and `next` parameters never select a redirect.
Queries on the login route are rejected. The callback erases its ASGI scope's
query before responding; ingress logs must independently redact callback queries.

The initial ID token must pass the existing RS256/ES256 verifier and have the
exact transaction nonce. Access and ID tokens must have the same issuer and
subject. Access tokens require the API audience and `azp=client_id`. Access-token
audiences cannot include the browser client; ID-token audiences cannot include
the API audience. This includes multi-audience tokens and prevents substitution
between the two token profiles. Optional ID-token `at_hash` is verified using
the SHA-256 hash prescribed for the allowed algorithms. These checks apply the
[OIDC code-flow validation rules](https://openid.net/specs/openid-connect-core-1_0.html#TokenResponseValidation)
with the stricter audience separation documented here.

Cookies are `__Host-ct_login` for the transaction and `__Host-ct_session` for the
session. Both use Secure, HttpOnly, SameSite=Lax, Path=/, and no Domain attribute.
Only random opaque identifiers appear in them. Login rotates the session ID and
CSRF token and invalidates the previous session after successful verification.
The browser must never store OAuth tokens in local storage, session storage or
JavaScript memory. Only the status response's CSRF value is used by the UI, kept
in memory and sent as `X-CSRF-Token` with unsafe requests.

All four routes return `Cache-Control: no-store`, `Pragma: no-cache`,
`Referrer-Policy: no-referrer`, and `X-Content-Type-Options: nosniff`. Status returns
HTTP 200 with unauthenticated state when a session is missing, expired or invalid.
The API resolver instead raises for invalid cookies, so the middleware must
never reinterpret such a failure as development identity. Public login/callback
failures are a fixed HTTP 401 response. Logout failures are HTTP 403 and do not
clear a valid cookie, preventing an invalid CSRF request from forcing logout.
Successful logout deletes the local session/transaction and clears both cookies.

The status hook accepts a bounded public principal projection: `actor`, `name`,
`subject`, `issuer`, `source`, `identity_ref`, `verified`, and `roles`. Permissions
and roles must be lists of short strings. Other fields are discarded. The hook
must perform the parent's normal principal/policy mapping; raw signed role claims
do not grant permissions. A failed projection yields signed-out status.

## CSRF and middleware integration

Every cookie-authenticated method other than GET, HEAD and OPTIONS requires the
session's CSRF value and an exact Origin match to the configured callback origin.
Missing, null, multiple or foreign Origin values fail. Duplicate cookie/header
values and simultaneous session-cookie plus Authorization credentials fail.
When supplied, `Sec-Fetch-Site` must be `same-origin` or `none`; it cannot replace
the required Origin on unsafe methods. Safe authenticated lookups also reject a
foreign Origin or cross-site Fetch Metadata. No CORS permission is added.

Parent middleware should check CSRF before resolving an unsafe cookie request,
so rejected cross-site requests cannot refresh tokens or extend idle time:

```python
if SESSION_COOKIE in request.cookies:
    session_service.csrf_check(request.method, request.headers)
resolved = session_service.resolve_session_with_lease(
    request.headers, touch=not is_passive_poll,
)
if resolved is not None:
    claims, guard = resolved
    # Map claims through normal principal and AccessPolicy checks, then carry
    # the guard using principal_scope(principal, validity=guard).
```

The service reparses original headers strictly; the initial cookie-presence check
does not replace its duplicate/malformed-cookie validation. `/auth` routes sit
outside API middleware and enforce their own boundary. Keep every safe method
free of application mutations. Parent configuration must not allow credentialed
CORS from other origins. XSS defenses and browser policy remain application work.
Development mode does not install sessions or verify a typed actor. Its status
reports `mode=dev`, `authenticated=false`, and `login_available=false`; the
existing development actor path must continue to label that identity unverified.

## Background jobs and local session revocation

Capture the raising guard while authenticating a cookie request and carry it in
the parent's validity ContextVar alongside the principal context. Prefer the
atomic `resolve_session_with_lease` API so a concurrent refresh cannot separate
claim verification from the guard snapshot. Existing integration can use
`resolve_session` followed by `session_guard`; retain the principal's own token
expiry check in either case. `require_current` must invoke the guard before each
sensitive operation and each new target command. Copying a principal without
its validity context does not carry browser-session authorization.

The guard checks, under the service lock, that the session still exists and that
idle timeout, absolute timeout, clock validity, credential generation, original
access-token expiry and original token-response lifetime permit continued use.
It never touches idle time, refreshes tokens, validates another JWT or performs
network I/O. Logout, replacement login, failed refresh, expiry and clock rollback
invalidate existing guards. A browser refresh cannot revive a guard from the
previous credentials or silently extend an immutable principal's authority.

Guards retain only a weak service reference, a SHA-256 session fingerprint and
numeric generation/expiry bounds. They do not capture request headers, cookies,
JWTs, refresh tokens or token-bearing session objects. The optional
`guard.fingerprint` is a non-credential audit correlation identifier; it cannot
authenticate as a cookie. Put the callable in the ContextVar, never in Principal
or audit serialization. The service's private fingerprint lookup remains bounded
by the session cap and is removed on every session deletion. Losing the service
instance invalidates its guards and does not retain token memory through jobs.

After logout completes, any new guard invocation rejects the session. This
boundary does not cancel a command already authorized or sent to a target; the
parent must check immediately before each new command. Existing bearer-only
jobs remain bounded by their principal's token expiry. Provider revocation and
cross-process job cancellation remain separate work.

## Token exchange, refresh and resource bounds

Public clients send their client ID and PKCE verifier. Confidential clients set
`client_secret_ref` to an alphanumeric/underscore reference; the value is read
from exactly `CT_CRED_<reference>` at exchange time and used with
`client_secret_basic`. Client secrets are never settings values or browser data.
The reference is case-sensitive on case-sensitive operating systems. Missing or
invalid secrets fail before sending HTTP. `client_secret_post`, private-key JWT,
implicit, hybrid and form-post flows are outside this profile.

The token endpoint is contacted by a disposable isolated interpreter using
verified HTTPS. No proxy, cookie, redirect, retry or netrc credential handler is
used. Its request credentials travel over stdin, never command-line arguments.
The socket timeout is two seconds and the parent kills/reaps the helper after a
five-second exchange deadline, including stalled DNS, TLS and trickled responses.
HTTP 200 JSON is required; compression, ambiguous framing, duplicate JSON members
and bodies over 64 KiB fail. Server bodies and exception chains never enter
public errors. The helper's stderr is discarded; neither module logs token data.
JWKS verification may additionally need its own bounded HTTPS fetches. The
synchronous service serializes operations with a lock; use a worker pool from
asynchronous middleware and retain one service instance per process.

Session/token bounds:

| Setting or resource | Default | Allowed bound |
| --- | --- | --- |
| Idle timeout | 900 s | 30–3,600 s |
| Absolute timeout | 28,800 s | 60–86,400 s, at least idle timeout |
| Pending-login timeout | 300 s | 30–600 s |
| Sessions | 256 | 1–1,024 |
| Pending logins | 128 | 1–256 |
| Login starts | 20 per minute | Fixed per service instance |
| Token exchanges | 60 per minute | Fixed per service instance, including failures |
| Access/ID token size | — | 16 KiB each |
| Refresh token size | — | 8 KiB |
| Token response `expires_in` | — | Integer, 1–3,600 s |

Capacity limits reject new entries rather than evicting authenticated sessions.
Expired entries are purged opportunistically during service operations. Token
and transaction dataclasses suppress their contents in their representations.
Only access/refresh tokens, the original nonce/subject and session timing/CSRF
data survive a completed exchange. ID tokens are not retained in the session.
No session or OAuth token is persisted; only the verifier's public JWKS cache is
stored on disk. Restart loses sessions and pending logins and requires login.
Process-memory zeroization is not guaranteed by Python. Multiple server workers
need affinity to their own in-memory sessions; cross-process sessions are not
implemented. Deployment-level request limits are still required.

Expiration uses the greater elapsed wall/monotonic interval, so suspend or clock
corrections cannot extend session lifetimes. Monotonic reads bracket each wall
sample: rollback is measured against the start of that interval, while expiry
advances through its end. A scheduler pause after the wall read cannot falsely
latch clock failure. Reversed or nonfinite samples still fail closed.
Backward clock movement beyond the
ID verifier's allowed skew (minimum 10 ms sampling tolerance) invalidates all
local sessions/transactions and latches rejection until service recreation.
Access expiry is enforced without additional token-skew grace and checked again
after verification. Idle and absolute expiry are rechecked after network work.

When the access token expires, a valid live session may redeem its refresh token.
Every successful redemption must return a different refresh token, including for
confidential clients. Missing/nonrotating refresh tokens, changed subjects, bad
signatures, failed exchanges or validation failures destroy the local session.
Optional refreshed ID tokens are verified; if nonce is included it must match the
original transaction. Without a refresh token, access expiry requires login.
Concurrent lookups redeem once, refresh never extends the absolute deadline,
and the CSRF/session identifiers remain stable until a new login. This policy
uses the rotation protections discussed in
[OAuth security best practices](https://www.rfc-editor.org/rfc/rfc9700.html).

Logout is local only. It does not revoke provider tokens, close provider SSO
sessions, or prove that stolen refresh tokens were revoked. Remote revocation,
back-channel logout, sender-constrained tokens, MFA/assurance enforcement and
provider-wide session lifecycle are not implemented or claimed validated.

## Validation and remaining acceptance

The focused suite uses fresh RSA/EC signatures, temporary CA certificates and
an HTTPS token/JWKS provider bound only to loopback. Its token endpoint checks
the real PKCE verifier, client binding and configured redirect URI. Negative
tests cover callback replay/concurrency, browser-cookie swaps, nonce/issuer/
subject/audience substitution, bad signatures, refresh reuse, malformed token
responses, TLS failures, redirects, size/time limits, CSRF, fixation, capacity,
idle/absolute expiry, restart loss and clock movement. FastAPI route tests verify
cookie attributes, status projection, fixed redirects and safe logout.

The separate self-review found and corrected expiry gaps around system suspend
and time spent verifying a token. Follow-up review traced every deletion path to
ensure the lease index is removed with its session, and checked that neither
guards nor passive polling renew idle timestamps. Regression tests cover copied
thread contexts rejecting the next command after logout, guard expiry/replacement,
refresh without revival, service loss, and status polling through refresh to idle
expiry. A clock-sampling follow-up reproduced three failures before applying
bracketed reads: false rollback after a scheduler pause for both live and expired
sessions, and failure to reject a reversed monotonic interval. The tests also
verify that elapsed time includes the entire pause and that ordinary sampling
can resume without a false clock-failure latch. No parent-owned files or previous
verifier code were changed.

```powershell
$env:PYTHONPATH = 'C:/Users/joshu/.codex/worktrees/oidc-validation/cyber-thunder'
& 'C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe' -m pytest tests/security/test_sessions.py -o addopts= -q --tb=short
```

Measured after the lease/passive-idle and clock-sampling follow-ups on Windows CPython 3.12.10:
**117 passed** in 62.58 seconds, no skips. One existing FastAPI/Starlette
test-client deprecation warning concerns its httpx backend; it is not a runtime
session warning. The staged whitespace check passed. This is focused session
acceptance, not a full application or Linux gate.

Remaining acceptance belongs to the combined application: middleware ordering
and principal/AccessPolicy projection, UI integration, TLS termination and
trusted CA/clock provisioning, cache ACLs, ingress log redaction, dependency
vendoring/platform gates and authorized testing with a real provider using this
strict profile. Public-client refresh rotation must also be enforced by that
provider. No real IdP account, provider configuration or external target network
was changed. These fixtures do not establish production PKI, remote revocation
or full zero-trust compliance.
