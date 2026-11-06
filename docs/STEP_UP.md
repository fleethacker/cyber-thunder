# Step-up authentication for risky decisions

Verified mode requires recent signed authentication evidence for `approve`,
`policy`, `kill.release` and every `admin` operation, including target and scope
changes. Application roles, exact actor identity, current sessions and resource
grants remain independent requirements. Workloads cannot approve by supplying a
human-looking name, authentication method or ACR. The issuer must manage `ct_kind`.
Development mode remains an explicitly unverified demonstration.

## Protected configuration

| Setting | Environment | Meaning |
| --- | --- | --- |
| `step_up_max_age_s` | `CT_STEP_UP_MAX_AGE_SECONDS` | Integer seconds, default 300, range 1–3600 |
| `step_up_acr_values` | `CT_STEP_UP_ACR_VALUES` | JSON array of exact accepted ACR strings; Python settings use a tuple |

For example, an administrator may configure `CT_STEP_UP_ACR_VALUES` as
`["urn:example:assurance:hardware"]` after validating that exact value against
the realm's authentication policy. This example does not establish CAC/PIV use.
There is no lexical ordering, prefix matching, wildcard or inference from `amr`.
At most eight unique values are accepted, each 1–128 printable ASCII characters
without whitespace, quotation marks or backslashes. Invalid settings fail
validation; invalid environment values never silently revert to defaults.

An absent or empty accepted set accepts no authentication context. Ordinary
verified reads can continue, but risky decisions fail closed with
`assurance_not_configured`; the UI cannot start step-up until configured.
These settings have no HTTP editing interface. Configuration changes require
the node's protected deployment configuration and a restart to update login
parameters. Core authorization reads the current settings on each decision.

## Core and HTTP contract

`security.step_up.require_step_up(settings, principal, action)` is called by
`AppContext.authorize` after current role and resource checks. It requires a
verified human principal, integer NumericDate `auth_time` no later than now and
no older than the configured maximum, and an exact accepted `acr`. Missing,
malformed, future or stale evidence cannot be replaced by token `iat`, expiry,
refresh time, a typed name or a request parameter. Core denials are audited.

The API repeats the assurance check before risky route handlers, including bulk
handlers that otherwise report per-item errors. Neither an HTTP preflight nor
successful step-up grants access to a target. The core repeats the checks when
the actual operation runs. If refusal cannot be audited, the API returns 503.

`StepUpRequired` is a `PermissionError` mapped to HTTP 401 with no-store headers:

```json
{
  "detail": "Fresh authentication with an accepted assurance context is required.",
  "error": "insufficient_user_authentication",
  "step_up": {
    "reason": "authentication_too_old",
    "max_age": 300,
    "acr_values": ["urn:example:assurance:hardware"]
  }
}
```

The `WWW-Authenticate` Bearer challenge carries the same error, `max_age` and
space-delimited `acr_values`, following [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470.html#section-3).
Reasons come from a fixed allowlist. Challenges contain protected requirements,
not actual token claims, provider errors, tokens or submitted command payloads.
Malformed signed claim types may be refused earlier by token validation with
the existing generic authentication error.

## Browser reauthentication and bearer clients

Browser assurance is captured from the signature-validated ID token at the
interactive authorization-code exchange. Existing issuer, subject, client
audience, nonce and optional access-token hash checks bind it to the access token.
Only `auth_time`, `acr` and `amr` are carried forward; roles and account kind
continue to come from the validated API access token. Refresh never advances
the captured authentication event, even if a refreshed token claims newer
assurance. A bearer API request must carry its own signed required claims and
cannot borrow browser ID-token evidence.

On a step-up 401, the UI keeps the signed-in view and offers a deliberate
Reauthenticate action. `POST /auth/reauthenticate` requires the current session,
same-origin verification and CSRF token. Its only input is an optional bounded
same-origin `return_to` path; unknown fields, duplicate JSON keys, oversized
bodies and query parameters are refused with a generic error. The server chooses
`max_age`, `prompt=login`, accepted `acr_values`, endpoints, PKCE, nonce and state.
The response contains `authorization_url` and the existing protected login cookie.

The pending transaction binds the original account and local session, requested
view and start time. Its callback requires fresh, accepted, signed human assurance
for the same subject and an `auth_time` at or after the transaction's start second.
Logout, account switching, replay, stale proof or insufficient ACR cannot finish
the transaction. A successful callback rotates the application session and returns
to the saved path/query/fragment. The rejected mutation is never replayed; the
operator must review and submit it again. Unsaved form contents are not persisted
through the identity-provider navigation.

These authentication-event semantics follow the
[OIDC Core authentication request](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
and [ID-token validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
requirements. The runtime does not reinterpret token issuance as authentication.

## Verification and remaining acceptance

Focused tests exercise direct core calls, API challenges, both document backends,
real signed tokens from an isolated HTTPS loopback provider, retained ID-token
assurance across refresh, reauthentication bindings, session/CSRF protections,
role and target denials, and UI challenge handling without automatic replay.
Fixture authentication times are sampled during execution; credential expiry
limits are unchanged. No live targets or realm settings are modified.

Live realm claim mapping, authenticator policy, CAC/PIV acceptance and multi-person
enclave acceptance remain open. A configured ACR is an issuer assertion, not local
proof of a particular physical authenticator. Policy signing and separation of
duties are separate controls. When integrating the separation-of-duties work,
retain its existing authorizer calls: each individual approval will encounter
this step-up guard, without changing quorum requirements or recorded decisions.
Standalone gates and custom service contexts must wire this authorizer; the
lower-level identity/role check alone is not the step-up policy. Delayed admin
publication can lose freshness while work is running and must then be refused.
The existing bulk proposal handler catches per-item exceptions: an expiry during
an already-started batch remains a refused item with status 401 inside its results.
The parent-owned bulk route should preserve the structured challenge for this
case (for example by propagating `StepUpRequired`). Earlier successful items must
remain visible and must never be automatically replayed. Entry-time expiry already
receives the normal top-level challenge from the middleware.

Parent integration must preserve the `AppContext.authorize` hook, API error mapping,
session assurance snapshot and client 401 distinction together. Rebuild the combined
UI separately; this change does not commit generated assets or dependencies.
