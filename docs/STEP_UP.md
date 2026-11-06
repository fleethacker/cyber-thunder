# Step-up authentication for risky decisions

Verified mode requires recent signed authentication evidence for `approve`,
`policy`, `kill.release` and `admin` decisions, including target and scope
changes and explicit transfer admission. Application roles, exact actor identity,
current sessions and resource grants remain independent requirements. Workloads cannot approve by supplying a
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

For native or container deployment, put both values in the administrator-owned
environment configuration and restart the application. A Kubernetes ConfigMap
may carry these non-secret settings; restrict who can edit it:

```yaml
CT_STEP_UP_MAX_AGE_SECONDS: "300"
CT_STEP_UP_ACR_VALUES: '["urn:example:assurance:hardware"]'
```

Replace the example ACR with an exact value accepted by the reviewed realm
policy. Configure the authorization-code client to request that context and
emit signed `auth_time` and `acr` in the nonce-bound ID token. Bearer clients need
their own signed authentication-event claims in API access tokens. Token `iat`
or an access-token refresh is not a substitute. The issuer/client/subject and
server-owned account policy remain separate configuration requirements.

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
The API and core share one nondecreasing clock for assurance age. A backwards
wall-clock correction cannot restore eligibility after the authentication event
has aged out. Monotonic-clock failure latches a refusal for that process; repair
the clock before a controlled restart. A forward time correction may conservatively
expire assurance. This clock does not change the signed claims or token lifetimes.

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
An interactive exchange with a future-dated ID-token `auth_time` is refused
before establishing a session, even when generic token skew would allow it.
Such evidence cannot sit in a session and silently become usable later. Correct
realm/node time rather than extending the assurance window.

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
the transaction. The originating session is checked before token endpoint I/O
and again before publishing its replacement, including logout from another tab
that does not hold the pending login cookie. A successful callback rotates the
application session, CSRF token and copied worker lease validity, and returns
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
lower-level identity/role check alone is not the step-up policy. Explicitly
admitted transfers use the bounded continuation interface below; all other
admin decisions recheck authentication age.
The bulk proposal handler preserves per-item outcomes: expiry during a batch
returns status 401, the error code and a structured `step_up` challenge on the
refused item. The browser keeps earlier results, prompts for deliberate
reauthentication and never replays the batch. Entry-time expiry receives the
normal top-level challenge from the middleware. Regressions advance the clock
after the first recorded decision and verify that its vote remains intact.

Parent integration must preserve the `AppContext.authorize` hook, API error mapping,
session assurance snapshot and client 401 distinction together. Rebuild the combined
UI separately; this change does not commit generated assets or dependencies.

## Independent review and bounded transfer continuation

Review base: `97bbfd2`, with parent bulk-result correction `554de9b` applied.
The review reproduced and corrected three issues:

- A small wall-clock rollback allowed an already-stale principal to approve
  through both direct core calls and HTTP. API and core now use the same
  nondecreasing age clock, including copied worker contexts.
- Initial browser login retained a future signed authentication event under the
  generic token clock-skew allowance. It could later satisfy step-up without a
  new interaction. The interactive exchange now rejects that event.
- A pending reauthentication whose original session was revoked could still
  exchange its code before failing the final session check. It now fails before
  token endpoint I/O, while retaining the final post-exchange check.

**Corrected: repeated step-up during an admitted transfer.** At the review base,
content pulls called `authorize("admin")` at initiation, each file, and the downloader
stop callback. Trusted-source publication called it again through
`ingest/content/signatures.py:decide`. Vulnerability database update guards also
used `admin`. An otherwise authorized operation stopped when the initiating
authentication event crossed the configured age limit, even when its credential
was still valid. A transfer at 56 kbps can reach this boundary before its first
file completes.

`admit_transfer` now requires fresh assurance and current node administration
authorization for `content.pull` or `vulnerabilities.update`. Its process-local,
immutable receipt binds the original principal, owning application context,
operation, job ID, hash of the request/file set and transfer configuration,
protected account-policy digest, assurance settings and security mode. Its
deadline is the earlier of original credential expiry and one hour. The audit
records the job, operation, intent hash and deadline; neither the receipt nor
credentials are serialized into the job record.

Each continuation passes a fresh declaration to `AppContext.authorize` through
the explicit `step_up_continuation` argument. The core verifies the receipt's
bindings in addition to the normal current-principal/session, role and account
grant checks. Only node-level `admin` continuation is accepted. No context-wide
freshness bypass exists. Scope, configuration, policy, unsigned-content override
and approval decisions continue using the ordinary fresh-assurance path.

Content guards recheck the admission before each network attempt, download
poll and trusted-source publication. Only a real live-download provenance
receipt can use this continuation; it cannot authorize an unsigned-content
override or offline import. Vulnerability update guards carry the same bounded
admission through engine execution and generation publication. Existing kill,
link, byte limits, source TLS and authenticity checks remain active. Policy,
assurance configuration, request intent, credential or session changes stop the
job. Completion/failure closes the admission; queued worker failures become
terminal and never trigger an automatic retry. A process restart loses the
admission and cannot resume it from saved job metadata.

Transfer regressions cover real loopback HTTPS publication after the freshness
window in synchronous and copied worker contexts; changed job, account, role,
node, policy, mode and assurance settings; revocation before I/O and after
download; and worker-start and persistence failures. Unsigned-content overrides
and new administrative decisions still refuse stale assurance. Managed database
tests use an isolated engine fixture and verify both publication and refusal.
The JSON and SQLite backends exercise the same authorization boundaries.

**Open: credential lifetime beyond the admitted job.** Copied browser leases deliberately
retain the original token expiry and become invalid on refresh generation change
or logout. An admission receipt alone cannot make a five-minute token authorize
a longer job. Supporting that needs an independently reviewed, explicitly bounded
per-job delegation/renewal design using actual newly validated signed credentials
and current grants. Configure the issuer's reviewed credential lifetime to cover
the intended bounded transfer; the current API verifier accepts token lifetimes
of at most one hour. A deployment with five-minute access tokens still cannot
run a longer job under its original credential. Increasing
`CT_STEP_UP_MAX_AGE_SECONDS` is not a fix for token expiry.
Never extend `exp`, synthesize `auth_time`, renew an old
principal silently, or substitute a shared privileged account. External CAC/PIV
and real realm acceptance remain open.
