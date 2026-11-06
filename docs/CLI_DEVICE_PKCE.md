# Device PKCE contract and review

The verified CLI supports the device PKCE extension implemented by Keycloak
26.7.4. It retains the configured public client's S256 requirement, exact
issuer/audience/authorized party, verified human identity, target grants and
server step-up enforcement. No server verifier or realm policy relaxation is
part of this change.

## Primary contract

[Keycloak's device endpoint](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/protocol/oidc/grants/device/endpoints/DeviceEndpoint.java)
checks PKCE parameters and saves the challenge and method with the device code.
[Device redemption](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/protocol/oidc/grants/device/DeviceGrantType.java)
reads `code_verifier` and validates it against that saved challenge before issuing
tokens. [Its PKCE validator](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/protocol/oidc/utils/PkceUtils.java)
checks verifier syntax and the derived challenge. These versioned sources establish
device support; the base device-grant RFC alone does not establish it.

The client follows [RFC 7636 sections 4.1–4.2](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.1):
32 cryptographically random bytes become a 43-character unpadded base64url
verifier, and SHA-256 plus unpadded base64url produces its challenge. Only S256
is sent. There is no method negotiation or downgrade fallback.

## Credential and concurrency boundaries

The verifier is a local variable for one login attempt. It never enters a profile,
token record, command argument, environment, audit record or public result. It
travels to the configured token endpoint through the isolated HTTPS worker's
private stdin pipe. Direct reflected verifier/device-code values are rejected
before token or identity publication and redacted from structured API challenges.
This does not promise erasure of interpreter memory, protection from a debugger,
or detection of arbitrary encoded/split server reflections. Provider request/debug
logging is a separate operator responsibility; do not enable credential logging.

Every poll retains the same attempt verifier. New attempts generate a new one,
including after interruption, denial or logout. Existing generation checks and
locks still precede redemption and cover identity validation and publication.
Logout completed during a polling wait prevents further redemption. PKCE does
not cancel the provider's pending grant or alter the existing local/provider
logout distinction and copied-JWT expiry limitation.

Actual-provider testing also exposed a logout ordering issue. Keycloak's
[revocation endpoint](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/protocol/oidc/endpoints/TokenRevocationEndpoint.java)
validates the session for both token types and removes it on refresh revocation.
Revoking refresh first can make the later access request return `invalid_token`.
The client now revokes access first, then refresh. It still attempts the second
request after a failure and requires both acknowledgements; HTTP 200 with an
error remains unconfirmed. No revocation policy or API bearer checks are relaxed.

## Evidence and acceptance boundaries

Focused tests cover the RFC example, random verifier size and attempt separation,
pending/slow-down/timeouts, cancellation generations, reflection canaries,
private-pipe transport, and absence of PKCE secrets from refresh/revocation.
The loopback TLS API fixture checks the actual device challenge/verifier binding
with both JSON and SQLite backends. Native Windows and Linux test receipts and
real-provider receipts are source-specific and handed off separately. Prior
failed attempts remain evidence for their original source, never later success.

The actual-provider procedure uses a disposable loopback-only Keycloak realm with
S256 required, a synthetic human, a trusted profile, real terminal subprocesses,
browser authorization, exact API claims, native per-user storage, scoped API reads,
rotating refresh, local logout/provider acknowledgement and explicit rejected
step-up cases. It does not establish production realm acceptance, stronger fresh
authentication, cross-user workstation isolation, immediate bearer revocation,
Windows domain/service-account provisioning or deployment accreditation. See
[operator setup and remaining limits](CLI_AUTH.md).

## Local acceptance receipt — 2026-11-06

The tested runtime revision is `9ec262566f1646a60fedbf102253d79ec5bdbdbc`,
including PKCE commit `3c40a49cd072084244d7f189855a52a7a7e19790` on reviewed base
`dd93db00b250d93515e52d816fe3063b9a33a1dc`. This receipt was added afterward as
a documentation-only change; results are attributed to that runtime revision.

| Focused run | Exact result |
| --- | --- |
| Windows, Python 3.12.10 | 147 passed, 1 skipped, 65 warnings in 240.64s |
| Native WSL Linux, Python 3.12.16 | 147 passed, 1 skipped, 65 warnings in 138.42s |

Both runs selected `tests/client`, the verified local-CLI bypass guard in
`tests/security/test_identity_boundary.py`, and `tests/engine/test_cli.py`, with
JSON and SQLite backends enabled. Windows skipped only the native Linux
symlink/mode test; Linux skipped only the native Windows inherited-DACL test.
Warnings were existing FastAPI/Starlette deprecations. The logout-order
regression first reproduced four failures before the fix; the targeted run
afterward passed all 39 selected tests.

Actual Keycloak 26.7.4 acceptance passed **19 of 19 checks** against the same
runtime revision using cached image ID
`sha256:3d911baa186f352563854039b95f21a7e2c01c76b527fdc64f24a0885b927bdf`.
The loopback fixture required S256 on its public human client. Real CLI terminal
subprocesses and browser login/consent established the API-verified human;
issuer, audience and authorized party matched the configuration. Scoped target
and finding reads excluded the other target. Refresh rotated both credentials
and preserved the authentication event. Empty accepted-ACR configuration,
unaccepted ACR and stale authentication each produced the expected HTTP 401.

Logout cleared the local session and changed its generation before networking.
Access revocation followed by refresh revocation each returned HTTP 200 without
an error; the CLI exited 0 with `provider_revocation: acknowledged`. A copied
unexpired JWT still received HTTP 200 from `/whoami`, confirming the documented
expiry limitation. Client processes constructed no `AppContext` or local node
state and sent no typed actor or browser cookie. The provider run used the real
Linux account-home token locator with private `0700`/`0600` storage, a unique
profile entry and no replacement of existing entries; it did not fake that locator.

All 786 selected source files matched the native copy before and after tests and
provider acceptance. The source-manifest SHA-256 is
`f18b6b53762457ae05f54dd94e5ef28413a2f86af67f075636b7332941ec7901`.
The final sanitized receipt is `keycloak-cli-pkce-attempt-5.json`; full focused
outputs and the manifest are retained with the separate local handoff. Owned
provider/API processes, temporary token files, CA/key/realm state and protected
browser profiles were removed. Source copies and sanitized evidence were retained.

Earlier receipts remain separate: the pre-PKCE failure, a browser selector
failure, the observed refresh-first logout failure, an interrupted harness setup,
and the diagnostic rerun. The diagnostic harness briefly compared source hashes
against a reused expectation variable; its original false comparison is retained
alongside an independent 785-file recheck showing no changes. The final harness
uses separate variables and passed its source comparison directly. No prior
receipt is relabeled as final acceptance. These are synthetic loopback results;
the deployment and identity limits above remain open.
