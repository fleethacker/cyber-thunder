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
