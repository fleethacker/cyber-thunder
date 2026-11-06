# Independent verified CLI review

Reviewed implementation commits:

- `9d4771396cc3b3a5c8fbb73d28a12f189a2a0afa`
- `b3cfa361e57046106cbc733587fc4b65c381f077`

This review covers the client modules, their narrow root-command dispatch, protected
credential files, device authorization, refresh/logout serialization, HTTPS and
diagnostics. It does not change the server verifier, resource policy, person mapping,
node-hardening permissions or application configuration.

## Reproduced findings

| Finding | Reproduction and correction |
| --- | --- |
| Credential reflection in an error | A schema-valid HTTP 401 challenge containing the opaque fixture bearer in an ACR value reached the public error from login, status, access verification and a mutation. Successful response redaction did not cover exceptions. Error construction now redacts the caller's known credential while retaining validated reason, status and challenge fields. This tests raw credential reflection; it does not claim to detect arbitrary encodings or fragments. |
| Root argument error escaped sanitization | An unsupported option/value before `auth` or `api` caused the root parser to echo the value as an invalid command. Root parse errors for client invocations now use the same fixed structured error as their subparsers. Actual handler selection still controls dispatch; the legacy verified-mode guard is unchanged. |
| Cancelled device login still redeemed a grant | After another process completed logout, a pending login made a token request and a `/whoami` request before noticing the changed generation at publication. The old implementation did prevent cache restoration. Generation checks now precede redemption, and the lock covers each bounded request, verification and publication. Waiting between polls releases it. A two-process regression verifies zero token/API requests after completed logout. |
| Empty URL userinfo accepted | `https://@host/...` and `https://:@host/...` passed truthiness checks. Profile validation and the isolated HTTPS worker now reject any userinfo component, including an empty one. |
| Numeric JSON overflow accepted | JSON exponent overflow produced a non-finite float despite rejection of literal NaN/Infinity. The bounded decoder now rejects non-finite parsed numbers. |

The initial independent harness reproduced 17 failing cases on both native Windows
and native Linux, with seven passing controls. The final harness adds 26 cases,
including native OS-identity binding, failed refresh publication and no mutation
replay. Test fixtures explicitly reject accidental use of the real default token
store. Every child process in the review receives an isolated fixture path.

## Trust and protocol assessment

The configured API is the identity authority. Real signed fixture tokens with a
wrong issuer, audience or authorized party are rejected by its unchanged verifier;
workload tokens cannot establish a human client session. The client independently
checks the reported human kind, verification flags, exact issuer, canonical actor,
subject and expiry. It does not derive authority from an unsigned JWT or send an
ID token as an API credential. Profile audience/client values bind provisioning and
cache selection; `/whoami` does not attest the API's configured audience/client ID.
Operators must keep that server configuration aligned. A second workstation JWT
verifier was not added.

One protected profile fixes the HTTPS API origin, issuer and same-origin IdP
endpoints. No provider-selected verification link, redirected credential request,
ambient proxy, ambient TLS override, arbitrary request URL or header override is
used. Existing native loopback TLS tests cover wrong certificates, redirects,
header/body limits and deadlines. Child requests receive credentials only through
their input pipe, with a minimal environment and no secret command-line arguments.

Device polling retains the required interval, five-second slowdown increments and
timeout backoff, and stops at the earlier provider/local deadline. These are the
behaviors checked against [RFC 8628 section 3.5](https://www.rfc-editor.org/rfc/rfc8628.html#section-3.5).
This grant has no client callback in this implementation; it does not substitute
for the browser code flow's nonce/PKCE protections. User-code phishing and the
provider's confirmation UI still require deployment acceptance.

Refresh requires a changed credential and preserves the original account and
authentication-event fields. A persisted in-progress marker makes an interrupted
refresh require a new login. Failure to publish the rotated credential, even when
the subsequent local clear also fails, does not redeem the old refresh credential
on restart. The native store lock and generation checks serialize processes.
These client checks support the public-client rotation requirements in
[RFC 9700 section 4.14](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14).
They do not prove that a real provider invalidates old refresh credentials, detects
family replay or binds grants correctly; that needs separate provider acceptance.

The API continues to enforce scopes, immutable ownership, human decisions, quorum,
assessment, kill and step-up policy. Pending results remain distinguishable from
completion. Mutation requests are never replayed automatically after rejection,
timeouts or ambiguous transport errors. Refresh cannot manufacture fresh
`auth_time`, accepted ACR or changed account identity.

## Native storage and integration boundaries

Linux uses effective-UID binding, the account database's home directory, pinned
directory descriptors and private modes. Windows uses the native known folder,
current-user SID, protected DACLs and the existing file-trust checks. Root creation
and temporary-file checks precede writing token bytes. Symlinks, hardlinks,
unsupported ACLs and untrusted read grants fail closed. Tests exercise native OS
mechanisms on each platform; changing actor/home environment text does not change
the credential record's OS-user binding.

The parent node-hardening exemption is absent from the implementation base. This
review's root CLI diff is confined to parsing/client dispatch above `Settings`
construction. Integration must preserve the parent's existing exemption in the
later verified-mode guard. No guard exemption is introduced by this review.

The existing concurrent-read integration case assumed both callers would always
acquire the lock within five seconds. Native Windows reproduced `client_store_busy`
while the first caller performed a rotating refresh and HTTPS checks. The test now
allows only that documented local refusal and explicitly issues a later read after
both callers finish. It still requires one refresh total and successful verified
results for both callers. A separate native-lock regression verifies that a busy
mutating caller sends no refresh or API request. Production retries and timeouts
are unchanged.

The real TLS-stall test also assumed a six-second total although the configured
parent request limit is ten seconds. Windows returned the expected timeout error
after 6.16 seconds including worker/TLS startup. Its assertion now follows the
configured limit with a two-second process-start allowance. The production socket
and request deadlines are unchanged.

## Evidence and open acceptance

The unchanged Windows client baseline passed 98 cases with one expected Linux-only
skip. Independent reproduction logs and final focused results are recorded
separately for native Windows Python 3.12.10 and native Linux Python 3.12.16 in the
local review receipt, including source hashes and exact skip IDs/reasons. Linux
uses copied source on its native filesystem, not Windows file semantics. Focused
signed-token/API tests run against both JSON and SQLite. No full gate is claimed.

Final selection: `tests/client`,
`tests/security/test_identity_boundary.py::test_local_cli_cannot_bypass_verified_mode`
and `tests/engine/test_cli.py`.

| Platform | Final result |
| --- | --- |
| Native Windows Python 3.12.10 | 129 passed, 1 skipped, 65 warnings; 220.11 seconds |
| Native Linux Python 3.12.16 | 129 passed, 1 skipped, 65 warnings; 112.69 seconds |

Windows skips
`tests/client/test_storage_config.py::test_linux_symlink_and_unsafe_parent`
because it requires native Linux symlink and mode checks. Linux skips
`tests/client/test_storage_config.py::test_windows_inherited_public_read_never_receives_token_bytes`
because it requires native Windows inherited DACL privacy. Both final runs have
zero failures/errors. Twenty reviewed source/test hashes match between platforms.
The local receipt retains the earlier failing and terminated diagnostic attempts;
they are not counted as successful runs.

Immediate server-side bearer revocation remains absent: a copied unexpired access
token may survive local logout or provider acknowledgement. Logout does not cancel
accepted jobs, another browser session or a remotely issued pending device grant.
Lock contention may produce an explicit busy refusal instead of a completed logout.
Changing a profile or CA selects another cache and does not revoke the old one.
Same-OS-user compromise, privileged storage rollback, disk remanence, peer-user
workstation acceptance, hardware custody, live realm freshness and enclave
deployment acceptance remain outside this fixture review. Actual loopback provider
acceptance is a separate activity; these results do not claim CAC/PIV assurance or
general standards/deployment compliance.
