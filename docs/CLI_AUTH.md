# Verified CLI access

`cyberthunder auth` signs a human into a configured verified API using OAuth
device authorization. `cyberthunder api` sends authenticated HTTPS requests to
that API. These commands do not construct local application state, read target
credentials, or contact targets. The server applies its existing roles, exact
account/group resource grants, original saved ownership, human approval,
separation of duties, assessment, scope, kill and step-up rules.

Legacy development commands remain available in development mode. Existing
verified-mode local-action restrictions remain in place. An explicit typed
`--actor` is rejected by the remote commands; `CT_ACTOR` is ignored. A transport
failure never falls back to a local operation.

## Provision the client and realm

Follow [Account access](ACCOUNT_ACCESS.md), [OIDC validation](OIDC_VALIDATION.md)
and [Browser identity](BROWSER_IDENTITY.md) for the server's identity and grant
configuration. This client adds no application Settings or dependencies.

Enable device authorization for the **same trusted public human client** already
accepted by the API's exact authorized-party check. Its issued access tokens must
have the existing API audience, issuer and client ID, signed human kind/roles,
and appropriate authentication-event claims. Do not weaken `azp`, accept another
audience, distribute a confidential client secret, or treat workload credentials
as human login. A confidential browser client or a provider that cannot enable
this public-client flow needs a separately reviewed deployment change.

Provision an integrity-protected JSON profile outside the checkout and node state.
All keys below are required; unknown keys are rejected. These reserved domains
are examples, not an installed realm or universal provider endpoint convention:

```json
{
  "version": 1,
  "api_base_url": "https://node.example/api/v1",
  "issuer": "https://id.example/realms/operators",
  "audience": "cyberthunder-api",
  "client_id": "cyberthunder-human",
  "device_authorization_endpoint": "https://id.example/realms/operators/protocol/openid-connect/auth/device",
  "token_endpoint": "https://id.example/realms/operators/protocol/openid-connect/token",
  "revocation_endpoint": "https://id.example/realms/operators/protocol/openid-connect/revoke",
  "verification_uri": "https://id.example/realms/operators/device",
  "scope": "openid profile",
  "ca_file": null
}
```

Use the provider's exact HTTPS URLs. All IdP URLs must share the issuer's host
and port. The API base ends in `/api/v1`. URL credentials, query strings,
fragments, redirects and arbitrary endpoint/header overrides are unsupported.
`ca_file` is null for platform trust, or an absolute path to protected public PEM
CA certificates. Private keys are rejected. An explicit CA bundle replaces
platform trust and must trust both configured services. Ambient proxies and
SSL override environment variables are not used.

The profile and optional CA are bounded, regular, single-link files with trusted
owners and protected ancestors. On Linux use an owned private directory and
mode `0600` for the profile. Public CA material may be readable but not writable
by other users. Symlinks, unsafe writable ancestors and POSIX ACLs are refused
rather than guessed safe. Windows uses the existing native owner SID, DACL,
reparse-point and pinned-handle checks; see
[Windows file trust](WINDOWS_FILE_TRUST.md). Existing permissions are never repaired.

`audience` and `client_id` bind the local cache and record deployment expectations.
The configured API verifier enforces the actual token claims. The client does
not decode an unsigned token or claim to discover the API's verifier configuration
from `/whoami`. Only that HTTPS API's verified human principal establishes the
account; an ID token is never sent to it as an API credential.

## Login and protected storage

The device flow always uses S256 PKCE. Configure the public client to require
S256 and enable device authorization; the provider must support PKCE on its
device endpoint. Each login generates a fresh 256-bit verifier, sends its SHA-256
challenge and `code_challenge_method=S256` to that endpoint, and sends the verifier
only during redemption. The verifier stays in memory and the HTTPS worker's
private input pipe; it is not stored with tokens or exposed as an option. Polls
reuse it only within that attempt. Rejection never retries without PKCE or with
`plain`. Keycloak 26.7.4 implements this device extension; support is not implied
by RFC 8628 alone. See [the contract and review boundaries](CLI_DEVICE_PKCE.md).

These examples use a Linux path. On Windows use an absolute protected profile
path, for example `C:/Users/operator/ClientProfiles/node.json`.

```sh
cyberthunder auth --profile /home/operator/.config/cyberthunder/node.json login
cyberthunder auth --profile /home/operator/.config/cyberthunder/node.json status
cyberthunder auth --profile /home/operator/.config/cyberthunder/node.json logout
```

Login requires an interactive input terminal and stderr terminal. It displays the
configured verification URL and user code there; authenticate at that URL and
authorize only the request you initiated. The device credential stays in memory.
The client ignores provider-supplied complete verification links, follows no
redirects and does not launch a browser. A pending grant is never reported as a
successful login. Polling honors the provider interval, adds five seconds on
`slow_down`, exponentially backs off after a request timeout, and stops at the
earlier of provider expiry and 15 minutes. Each HTTPS request has a bounded total
deadline and bounded headers/body. See [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html#section-3.5).

Tokens are stored only in the current OS user's dedicated directory:

| Platform | Location and checks |
| --- | --- |
| Linux | Account database home plus `.cyberthunder-client`; owned `0700` directory and `0600` token/lock files; descriptor-relative no-follow checks. |
| Windows | Native Local AppData known folder plus `CyberThunderClient`; private native DACL and trusted ownership required for directory, token and lock files. |

No token path override exists in the CLI. A missing leaf directory can be created;
an inherited Windows DACL that fails privacy checks requires operator provisioning
before use. No ACL, parent directory or service is changed automatically. Tokens
are not written to the repository, node state, application audit, argv or
environment. Files are permission-protected, not application-encrypted: protect
the workstation disk and backups, and exclude this directory from synchronization,
source archives and ordinary diagnostic bundles. The OS account, trusted system
administrators and memory compromise remain outside this file-isolation boundary.

Each profile, exact endpoints, trust bundle and OS user bind one active account.
Profile/CA edits select a new cache; logout with the original protected profile
before changing it. A changed profile does not erase an older cache automatically.
Logout/login is required to change account or authentication assurance.

An interprocess lock serializes refresh and API use. Refresh tokens must rotate;
a missing, reused or uncertain rotated token clears the local session. A persisted
refresh-in-progress marker prevents replay after a crash. Atomic publication,
flushes and logout generations prevent a concurrent login from restoring a cleared
session. Pending login checks that generation before each device-token redemption,
holding the store lock through the bounded request, API identity check and local
publication. Polling waits release the lock. A completed logout prevents further
redemption by that pending login. If another request holds the lock for more than
five seconds, logout returns a busy error; it has not cleared the session and must
be retried explicitly. An already issued device grant is not remotely cancelled by
this local tombstone. Crash recovery does not promise secure erasure of disk remnants or provider
revocation of a token issued just before a crash. See
[public-client refresh protections](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14).

`status` checks the API online without refreshing. It reports `online_verified`,
`expired`, or `logged_out`, or a structured error when verification is unavailable.
Normal API commands refresh near expiry when a refresh credential is available,
then verify the account again. Refresh cannot change issuer/subject or invent a
new `auth_time`, ACR or AMR. Clock rollback fails closed; correct the workstation
clock before logging in again. Access lifetimes above one hour are unsupported.
The saved clock watermark is an actual wall-clock observation. Session expiry
also advances with process-local monotonic elapsed time; clocks with different
tick resolution do not create a future saved watermark. A real backward wall or
monotonic step, or a saved wall observation ahead of the current clock, still
refuses use without a grace period. Existing future watermarks remain refused
until the system clock catches up; the client does not silently rewrite them.

## Read, scan and decide through the API

```sh
cyberthunder api --profile /home/operator/.config/cyberthunder/node.json targets list
cyberthunder api --profile /home/operator/.config/cyberthunder/node.json findings list --host alpha --limit 100
cyberthunder api --profile /home/operator/.config/cyberthunder/node.json findings show FINDING_ID
cyberthunder api --profile /home/operator/.config/cyberthunder/node.json scans start --target alpha --module check
cyberthunder api --profile /home/operator/.config/cyberthunder/node.json scans show SCAN_ID
cyberthunder api --profile /home/operator/.config/cyberthunder/node.json decisions list
cyberthunder api --profile /home/operator/.config/cyberthunder/node.json decisions show PROPOSAL_ID
cyberthunder api --profile /home/operator/.config/cyberthunder/node.json decisions plan PROPOSAL_ID
cyberthunder api --profile /home/operator/.config/cyberthunder/node.json decisions assess PROPOSAL_ID --static
cyberthunder api --profile /home/operator/.config/cyberthunder/node.json decisions approve PROPOSAL_ID --assessment-id ASSESSMENT_ID
cyberthunder api --profile /home/operator/.config/cyberthunder/node.json decisions apply PROPOSAL_ID
```

Replace uppercase IDs with returned IDs. Scan targets are explicit and repeatable;
there is no implicit scan-all option. Modules are `check` (default), `hunt` or
`cve`. `scans list`, `decisions deny`, `cancel`, `verify`, `rollback` and
`review-impact --assessment-id ASSESSMENT_ID` are also available. Assessment
requires an explicit `--static` or `--live`; `--live` requests server-side
collection and remains subject to its grants and guards.

Decision notes are hidden terminal input. For automation, `--stdin` reads at most
8 KiB of a JSON object containing `note` and, for approve only, `assessment_note`.
Individual notes are limited to 2,000 characters. Never put credentials in these
notes; they become decision evidence. No password, token, note, custom header,
force, actor or URL argument is supported. `review-impact` requires both an
assessment ID and a note. Approval can remain unassessed where the existing server
allows it, with the server recording that limitation. A supplied assessment must
be valid and bound to the proposal. See [Separation of duties](SEPARATION_OF_DUTIES.md).

All results use JSON stdout. Error messages omit provider descriptions, exception
text and echoed credentials while retaining safe HTTP status and bounded step-up
challenges. Known bearer strings are also redacted from challenge values; arbitrary
encoded or split representations from a malicious configured server are not a
general data-loss-prevention guarantee. Malformed options before `auth` or `api`
use the same safe error response as their subcommands. No mutating request is
automatically retried after an ambiguous failure.

| Exit | Meaning |
| --- | --- |
| `0` | Requested synchronous operation completed. For logout, inspect the separate provider acknowledgement field. |
| `2` | Local arguments, profile, storage, response validation or client failure. |
| `3` | Authentication required/rejected, expired login, or API authorization/state rejection; includes safe `http_status` when available. |
| `4` | Accepted **pending**, unavailable/uncertain transport, expired unfinished device authorization, or locally cleared logout with provider revocation unconfirmed. Inspect `status`/`error`. |
| `130` | Interrupted. No claim that an already accepted server operation was cancelled. |

**HTTP 202 and a successful partial quorum vote both exit 4: accepted pending,
not failure and not completed.** For example:

```json
{"status":"accepted_pending","http_status":202,"operation_id":"SCAN_ID","result":{"id":"SCAN_ID","status":"running"}}
```

A first CAT I approval may instead have HTTP 200 and proposal state `proposed`,
with the proposal ID in `operation_id`. Poll the corresponding `scans show` or
`decisions show`; do not blindly replay a write because its exit code is nonzero.
An uncertain network result may lack an operation ID even if the server accepted
the write; inspect the server's authorized lists before deciding what to do next.

## Fresh authentication and logout limits

An API 401 `insufficient_user_authentication` includes the real server challenge.
The client cannot satisfy it by changing a timestamp, refreshing an access token,
typing a name or setting an ACR. Logout and start a new device login that causes
**real IdP human authentication** with the server's required assurance. Device
grant has no standard `prompt`/`max_age`/ACR request mechanism in this slice. If
the provider reuses an old browser session, login may succeed for reads while the
risky action remains rejected. Configure the realm's device flow appropriately;
see [Step-up](STEP_UP.md). No assurance fabrication or automatic retry occurs.

Logout atomically clears local credentials before making bounded provider
revocation requests. Access revocation precedes refresh revocation, which can
remove the provider session needed to validate the access request. Both are
attempted even if the first fails; acknowledgement requires HTTP 200 without an
error from every attempted request. `local_cleared: true` is separate from
`provider_revocation: acknowledged|unconfirmed|not_needed`. A configured endpoint
is required if the provider issues a refresh token. A 200 response acknowledges
the revocation request; it does not prove immediate API rejection. See
[RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1).

**A copied, unexpired JWT can still be accepted by the API after local logout or
provider acknowledgement.** This API's bearer verifier does not consult the
browser session lease or a bearer revocation registry. Logout does not cancel
accepted jobs, close another browser's session, prove secure disk erasure or revoke
workstation copies. Immediate server-side bearer revocation, peer-OS-user live
acceptance, real realm/SSO/fresh-authentication acceptance, domain/service-account
Windows provisioning and deployment accreditation remain open ZT06 work.

## Implementation and evidence boundaries

`client/{config,files,store,http,auth,api,cli}.py` isolate non-secret provisioning,
native protected storage, bounded HTTPS, device/refresh lifecycle and the explicit
API command surface. `_http_worker.py` is a short isolated stdlib process with
credential input through a private pipe; it contains DNS/TLS/header/body blocking
under a parent deadline. The server's OIDC and policy modules are unchanged.

Focused tests use temporary protected files, native locks/DACLs or Linux modes,
signed fixture tokens and real loopback TLS to the actual verified API. They
exercise both JSON and SQLite policy/state backends, scoped resources, saved
ownership, approval quorum, step-up, kill guards, token rotation, concurrent
refresh, publication failures and the copied-JWT logout limitation. Platform-only
checks explicitly skip on the other OS. These fixtures are implementation evidence;
they do not attest a live IdP, live targets, multi-user workstation isolation or
production deployment. Exact run receipts are handed off separately.
