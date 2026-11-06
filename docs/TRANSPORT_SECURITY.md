# Target transport security

This implements the transport portion of ZT-29, ZT-30, and the SSH implicit
credential restriction in ZT-20. It does not establish per-user target identity,
short-lived credentials, or overall zero-trust compliance. Application wiring
and external acceptance still have the dependencies listed below.

## Profiles and target options

`SSHTransport.from_target(target, settings)` and
`WinRMTransport.from_target(target, settings)` read
`getattr(settings, "security_mode", "range")`. The application owns the
`Settings.security_mode` field and `CT_SECURITY_MODE`. Only `range` and `fleet`
are accepted. Target options cannot downgrade the application profile.

Both transports also accept `security_mode=` when constructed directly.
Trust inputs use the existing `Target.options` dictionary; no inventory schema
change is required for these options.

| Transport option | Meaning |
| --- | --- |
| SSH `host_key_sha256` | One independently provisioned OpenSSH SHA256 fingerprint; padded or unpadded base64 accepted. |
| SSH `known_hosts` | Explicit path to a provisioned OpenSSH known_hosts file. Choose this or a fingerprint, not both. |
| SSH `key_file` | Explicit private key path; `credential_ref` may also name an existing key file. |
| SSH `allow_agent` | Boolean; only accepted when the caller also passes `interactive=True` to `from_target`. An inventory `interactive` option grants nothing. |
| WinRM `transport` | Unbound accounts default to `kerberos` in fleet and `ntlm` in range. Selected bound accounts require explicit `ntlm`; fleet still requires validated HTTPS. |
| WinRM `ssl` | Boolean; fleet defaults to HTTPS/5986 when no port is specified. Custom HTTPS ports require `ssl: true`. |
| WinRM `cert_validation` | `validate` or `ignore`; fleet accepts only `validate`. |
| WinRM `ca_trust_path` | Explicit PEM CA bundle, required in fleet. Directories, empty/missing files, leaf-only certificates, and `legacy_requests` are rejected. |
| Both `allow_insecure_range` | Boolean, default false. Explicit acknowledgement of insecure range operation; never overrides fleet policy. |

Trust files must be regular files no larger than 1 MiB. Provision and protect
them using the runtime service account's file permissions. The service account
must not be able to substitute arbitrary trust roots through untrusted input.
Provisioning, ownership/ACL policy, rotation approval, and revocation are
application/deployment responsibilities.

Example fleet SSH target options:

```yaml
options:
  known_hosts: /etc/cyberthunder/ssh_known_hosts
  key_file: /run/cyberthunder/target_key
```

For a non-default SSH port, the known_hosts entry must bind the exact endpoint,
for example `[host.example]:2222`. Hashed host names are supported. Do not
promote a key observed over an untrusted connection into approved trust
material without independent verification. Host CA/certificate authorization
and known_hosts `@cert-authority`/`@revoked` semantics are not implemented.

Example fleet WinRM target options:

```yaml
options:
  transport: kerberos
  ssl: true
  cert_validation: validate
  ca_trust_path: /etc/cyberthunder/enclave-ca.pem
```

## Enforcement

Fleet SSH requires a pin or explicitly provisioned known_hosts. It never loads
the process user's default known_hosts and never auto-adds or writes a key.
Paramiko checks the host key before authentication. A pin mismatch or changed
known_hosts key stops authentication and emits a high-severity
`discovery:identity_changed` event. A missing endpoint in known_hosts is refused
before opening a network connection. A malformed pin or absent trust source is
also refused. A configured trust mismatch is never rescued by the range flag.

SSH always passes `look_for_keys=False`; `allow_agent=False` is the default in
both modes. An explicit key path does not enable other key discovery. A caller
may authorize an agent only for an explicit interactive invocation. No password,
key path, or authorized interactive agent means failure before connection.
Private key paths and passwords stay out of security events and error text.
Passwords still resolve only through `CT_CRED_<credential_ref>`, never through
a bare environment variable name.

Fleet WinRM refuses HTTP, port 5985 (including an HTTPS declaration on that
port), disabled certificate validation, Basic, and CredSSP before constructing
a network session. It requires usable CA certificates and defaults to Kerberos;
missing Kerberos support fails without an NTLM fallback. Kerberos delegation
is disabled and channel binding remains enabled.

The actual pywinrm requests session is constrained to the original HTTPS
endpoint, with TLS 1.2 or newer, only the explicit CA material, and DNS/IP SAN
matching. Common-name-only certificates are rejected. No separate preflight
socket is used as trust evidence. Environment proxies, `.netrc`, and CA bundle
overrides cannot replace the fleet session settings. Redirects are rejected
before following them, including redirects to HTTP. A direct protocol call
through this session still receives the same TLS restrictions and failure event.

Range can use an unpinned SSH host, HTTP WinRM, ignored certificate validation,
Basic, or CredSSP only with `allow_insecure_range: true`. These exceptions emit
fixed warning messages and structured events explicitly marked `verified=False`.
They are never described as verified device identities. Secure range SSH using
a pin/known_hosts and validated HTTPS with NTLM/Kerberos need no exception flag.
The default range WinRM port/auth declarations remain 5985/NTLM, but starting an
insecure connection now requires the explicit acknowledgement.

## Selected account bindings

The account-selection helper supplies a detached target with
`credential_bound: true`, `credential_source: environment | key_file`, and
`allow_agent: false`, `look_for_keys: false`, `interactive_auth: false`.
SSH/WinRM validate these declarations and require an explicit username. The
marker alone does not prove authorization; the parent must select the account
through its policy and retain fresh principal/target checks.

Bound SSH honors the source exactly. `environment` reads only
`CT_CRED_<credential_ref>` and never checks whether the reference names an
existing local file. A missing or empty selected variable fails without trying
that file or an agent. `key_file` requires an explicit absolute
`options.key_file` with no competing `credential_ref` and performs no shell,
environment, or home-directory expansion. Conflicting or unknown sources fail
closed. An interactive invocation cannot enable ambient authentication for a
bound account. Unbound targets retain their documented legacy resolution order.

For bound SSH accounts, `target.sudo: false` rejects `sudo=True` requests in
`run`, `check_output`, and `write_file` before connection or remote staging.
After an SFTP permission error, `read_file` checks the same bound permission
before invoking its internal sudo fallback. The original internal authorization
callback still runs; an application wrapper on public instance methods is not
the only enforcement point. Accounts explicitly granted sudo keep the fallback,
and ordinary operations without sudo remain available. This controls transport
elevation requests; the selected remote account's actual OS privileges remain
the deployment's responsibility.

Bound WinRM requires `credential_source: environment`, `transport: ntlm`, and
`target.sudo: false`. Missing selected secrets, a competing key file, another
authentication transport, or absent explicit NTLM are refused. The fleet
Kerberos default applies only to unbound connections and cannot provide ambient
authentication for a bound account. Fleet NTLM remains subject to all HTTPS,
CA, and DNS/IP validation requirements.

Bound-account validation passed **87 focused tests** in 1.54 s using the shared
runtime and checkout-specific `PYTHONPATH`:

```powershell
& 'C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe' -m pytest -o addopts='' -q tests/transport/test_bound_accounts.py tests/transport/test_factory.py tests/transport/test_trust_guards.py tests/windows/test_winrm_transport.py tests/engine/test_dependencies_io.py::test_ssh_fixed_credentials_bounded_reads_and_guard tests/test_audit_and_control.py::TestSSHCredentialRef
```

Three additional in-memory interoperability checks loaded the actual account
helper from commit `9effc98` and exercised `bind_target` followed by the transport
factory for SSH environment, SSH key-file, and WinRM environment bindings. The
environment case included an existing same-name local file. These checks opened
no network connections and did not modify the helper or parent-owned files.

## Guard and event interfaces for parent integration

Both `from_target` methods and constructors accept `guard=` and
`on_security_event=` keyword arguments. `guard` is a no-argument callback owned
by the application, which must recheck scope, the kill switch, connection
identity, and any applicable authorization. Guards run on every public remote
operation, including cached connections. SSH shell channels keep the callback
on subsequent channel calls; WinRM file writes recheck between chunks. Guard
exceptions are preserved. Closing a session/channel remains possible after
revocation. The callbacks do not themselves create an authenticated principal.

The factory now exposes
`make_transport(target, settings=None, *, guard=None, on_security_event=None)`.
It forwards settings and these per-instance callbacks to SSH/WinRM construction;
it does not change adapter construction for other transport kinds. The parent
must continue to guard those kinds in its application authorization wrapper.
Bind the operation's actor and target in callback closures using
`AppContext.authorize(action, actor=actor, target=target)` and the existing fresh
scope/kill checks. Transport policy does not infer an actor from `auth_mode` and
does not store a principal in a mutable global.

`SecurityEvent` in `transport/trust.py` is immutable and exposes
`code`, `severity`, `message`, `verified=False`, and `to_dict()`. Each transport
retains emitted events in `security_events` and logs the fixed code/message.
The callback receives a `SecurityEvent` and must associate it with the inventory
target and current authenticated principal using a closure. Events contain no
target-controlled strings, credentials, command output, certificate PEM, or
private key material. Duplicate events are suppressed only after successful
delivery within one transport instance. A failed sink raises a sanitized
`transport:event_sink_failed` error; a retry must retry delivery and cannot
bypass the failure.

| Event code | Severity | Parent persistence requirement |
| --- | --- | --- |
| `discovery:identity_changed` | high | Open/update the target's identity-change finding and append an audit event before any authentication retry. |
| `transport:unknown_host_key` | high | Record the refused endpoint trust lookup; require explicit provisioning. |
| `transport:tls_failed` | high | Record a TLS trust/handshake failure; do not mislabel all TLS errors as a confirmed key change. |
| `transport:ssh_unverified` | medium | Keep a target warning finding for unverified range SSH and record the range exception. |
| `transport:winrm_http` | medium | Keep a warning finding for range WinRM without TLS server verification. |
| `transport:winrm_cert_unverified` | medium | Keep a warning finding for ignored certificate validation. |
| `transport:winrm_legacy_auth` | medium | Keep a warning finding for Basic/CredSSP range authentication. |

`TrustError` extends `TransportError` with a fixed `code`. Configuration refusals
can occur before the transport exists; the parent must catch these at factory
creation to record a sanitized refusal. Do not stringify underlying library
exceptions or persist exception contexts. Normal command results remain data;
transport-generated error text and `check_output` failures omit command text and
remote stdout/stderr.

Completed integration seams:

- `transport/base.py:make_transport` forwards the parent-owned settings to both
  transport constructors. Fleet policy holds regardless of `auth_mode`
  (`dev`, `oidc`, or `mesh`), and target options cannot downgrade it.
- `remediation/dependencies_io.py:_ssh` now uses
  `transport.connect_client(timeout=min(3, timeout), guard=guard, allow_agent=False)`.
  The collector in `remediation/dependencies.py` already delegates to this helper
  and needs no connector change. The helper keeps explicit credentials, deadline
  accounting, bounded channel reads, output limits, scope/kill checks, and
  channel/client cleanup. It also checks both the transport authorization callback
  and the dependency callback while polling. Even an interactive transport cannot
  use its agent for a dependency probe. No general command-recording, file-write,
  or remediation path is used.

Remaining parent integration requests:

1. In the application transport construction path, pass fresh authorization
   `guard` and durable `on_security_event` callbacks. Persist the above findings
   and audit events with the target/principal context. Add application tests
   proving a range warning appears and a changed-key finding/audit survives the
   failed operation. Local logger output is not a durable audit substitute.
2. Make discovery/acceptance record an observed fingerprint separately from an
   approved pin, require independent verification/authorization for acceptance,
   and bind target identity/options into any existing change/rollback guards.
   No discovery schema or UI changes are included here.

## Validation and acceptance boundaries

The new tests use ephemeral servers bound only to `127.0.0.1`, generated keys
and certificates in pytest temporary directories, and bounded thread cleanup.
No live Windows, Linux, Cisco, Navy, or external target was contacted.

| Acceptance area | Evidence in this change | Still required |
| --- | --- | --- |
| SSH pinned/provisioned trust | Real successful Paramiko handshake and command; plain and hashed known_hosts. | Authorized target provisioning and rotation workflow. |
| Changed/unknown SSH key | Real changed-pin and changed-known_hosts failures with zero server authentication attempts; unknown endpoint refused before connect. Sanitized high-severity events asserted. | Durable finding/audit integration; discovery acceptance binding. |
| No implicit SSH identity | Recorded Paramiko connect arguments for password, explicit key, and explicitly authorized interactive agent; no-credential failure before client creation. | Broader ZT-20 subprocess/kubeconfig work is outside this assignment. |
| Fleet WinRM policy | Pre-session refusals for HTTP/5985, ignore, Basic/CredSSP, absent or invalid CA material; settings forwarded by the factory. | Deployed inventory migration. |
| Actual WinRM TLS path | Real pywinrm/requests HTTPS exchange with correct DNS and IP SAN; untrusted, expired, wrong-DNS/IP, DNS-only-for-IP, and CN-only certificates fail with zero HTTP requests. | Real domain authentication/WinRM SOAP execution and deployment CA policy. |
| Range exceptions | Explicitly acknowledged real loopback HTTP and ignored-certificate HTTPS exchanges; structured unverified warnings. | Persistent target warning findings in the application. |
| Redirects/environment | Real HTTP downgrade redirect refused; environment proxy/CA settings cannot replace fleet trust; another endpoint is refused before a socket opens. | Deployment egress policy is separate. |
| Guards/error handling | Negative tests cover cached operation revocation, shell I/O, chunked write revocation, failed event-sink retries, sanitized error text/tracebacks, and nonzero-command errors. | Parent must supply the fresh guard and principal-bound event sink everywhere. |

The loopback HTTPS peer does not implement a Windows domain, NTLM negotiation,
or a full WinRM SOAP service. Success proves the actual HTTP/TLS transport path,
not successful Kerberos or Windows authorization. Kerberos-unavailable behavior
is tested explicitly without fallback. SSH tests exercise real password
authentication but do not prove SSH user certificate/CA issuance, PIV, or TACACS+.
No certificate revocation service or organizational trust approval is simulated
as completed acceptance.

Run from this checkout with the shared interpreter and checkout-specific import
path (PowerShell):

```powershell
$env:PYTHONPATH = 'C:/Users/joshu/.codex/worktrees/transport-trust/cyber-thunder'
& 'C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe' -m pytest -o addopts='' -q tests/transport tests/windows/test_winrm_transport.py
& 'C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe' -m pytest -o addopts='' -q tests/engine/test_dependencies_io.py tests/api/test_host_scope_review.py tests/test_audit_and_control.py tests/cisco/test_adapter.py
```

Recorded on 2026-11-05: the transport command passed **114 tests** in 17.05 s;
the affected-caller command passed **165 tests** in 59.48 s, with 73 existing
FastAPI/Starlette deprecation warnings. `git diff --check` passed. These are
focused Windows/shared-runtime results, not the full integrated gate.

For the factory/dependency integration commit, repeat only affected checks:

```powershell
& 'C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe' -m pytest -o addopts='' -q tests/transport/test_factory.py tests/engine/test_dependencies_io.py tests/engine/test_dependencies.py tests/transport/test_ssh_trust.py::test_no_implicit_keys_and_agent_only_explicit_interactive tests/transport/test_ssh_trust.py::test_no_credential_fails_before_network tests/transport/test_ssh_trust.py::test_guard_failure_after_handshake_closes_client_without_translation tests/transport/test_ssh_trust.py::test_connector_agent_override_cannot_grant_interactive_access tests/transport/test_ssh_trust.py::test_connector_combines_transport_authorization_with_probe_guard
```

These added checks use protocol fixtures, not new live handshakes: factory
fleet refusal/defaults and isolated callbacks; dependency pin mismatch,
unknown/changed known_hosts rejection before simulated authentication; forced
agent disablement; cancellation/deadline/resource cleanup and output limits;
transport authorization revocation during connection and dependency reads.

The integration command passed **158 tests** in 33.13 s. A final check before
returning SSH evidence was then added so authorization revoked during the last
read cannot return evidence. Its affected regression command passed **17 tests**
(21 deselected) in 2.34 s:

```powershell
& 'C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe' -m pytest -o addopts='' -q tests/engine/test_dependencies_io.py -k 'ssh or dependency_probe'
```

The original real-handshake regression results above were retained without
repeating those handshakes for this integration-only change.

The existing fake WinRM transport factory now explicitly acknowledges its range
exception. Unrelated range declaration/credential tests retain their previous
behavior. No UI or central documentation files are changed. The parent owns
the complete Windows/Linux integration gates after wiring these interfaces.

## Dependencies

No new core package is introduced. Validation used Paramiko 5.1.0, pywinrm
0.5.0, Requests 2.34.2, and cryptography 50.0.2 in the shared environment.
`cryptography` generates test certificates and already comes with Paramiko.
Fleet Kerberos deployment additionally needs the optional `pywinrm[kerberos]`
support (`requests-kerberos` and its platform GSSAPI/Kerberos dependencies), a
working ticket cache/service identity, SPNs, DNS, synchronized clocks, and an
authorized domain/realm. These were not installed or domain-tested here;
dependency pinning and offline vendoring belong to the parent.

Primary implementation references:
[Paramiko client host-key and credential controls](https://docs.paramiko.org/en/stable/api/client.html)
and [pywinrm authentication and HTTPS guidance](https://github.com/diyan/pywinrm).
