# Credential resolvers

The resolver adds explicit mounted-file and native Windows Credential Manager
password sources for account-bound SSH and WinRM. It introduces no runtime
dependency. Source definitions contain references, never password values.
Inventory and the access-policy schema are unchanged. Linux Secret Service,
Vault, CyberArk, broker renewals and private-key resolution remain open.

## Integration contract

`credential_ref` remains a bounded opaque alias, such as `READER`. It is not a
path, provider URL or instruction to search a keyring. A trusted server-side
registry maps it to exactly one source. No environment variable, inventory
option or missing provider silently activates a different backend.

```python
from cyberthunder.security.secret_resolver import MountedSecret, SecretResolver

resolver = SecretResolver(
    {"READER": MountedSecret("/etc/cyberthunder-credentials/reader", "password")},
    security_mode="fleet", auth_mode="oidc", lease_seconds=30,
)
use = resolver.bind(
    binding, principal=principal, target=current_target, purpose=action,
    guard=fresh_authorization, on_event=record_credential_event,
)
# AppContext performs this selection and the factory forwards the use object.
transport = make_transport(selected_target, settings, guard=fresh_authorization,
                           on_security_event=record_transport_event, credential_use=use)
```

`binding` is the immutable `CredentialBinding` returned by the existing
`AccessPolicy.credential` after account/action authorization. `selected_target`
comes from `bind_target`. The resolver verifies the principal, action, target
identity and target generation. Transports verify the selected username,
reference, endpoint and profile against the use object. A raw reference alone
does not authorize a lookup.

The caller's raising `guard` must retain the existing current-session check,
fresh role/resource/step-up authorization, inventory ownership and generation,
scope, kill/cancellation checks, and credential-policy comparison. It runs
before and after lookup and on value access. Existing transport guards still
run on operations using an authenticated connection. Do not replace that guard
with a callback that merely compares a cached principal or a boolean grant.

For a single direct use, `resolver.resolve(binding, principal=..., target=...,
purpose=..., guard=..., on_event=...)` returns a context manager. For transport
reuse, keep the reference-only `CredentialUse` and acquire `use.lease()` at
authentication. Neither object reads a secret when constructed.

### Application configuration and audit

Set optional `CT_CREDENTIAL_SOURCES` to the absolute path of a protected,
server-owned JSON registry. The application validates it before creating state
and reloads it before transport creation and every guarded operation. Only an
unset setting (`None`) enables legacy compatibility. Empty, missing, relative,
unsafe or invalid configured files refuse startup and use. Registry configuration
requires `CT_AUTH_MODE=oidc` or `mesh`; development identities cannot activate
these account-bound backends. `Settings.credential_sources` provides the same
programmatic setting. No runtime registry is created automatically.

Version 1 has exactly these top-level fields:

```json
{
  "version": 1,
  "sources": {
    "READER": {
      "provider": "mounted",
      "root": "/etc/cyberthunder-credentials/reader",
      "key": "password",
      "layout": "regular"
    }
  }
}
```

This is a documentation example, not a provisioned credential. `sources` must
contain 1–256 aliases; the complete UTF-8 file is limited to 256 KiB. Duplicate
keys at every level, unknown fields/providers, unsupported versions, invalid
types, non-JSON numeric constants, path expansion and escaping keys are refused.
The registry contains references only; inline password/token fields are invalid.
Each declaration has one exact provider:

| Provider | Required fields | Optional fields |
| --- | --- | --- |
| `mounted` | `provider`, absolute `root`, single-name `key` | `layout` (`regular` default or `kubernetes`), `reader_gid` (nonnegative integer only for Kubernetes) |
| `wincred` | `provider`, exact `target_name` described below | None |

There is no environment provider in the application JSON schema. The existing
unconfigured range environment path remains available; the development-only
`EnvironmentSecret` Python interface is separately restricted. Registry paths
must themselves be regular single-link files without symlink/reparse components,
even when a declared secret uses the opt-in Kubernetes projection layout.
POSIX registry files/ancestors require trusted ownership (root or the process
UID), no group/world writes, and stable identities through a held-descriptor
read. Registry contents may be readable by others because they contain only
references. Windows uses `file_trust.open_protected(private=False)` and its held
handle chain and native owner/DACL validation; chmod does not provision an ACL.
A Kubernetes registry should therefore be explicitly provisioned as a protected
regular file, not implicitly followed through a projected ConfigMap symlink.

`AppContext.transport_for` retains the original account selection, authorization,
current-session, inventory, scope, step-up and kill-switch checks. It binds the
selected alias to the resolver and passes `credential_use` through the factory
only to SSH/WinRM. Each guard reloads the protected registry and compares its
canonical JSON fingerprint and the captured settings. A mapping change, invalid
file, deletion, changed profile or removed setting invalidates the old use;
a fresh authorized transport can select a new valid mapping. JSON whitespace or
key ordering alone does not invalidate it. Secret-value rotation does not change
the registry fingerprint and is observed on the next lease.

`credential.use` records the actual selected backend (`mounted` or `wincred`)
and registry fingerprint, preserving the existing account-binding evidence.
`credential.resolve` and `credential.failed` persist in the audit chain under the
captured, still-current verified principal. The sink accepts only fixed event
actions/reasons, the bound target/purpose/backend, validated account/target/
reference fingerprints and a random lease ID. A switched principal or forged
metadata is refused; failures after revocation can still be attributed without
reauthorizing the failed operation. No alias, source path, native target name,
password or password hash enters these events. Audit failure refuses resolution.

Inventory policy, UI selection/execution provenance and other transports remain
outside this change. Fleet password aliases without a resolver are refused
before reading `CT_CRED_*`; there is no guessed broker or ambient fallback.
The selected target's existing `environment` source marker still identifies
its opaque password-reference shape; the separate `credential_use` is the
provider authority and audit source.

## Supported sources

| Source | Explicit declaration | Boundary |
| --- | --- | --- |
| Development environment | `EnvironmentSecret("LAB_READER")` | Reads only `CT_CRED_LAB_READER`. The new resolver accepts it only with `auth_mode="dev"`, `security_mode="range"`. |
| Regular mounted file | `MountedSecret(absolute_root, key)` | One protected regular private file, no links/reparse points or ambient path expansion. |
| Kubernetes projection | `MountedSecret(absolute_root, key, layout="kubernetes", reader_gid=dedicated_gid)` | Explicit Linux/POSIX projection handling; exact relative link layout, protected ancestors and private final value. Group access is optional and must be explicit. |
| Windows Credential Manager | `WindowsCredential(exact_target_name)` | Exact generic credential read under the current non-impersonated process logon; exact returned target and remote username must match. |

Aliases start with a letter, digit or underscore and contain at most 64 ASCII
letters, digits, underscores, dots or hyphens. The registry supports at most 256
entries. Mounted keys are single bounded names. Provider schemes such as
`vault:` or `keyring:` inside an inventory alias are rejected; they are not
interpreted as a fallback search.

Legacy `CT_CRED_<ref>` remains compatible with existing range development
transports. Existing verified-range legacy paths also remain unchanged; migrate
those to the registry explicitly. Fleet no longer resolves password references
from environment variables. Explicit SSH key paths and existing unbound
Kerberos configuration retain their previous policies; a bound WinRM account
continues to require explicit NTLM and never falls back to ambient Kerberos.
The new password resolver cannot be combined with an SSH key or agent.

## Mounted-file trust and Kubernetes projections

Regular mounts require absolute paths, trusted-owned ancestors, a regular
single-link leaf and a bounded nonempty UTF-8 value (maximum 16 KiB, no NUL).
Values are read exactly; trailing newlines are not stripped. No secret is copied
to a staging file. POSIX private files forbid every group/world permission bit;
ancestors must not be writable by other users. Only root-owned sticky ancestors
such as `/tmp` receive the usual safe directory exception.

On Windows, the existing `security/file_trust.py::open_protected(private=True)`
checks owner/DACLs and pins the complete handle chain, refuses reparse points,
remote/unverifiable filesystems and hardlinks, excludes concurrent file writers,
and rechecks identity and ACLs. POSIX mode bits are not presented as Windows ACL
evidence. On POSIX, descriptor-relative traversal uses `O_NOFOLLOW` on every
directory and leaf, checks owner/mode/type/link count/size, and compares file,
directory and pathname identity before returning any value. FIFOs are opened
nonblocking and rejected before reading. Changes during the read fail closed.

Kubernetes uses an atomic symlink projection strategy, as described in its
[projected-volume documentation](https://kubernetes.io/docs/concepts/storage/projected-volumes/).
The optional `kubernetes` layout accepts only this reviewed chain beneath the
configured root:

```text
password -> ..data/password
..data   -> ..<single-generation-name>
..<single-generation-name>/password  (regular, single-link private file)
```

The root and all ancestors are opened without following symlinks. Both link
owners and exact relative destinations are checked; absolute links, `..`
traversal, nested redirects, a redirected generation directory, hardlinks and
arbitrary symlinks are refused. The generation is opened by descriptor and all
link/descriptor identities are checked again after reading. Concurrent kubelet
rotation may refuse the operation; the next lease reads the new generation.
There is no retry that silently changes generations during one lookup.

A projection directory that is root-owned and proven read-only by `fstatvfs`
may have kubelet's writable directory mode bits. This exception applies only to
the explicitly selected projection root/generation, never arbitrary ancestors
or the secret leaf. World-readable values such as `0444` are always rejected.
An explicitly configured `reader_gid` may permit group-read only when the file's
GID equals that value and the process's primary GID. Administrators must reserve
that group for the intended application account; the resolver cannot prove
group exclusivity. Default Kubernetes `0644` mounts do not qualify. Provision
appropriate ownership/modes and read-only mounts; do not relax application
account-policy protections or add a trust-copying init container.

Tests create the real projection layout on a Linux-native filesystem. They do
not attest a live kubelet mount, CSI implementation, pod UID/GID or mount flags.
Those remain deployment acceptance requirements.

## Native Windows provisioning contract

Use `windows_target_name(binding, principal, target)` to obtain the exact
provisioning name. Its form is `CyberThunder/v1/<scope-sha256>/<alias>`. The
scope binds issuer, subject, operation, target endpoint/environment/generation
and remote username. Two subjects with the same display name have different
names; changing a target generation or using an apply credential for scan does
not select an old entry. Configure that exact name in `WindowsCredential`.

An administrator must provision a `CRED_TYPE_GENERIC` entry in the application's
intended Windows logon account with the exact remote username and a UTF-16LE
password blob without a terminating NUL. Only session persistence or local-machine
persistence is accepted; the latter is still the user's credential set on that
computer, not a shared all-user store. Enterprise/roaming entries, aliases,
unsupported attributes, malformed/oversized blobs and mismatched usernames are
refused. There is no enumeration, UI prompt, CredReadDomainCredentials, username
guessing, DPAPI file fallback or lookup in another logon account.

[Microsoft documents](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credreadw)
that `CredReadW` selects the current token's logon-session credential set. The
native helper rejects thread impersonation and compares process-token/logon
identity before and after the exact read. It frees the returned native buffer
on success and failure. It caches function bindings only, never credentials,
user SIDs or logon identities. Blob limits follow the
[CREDENTIALW contract](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw).

The automated tests substitute uniquely scoped fake CredRead buffers; the
Windows ABI check uses the real token APIs with CredRead/CredFree replaced.
No existing user credential is read, enumerated, written or deleted. Actual
provisioning under a service logon and native vault authentication remain live
acceptance work.

## Lifetime, failures and transport behavior

Leases are single-entry context managers with a configurable 1–60 second limit
(default 30 seconds), additionally bounded by principal expiry and the fresh
authorization callback. `Secret.reveal()` is usable only within an active lease.
`str`/`repr` redact; JSON and pickle serialization refuse the secret/lease.
Closing, expiration, cancellation or failed acquisition invalidates access and
clears the resolver-owned mutable buffer. This is not a secure zeroization
claim: Python strings/bytes, native APIs and authentication libraries may create
copies that cannot be reliably erased. Expiration is checked at use boundaries,
not by a background thread that forcibly destroys objects or remote work.

SSH leases a password only for connection authentication, leaves `_password`
unset on resolver-backed instances, disables implicit agent/key discovery and
retains every host-trust and operation guard. A cached authenticated SSH
connection uses those guards; rotation is picked up at the next connection.
WinRM uses a new NTLM session for each operation and closes it on every exit.
Its request timeouts are capped by the remaining lease, and protocol messages
recheck the lease/authorization before and after sending. These limits do not
promise forced cancellation of already executing remote commands.

Both transports retain strict fleet host/TLS checks and bounded probe guards.
Authentication failures emit `credential.failed` with fixed metadata and expose
fixed errors, never provider exception text. Values are passed to library
authentication APIs, never command arguments, environment additions, inventory,
audit payloads or source configuration. No new subprocess credential path is
introduced.

## Focused validation and compatibility migration

Run the new resolver, native-helper, filesystem and transport tests on both
document backends:

```sh
CT_STATE_BACKENDS=json,sqlite PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest \
  tests/security/test_secret_resolver.py tests/security/test_secret_mounts_posix.py \
  tests/security/test_wincred_resolver.py tests/security/test_secret_transport_integration.py \
  tests/security/test_credential_registry.py tests/transport tests/security/test_account_transports.py \
  -o addopts= -q --tb=short -p no:cacheprovider
```

Canaries are generated uniquely in disposable fixtures. Tests cover both
storage backends, real loopback SSH, fake WinRM/native credential buffers,
provider/callback error sanitation, expired/revoked/changed bindings, matching
display names, target-generation reuse, audit refusal, secret serialization,
rotation, wrong native users/targets/logons, path/link/mode/DACL attacks and
mid-read replacement. POSIX projection cases skip only on non-POSIX hosts;
native DACL/token-ABI cases skip only on non-Windows hosts.

The four former fleet-environment fixtures now preserve their intended range
source-exactness checks and explicit Kerberos configuration without requiring
fleet environment passwords. Separate fleet tests require a resolver before any
environment lookup. No compatibility failure is waived or converted to a skip.

The focused transport/account run passed on both document backends: Windows
Python 3.12.10: **379 passed, 44 skipped**; Linux Python 3.12.16:
**419 passed, 4 skipped**. Linux sources, pytest temporary files and execution
were on `/dev/sdd` ext4, not `/mnt/c`. Live service-logon provisioning, kubelet
mount ownership/read-only flags and real target authentication remain external
acceptance requirements; these tests never contact live targets.

After the final lease-cleanup change (observed expiry/revocation permanently
closes the lease and clears its buffer, even if caught inside the context), the
following affected checks passed again: **331 passed, zero skips on Windows**;
**327 passed, 4 Windows-only skips on Linux**. These include the existing account
binding and Kubernetes integration regressions. Counts are separate receipts,
not added totals; the runs overlap.

```sh
CT_STATE_BACKENDS=json,sqlite PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest \
  tests/security/test_secret_resolver.py tests/security/test_wincred_resolver.py \
  tests/security/test_secret_transport_integration.py tests/security/test_credential_registry.py \
  tests/security/test_credential_binding.py tests/security/test_kubernetes_account_integration.py \
  tests/transport/test_bound_accounts.py -o addopts= -q --tb=short -p no:cacheprovider
```

The focused runs did not invoke the full release gate. Parent CI integration
must add only the 44 Windows and 4 Linux node IDs below, with their exact reasons,
to `scripts/ci_pytest.py` and update its count regression. The existing allowlist
at this branch's base does not include these new modules. No broad module skip
or production-coverage waiver is needed.

### Exact platform skip receipts

These are platform-only tests, not waived failures. Every collected Windows
case capable of running on Windows executed; no unexpected skips occurred.
The Linux run executed every POSIX case skipped by Windows.

Windows: **44 skips**, exact reason `POSIX dir_fd, ownership, modes and Kubernetes projection layout`:

```text
tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[json-420]
tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[json-416]
tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[json-438]
tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[json-388]
tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[json-385]
tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[sqlite-420]
tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[sqlite-416]
tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[sqlite-438]
tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[sqlite-388]
tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[sqlite-385]
tests/security/test_secret_mounts_posix.py::test_untrusted_nodes_fail_before_read[json-writable_parent]
tests/security/test_secret_mounts_posix.py::test_untrusted_nodes_fail_before_read[json-fifo]
tests/security/test_secret_mounts_posix.py::test_untrusted_nodes_fail_before_read[json-foreign_owner]
tests/security/test_secret_mounts_posix.py::test_untrusted_nodes_fail_before_read[sqlite-writable_parent]
tests/security/test_secret_mounts_posix.py::test_untrusted_nodes_fail_before_read[sqlite-fifo]
tests/security/test_secret_mounts_posix.py::test_untrusted_nodes_fail_before_read[sqlite-foreign_owner]
tests/security/test_secret_mounts_posix.py::test_projection_requires_explicit_layout_and_accepts_atomic_rotation[json]
tests/security/test_secret_mounts_posix.py::test_projection_requires_explicit_layout_and_accepts_atomic_rotation[sqlite]
tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[json-absolute_data]
tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[json-escaping_data]
tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[json-escaping_key]
tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[json-generation_redirect]
tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[json-public_value]
tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[json-hardlink]
tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[sqlite-absolute_data]
tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[sqlite-escaping_data]
tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[sqlite-escaping_key]
tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[sqlite-generation_redirect]
tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[sqlite-public_value]
tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[sqlite-hardlink]
tests/security/test_secret_mounts_posix.py::test_reader_group_requires_explicit_matching_dedicated_gid[json]
tests/security/test_secret_mounts_posix.py::test_reader_group_requires_explicit_matching_dedicated_gid[sqlite]
tests/security/test_secret_mounts_posix.py::test_only_root_owned_readonly_projection_can_relax_directory_write_bits[True-True-0-True]
tests/security/test_secret_mounts_posix.py::test_only_root_owned_readonly_projection_can_relax_directory_write_bits[True-False-0-False]
tests/security/test_secret_mounts_posix.py::test_only_root_owned_readonly_projection_can_relax_directory_write_bits[False-True-0-False]
tests/security/test_secret_mounts_posix.py::test_only_root_owned_readonly_projection_can_relax_directory_write_bits[True-True-99999-False]
tests/security/test_secret_mounts_posix.py::test_midread_identity_changes_are_refused[json-replace_file]
tests/security/test_secret_mounts_posix.py::test_midread_identity_changes_are_refused[json-write_file]
tests/security/test_secret_mounts_posix.py::test_midread_identity_changes_are_refused[json-rotate_projection]
tests/security/test_secret_mounts_posix.py::test_midread_identity_changes_are_refused[json-replace_parent]
tests/security/test_secret_mounts_posix.py::test_midread_identity_changes_are_refused[sqlite-replace_file]
tests/security/test_secret_mounts_posix.py::test_midread_identity_changes_are_refused[sqlite-write_file]
tests/security/test_secret_mounts_posix.py::test_midread_identity_changes_are_refused[sqlite-rotate_projection]
tests/security/test_secret_mounts_posix.py::test_midread_identity_changes_are_refused[sqlite-replace_parent]
```

Linux: **2 skips**, exact reason `native Windows private-file DACL enforcement`:

```text
tests/security/test_secret_resolver.py::test_windows_world_readable_secret_fails_closed[json]
tests/security/test_secret_resolver.py::test_windows_world_readable_secret_fails_closed[sqlite]
```

Linux: **2 skips**, exact reason `native Windows token and CredReadW ABI with mocked credential data`:

```text
tests/security/test_wincred_resolver.py::test_native_windows_abi_and_current_logon_with_mocked_credread[json]
tests/security/test_wincred_resolver.py::test_native_windows_abi_and_current_logon_with_mocked_credread[sqlite]
```

### Windows provisioning and remaining acceptance

Provision the registry, secret files and ancestor directories under the intended
service account with native owner/DACL protection. The Windows trust helper
accepts the current process account and its explicit trusted system/administrator
owners; other principals must not be able to write, delete, replace, change ACLs
or change ownership through the file or its ancestors. A password file must also
exclude untrusted readers. Registry reference metadata may be readable by others.
Inherited permissive ACEs can therefore require an administrator to provision a
protected directory and restricted file DACLs. `chmod(0600)` is not Windows ACL
provisioning or evidence. The test harness creates and removes only its own
protected temporary directory and never modifies the user's credential store.

The account fixture blocks an unmocked native credential API before DLL/provider
lookup. Native tests install fake unique canary buffers; the ABI test patches
CredReadW/CredFree before reading while exercising the real process-token APIs.
No native credential entry was provisioned or accessed. Real service-logon vault
provisioning, deployed read-only projected mounts/UID/GID assignments, real
SSH/WinRM endpoints and operator UI execution provenance remain external
acceptance. Linux Secret Service, Vault and CyberArk are not implemented.
