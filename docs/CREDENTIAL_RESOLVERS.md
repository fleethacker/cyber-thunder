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

The focused runs did not invoke the full release gate. Their platform skips are
the 44 Windows and 4 Linux node IDs below, with their exact reasons. The independent
review below adds two Windows-only cases, making six Linux skips for its run.
Parent CI integration owns the exact allowlist and count regression updates in
`scripts/ci_pytest.py`; this branch does not change that policy. No broad module
skip or production-coverage waiver is needed.

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

## Independent security review of 307328a

Review base: `307328a2c5713221659c1ef2a8c4d7fb13a3eefd`. The review branch is
`codex/credential-resolver-review`, created directly from that commit in the
`scope-recipes` worktree. The prior `codex/control-map-review` branch is preserved.
Review changes stay within the original 16-file diff; no access-policy V2,
person mapping, CLI token-store, global CI policy or backlog changes are included.

### Reproduced defects and fixes

| Severity | Reproduction at the reviewed base | Fix |
| --- | --- | --- |
| P2 | A guard that finished after lease or principal expiry could still reach the credential provider during acquisition, or return plaintext from `Secret.reveal()`. Eight JSON/SQLite cases failed. | Recheck principal expiry after the guard and the lease deadline after authorization returns. Failure permanently closes the lease and clears its buffer. |
| P2 | Cancellation in the caller's separate SSH probe guard during credential resolution was observed only after `SSHClient.connect`, allowing authentication first. Two cases failed. | Recheck both connection guards after resolution and refresh the remaining lease timeout before connecting. Preserve guard exceptions while sanitizing provider exceptions and releasing the password reference. |
| P2 | An interrupt from WinRM SDK session cleanup skipped removal of its known password/authentication references even though the resolver lease closed. Two cases failed. | Drop the provider password, encryption and HTTP authentication references in `finally`, retaining interrupt propagation. This is reference cleanup, not secure memory erasure. |

The SSH trust regression now triggers revocation when the mocked handshake
actually completes, rather than counting guard calls. An intermediate review
run exposed translation of a guard exception; the final fix preserves that
existing exception contract. No failure was waived or changed into a skip.

Additional review cases use real Windows token APIs to impersonate only the
test process's own identity, verify refusal before any CredRead call, and restore
the thread token in `finally`. CredRead/CredFree are replaced before the operation.
Separate fake-buffer cases verify native allocation release and sanitized errors
when reading, copying, or the post-read token check raises. All credential values
are unique disposable canaries; no user credential entry is accessed or changed.

### Review validation receipts

The review reruns the focused command above with JSON and SQLite. It adds 20
cases to the original 423-case selection. Windows Python 3.12.10: **399 passed,
44 skipped**; Linux Python 3.12.16: **437 passed, 6 skipped**. Both collect 443
cases with zero failures/errors. The exact machine-readable skip list and JUnit
receipts are retained with the handoff under `.build/credential-resolver-review-*`.

Linux source and permission fixtures run on `/dev/sdd` ext4 from a copied tree at
`/home/joshua/credential-resolver-review-307328a-e345f095`, using
`/home/joshua/cyber-thunder-linux-validation-20261105-f7018959/venv312/bin/python`.
`/mnt/c` is used only to transfer source archives and receipts. There are no live
target, vault, kubelet or broker checks. SSH integration uses disposable loopback
peers; WinRM uses fake sessions and the installed SDK with networking blocked.
The full release gate is separate from these review receipts.

Windows retains exactly the 44 node IDs and their reason in the original
platform receipt above. Linux retains the original four node IDs and reasons,
and adds only these two:

```text
tests/security/test_wincred_resolver.py::test_native_windows_rejects_thread_impersonation_before_credread[json]
tests/security/test_wincred_resolver.py::test_native_windows_rejects_thread_impersonation_before_credread[sqlite]
```

Their exact reason is `native Windows thread impersonation with mocked credential data`.
The handoff's skip list is generated from JUnit and contains every platform
node ID and reason, not a module-wide allowance.

### Interfaces and limits retained by the review

- `CT_CREDENTIAL_SOURCES` / `Settings.credential_sources` select the protected
  registry. `None` alone is unconfigured. Duplicate/unknown declarations, byte
  bounds, owner/handle trust, canonical fingerprints and fresh reloads remain
  fail-closed. A configured missing alias never falls back to the environment.
- `SecretResolver.bind` / `resolve`, `CredentialUse`, `Lease`, `Secret` and
  `windows_target_name` keep their existing signatures. Binding covers issuer,
  subject, action, target endpoint and generation; the raising guard owns fresh
  application authorization. A caller-created `Principal` or use object is not
  an authentication boundary against arbitrary code inside the process.
- `make_transport(..., credential_use=...)` forwards only to SSH/WinRM.
  `credential.use` records the actual backend and registry fingerprint;
  resolve/failure events retain bound allowlisted metadata. The selected target's
  legacy `environment` marker describes its alias shape, not its selected backend.
- Native Windows lookup uses the current process logon's credential set, with
  thread impersonation rejected. Application subjects do not each receive a
  separate Windows vault. Shared remote accounts are not eliminated by this
  resolver, and this review makes no zero-trust compliance claim.
- POSIX regular-file and opt-in Kubernetes projection checks cover descriptor
  traversal, links, ownership, modes and mid-read replacement. Real kubelet
  read-only flags, UID/GID provisioning and dedicated-group exclusivity remain
  deployment acceptance work. Windows requires native DACL protection.
- Lease deadlines are checked at use boundaries. They cannot forcibly interrupt
  a blocking callback or already executing remote operation. Python and SDK
  copies cannot be reliably zeroized. An authenticated SSH connection keeps
  operation guards and reads a rotated password on its next connection.
- Bounded dependency collection was outside the initial review and refused
  resolver-backed SSH/WinRM at `8367ed5`. The bounded follow-up below resolves
  that integration limit, preserving fresh guards and failure semantics.

Parent integration must retain the registry validation in `AppContext.__init__`
alongside independently developed callbacks, and retain transport forwarding,
registry reload guards and backend audit attribution. The parent CLI token
store and person/access-policy changes belong to their own contexts. No push,
live provisioning or additional work is part of this review handoff.

## Bounded dependency collection follow-up

This separate change starts from review commit `8367ed5`. It touches only
`remediation/dependencies_io.py`, narrowly required SSH/WinRM transport support,
dependency-reader tests and this document. Context, configuration, CLI token
stores, person mapping, access policy, CI policy and other workers' files are
outside the change.

`read_command` starts its absolute monotonic deadline before the initial
authorization callback. Scope, account, principal, kill and time checks surround
credential acquisition, connection, channel/protocol operations and output
acceptance. A slow guard or connection consumes the original allowance; neither
starts a fresh timeout. Nonpositive/nonfinite budgets are refused. The existing
64 KiB combined stdout/stderr limit remains, and malformed completion/exit status,
timeouts, nonzero exits, provider failures and cleanup failures return no
collected evidence. Public provider/permission errors are sanitized without
exception chaining. Kill signals and fixed host-trust failures retain their
control-flow semantics.

SSH now accepts an actual `CredentialUse` as its explicit credential source.
`connect_client(..., deadline=absolute_monotonic_time)` is the only added SSH
parameter; it checks the caller's guard during resolution and caps authentication
timeouts by the remaining budget. The password never moves into `_password` or
`_key`, implicit agent/key discovery stays disabled, and the connection is local
to the bounded read. Its lease closes after authentication; subsequent reads
continue to check account/principal authorization and the original read deadline.
A new bounded read creates a new connection and observes source rotation.

WinRM uses `bounded_reader(guard=..., deadline=..., cleanup_timeout=3)` to acquire
one operation lease and one newly constructed trusted session. It never falls
back from a resolver to legacy credentials and refuses a cached/injected session.
The private operation exposes only shell creation, command execution and single
receive-frame polling to the collector. Every collection send and its result
are guarded, with short HTTP connect/read timeouts capped by the remaining read
and lease budgets. Transport-wide timeout settings and `_session` are not reused
or mutated. The existing fleet TLS, endpoint and proxy restrictions still apply.

The operation saves the shell/command identifiers before the post-operation
authorization check, so revocation just after creation can still release those
exact resources. Cleanup permanently disables collection and has a separate
three-second budget for at most two SOAP sends: terminate the owned command and
delete the owned shell. The cleanup validator accepts only those actions, exact
resource IDs and expected SOAP bodies. Receive, new Command, foreign identifiers,
a missing/changed HTTP session or an exhausted budget are refused. Cleanup uses
the existing session without acquiring or revealing another credential; it can
run after scope, kill or lease revocation without authorizing more collection.
The HTTP session is then closed and known SDK password, encryption and HTTP-auth
references are dropped, including `Protocol.password`.

Cleanup failure invalidates an otherwise successful read. If collection already
failed or was cancelled, cleanup still runs and cannot replace the original kill
signal with an ordinary provider error. The dependency engine records failed or
uncertain reads as unknown/incomplete, without adding collected facts or edges.
An unacknowledged creation response may leave no usable remote resource ID;
session closure is still attempted, but remote cleanup is not asserted.

These bounds govern request admission, timeouts, accepted output and evidence.
They do not forcibly interrupt a blocking OS/SDK call, guarantee remote command
termination or bound every SDK-internal response allocation. Late responses and
failed cleanup are never accepted as evidence. Python/SDK copies are not claimed
to be securely zeroized, and live endpoint behavior remains deployment acceptance.

### Focused follow-up validation

Four calibrated tests failed on the pre-fix review commit, with exactly the
expected SSH `explicit_ssh_credential_required` and WinRM missing-operation-lease
refusals. Those same JSON/SQLite cases now verify success and source rotation.
Additional cases cover deadlines during initial/credential guards, connection
and reads; cancellation before authentication; principal/scope/account/generation
revocation; lease expiry; output limits; malformed and failed exits; sanitized
provider/permission errors; cleanup failure and timeout; and incomplete dependency
packets. Real installed WinRM SDK tests construct and parse SOAP with fake
responses, reject cleanup-time Receive/foreign IDs, and retain uncertainty for
unacknowledged shell creation. No remote endpoint or user vault is accessed.

```sh
CT_STATE_BACKENDS=json,sqlite PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest \
  tests/engine/test_dependencies_credentials.py tests/engine/test_dependencies_io.py \
  tests/engine/test_dependencies.py tests/security/test_secret_transport_integration.py \
  tests/security/test_credential_registry.py tests/transport \
  -o addopts= -q --tb=short -p no:cacheprovider --junitxml=RECEIPT.xml
```

Final JUnit, source hashes, counts and exact skip lists are retained in
`.build/dependency-resolver-*`. The final selection passed **528 tests, zero
skips, zero failures/errors on each platform**, including **118 cases** in the
new credential-reader module. Both JSON and SQLite execute. The exact skip
ID/reason list is `[]` on Windows and `[]` on Linux; this follow-up needs no new
platform allowances. Windows uses Python 3.12.10. Native Linux uses
Python 3.12.16 in `/home/joshua/dependency-resolver-followup-8367ed5` on ext4;
source/receipt transfer alone uses `/mnt/c`. These are focused receipts, separate
from the parent-owned full gate and CI allowances. No full gate or push is part
of this follow-up.

## Independent bounded-reader review

Reviewed follow-up `40537cec60d6e12a24bb2458863be0885d06caf1`, integrated as
`4535894`, from parent `ab10dfceb8a225900bb3d3b484ce97dbcc0db0e0`.

The installed pywinrm 0.5.0 and Requests stack exposed two gaps below the
previous tests' mocked `Transport.send_message` boundary. First, cancellation
during authenticated request preparation still allowed Create, Command or
Receive onto the wire. Requests-NTLM can also retry through the HTTP adapter
without reentering that method. Second, request preparation and the final
lease authorization check could consume the budget after the HTTP timeout had
already been calculated. Fourteen JSON/SQLite cases reproduced these defects
on the unchanged parent before the transport fix.

Bounded operations now guard the actual HTTP adapters before each send and
authentication retry. They recompute the timeout from the original absolute
deadline after the lease check, including time spent preparing the request.
The wrapper retains the fleet TLS adapter and its endpoint restrictions.
Creation responses are still parsed before the post-operation guard so known
owned identifiers remain available for cleanup after revocation.

Cleanup returns only the existing owned HTTP session, without invoking the SDK
session builder or acquiring another credential lease.
The existing SOAP action, body and identifier checks still restrict release to
the owned command and shell. Each release action admits at most one HTTP send;
an authentication retry during cleanup fails the read rather than extending
the two-request cleanup allowance. Cleanup deadlines are checked again after
request preparation. Failure, expiry or interruption cannot return collected
facts; known password, encryption and HTTP-auth references are still discarded.

Focused tests use the installed SDK, Requests and NTLM retry code with fake
HTTP-adapter responses. They cover fresh account, principal, scope, generation
and kill checks; late preparation; cleanup failure/interruption; collection
refusal after revocation; and refusal of cached or environment credentials
after a source becomes unavailable. The focused regression selection and exact
counts, skip lists, source hashes and calibrated failures are retained in
`.build/dependency-reader-review/receipts.json` and `handoff.md` in the review
worktree. These receipts are separate from the parent-owned final gate.

This review changes no OS permission, process, SSH or native credential-store
semantics. Native Linux validation was not repeated; the earlier follow-up's
528-pass Linux receipt remains historical evidence, not validation of this
patch. No live endpoint or vault was used. These checks cannot interrupt an
already executing SDK/OS call, prove remote termination, securely erase Python
copies, or isolate arbitrary code inside the process. Real deployed endpoints
and service-account provisioning remain acceptance work.
