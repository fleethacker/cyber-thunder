# Selected SSH private keys

An SSH account selected by access policy can use an explicitly provisioned
`options.key_file` with its own username and sudo permission. Account/action
selection and revocation remain in the existing access-policy and transport
guards. A scan grant does not acquire an apply grant's key or sudo permission.
Inventory credentials, an environment password, an agent, and discovered home
directory keys cannot supplement a selected key.

## Loading contract

Every new key-authenticated connection reads the selected file through the
regular mounted-secret reader in `security/secret_resolver.py`, with
`private=True` and a 32 KiB maximum. The SSH loader does not define another
ownership or permissions policy:

- Windows uses `security/file_trust.py` for native owner SID, DACL, volume,
  ancestor and handle checks. Foreign data read/write, delete, ownership and
  DACL modification rights are rejected. Reparse points and hardlinks are
  rejected. Held handles prevent file writes and replacement; DACL and identity
  checks run again before the reader releases the bytes. The trusted SID set is
  the process user, SYSTEM, Administrators and TrustedInstaller.
- POSIX uses the mounted-secret reader's descriptor-relative traversal with
  `O_NOFOLLOW`, `O_NONBLOCK`, regular-file and single-link checks. Owner must be
  root or the effective user; private files must have no group/other permission
  bits. Ancestors must satisfy the existing trusted-directory rule, including
  its root-owned sticky-directory exception. File identity, size, timestamps,
  permissions and the held ancestor chain are rechecked after the bounded read.
- The native absolute path must satisfy the shared mounted-source path rules.
  The basename starts with an ASCII letter, digit or underscore, followed by
  up to 252 ASCII letters, digits, underscores, dots or hyphens. Parent traversal,
  network aliases and expansion syntax are unavailable. An unavailable native
  trust API fails closed. The application never changes an operator file's ACL
  or permissions to make it acceptable.

The parser consumes only the returned snapshot, using in-memory streams. It
supports the provider's unencrypted RSA and ECDSA PEM/OpenSSH keys and Ed25519
OpenSSH keys; older providers' existing DSS parser is used only if present.
Paramiko receives `pkey` and no filename. It cannot reopen a replaced file or
automatically load an adjacent `-cert.pub` file. Replacement after a completed
checked read cannot change that connection's key; the next connection performs
a fresh read. Replacement or mutation detected during the read rejects the
connection. No password or passphrase is supplied to the parser.

Authorization and deadline checks run before and after loading and after
connection. Host pins and provisioned known-hosts verification retain their
existing behavior. The private-key reference held by Paramiko's authentication
handler is dropped after the authentication attempt, including failure.

An unsafe, unavailable, malformed, oversized or encrypted key fails before
network connection with `transport:ssh_key_unavailable` and the fixed message
`SSH private key is unavailable or unsafe`. Provider exceptions, paths and key
contents are excluded from that diagnostic. Raw key bytes and parsed private
keys are not added to inventory, audit events, application state or model input.
Audit continues to describe the selected account and action through existing
credential-use evidence. Explicit key-plus-password authentication is rejected;
an explicitly selected file also disables an otherwise authorized interactive
agent. Password-only resolver leases are unchanged.

## Focused verification

Run from the repository root, with both document backends:

```text
python -m pytest -p tests.ssh_key_support tests/security/test_ssh_key_credentials.py tests/security/test_credential_binding.py tests/security/test_account_transports.py tests/transport/test_bound_accounts.py tests/transport/test_ssh_trust.py tests/security/test_secret_mounts_posix.py tests/security/test_windows_file_trust.py -ra
```

Leave `CT_STATE_BACKENDS` unset, or set it to `json,sqlite`. The support plugin
blocks public socket connections and DNS resolution. Tests generate disposable
keys, use native private temporary directories outside repositories, and use
inert clients or loopback peers that check the exact username and public key.
The account/action integration test runs on JSON and SQLite and checks distinct
keys, sudo denial, session ownership, revocation, missing-key denial and absence
of private-key material in captured logs and state.

Windows-only SID/DACL, junction and handle-sharing tests skip on POSIX. POSIX
owner, mode, symlink, FIFO and descriptor-race tests skip on Windows. Run both
platforms: a platform-specific skip is not a pass for that protection. Foreign
owner rejection is exercised by altering the trusted SID set around a real
Windows descriptor, or injecting a foreign UID into POSIX descriptor metadata;
tests do not create accounts or change real operator ownership.

Before the fix, a real loopback server accepted the selected key with an
Everyone-write DACL on Windows and mode `0666` on Linux. The corrected transport
rejects both before authentication. Real loopback regressions also prove that
protected keys still authenticate, wrong host pins prevent authentication, and
replacement after the checked read cannot substitute a different key.

The existing `tests/transport/test_ssh_trust.py` key fixture now writes a
generated private key with private permissions and asserts the supplied public
key identity instead of expecting a filename. Its implicit-key, agent, timeout
and host-trust regression assertions remain intact.

## Limits

This is protection for provisioned static keys, not a key issuance, expiration,
rotation, SSH certificate or broker service. Encrypted keys require a separate
passphrase design and are rejected. No short-lived credential acceptance is
claimed. A successful read does not prove the account's remote privileges:
provision distinct target accounts/authorized keys and enforce their privileges
on the target as well as in access policy.

The boundary trusts the service's native OS identity and administrators. It does
not defend against a compromised process, kernel or trusted administrator, and
does not cryptographically map a file owner to the authenticated human. Python
and provider memory cannot be guaranteed erased. Removing a file alone does
not terminate an already authenticated connection; repeated authorization,
kill-switch and account guards still govern commands, and a reconnect rereads
the file. Keep existing host trust and account-revocation controls in force.
