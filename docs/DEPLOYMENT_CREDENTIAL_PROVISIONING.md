# Deployment credential provisioning

This describes the current source contract for native and container deployments.
The checked-in packages do not provision target credentials end to end. Examples
below contain only placeholder identities and file references; they are not
ready-to-deploy account policies or evidence of successful target authentication.

## Application identity and target access

| Input | Purpose |
| --- | --- |
| Runtime OS user (canonical container UID/GID 10001; alternate image 1000) | Owns/reads protected local files. It is not the signed-in human or the remote target account. |
| OIDC client secret (`CT_CRED_BROWSER_LOGIN`) and application TLS material | Authenticate the browser client to the issuer and protect application traffic. These do not select SSH/WinRM credentials. |
| Signed issuer/subject, application roles and protected `auth/access.json` | Authorize the active named account for exact resources/actions and select its target credential binding. |
| SSH private key, resolver-backed password or selected kubeconfig | Authenticate the selected remote account, subject to that target's own permissions. |

Follow [packaged identity setup](PACKAGE_IDENTITY.md) first. A typed actor name,
pod service account, inventory credential field or successful login alone does
not authorize a target operation. Person associations used for approval checks
do not merge account roles, grants or credentials. Keep the existing approval,
step-up, session, scope and kill-switch checks; provisioning a credential does
not satisfy them.

## Select exact accounts and operations

The storage/policy administrator must review the issuer and stable subject for
each account, target ID, environment and allowed actions. Each target connection
action needs one unambiguous credential binding. Conflicting bindings are refused.
The target administrator must separately provision the remote accounts and
their permissions. A local file owner does not prove a human's remote rights.

This JSON example belongs in the protected account policy, not the inventory.
Replace every placeholder and review it alongside the existing policy; do not
overwrite unrelated entries. Paths are absolute **runtime** paths, so a host
provisioning mount path must not appear in the container's binding.

```json
{
  "version": 1,
  "entries": [
    {
      "issuer": "https://sso.example.test/realms/uds",
      "subject": "REPLACE_SCAN_ACCOUNT_SUBJECT",
      "node_actions": [],
      "grants": [
        {
          "target_ids": ["REPLACE_TARGET_ID"],
          "environments": ["REPLACE_ENVIRONMENT"],
          "actions": ["read"]
        },
        {
          "target_ids": ["REPLACE_TARGET_ID"],
          "environments": ["REPLACE_ENVIRONMENT"],
          "actions": ["scan"],
          "credential": {
            "username": "replace_scan_user",
            "credential_ref": null,
            "sudo": false,
            "options": {
              "key_file": "/var/lib/cyberthunder/auth/credentials/scan_account/id_ed25519"
            }
          }
        }
      ]
    },
    {
      "issuer": "https://sso.example.test/realms/uds",
      "subject": "REPLACE_APPLY_ACCOUNT_SUBJECT",
      "node_actions": [],
      "grants": [
        {
          "target_ids": ["REPLACE_TARGET_ID"],
          "environments": ["REPLACE_ENVIRONMENT"],
          "actions": ["read"]
        },
        {
          "target_ids": ["REPLACE_TARGET_ID"],
          "environments": ["REPLACE_ENVIRONMENT"],
          "actions": ["apply"],
          "credential": {
            "username": "replace_apply_user",
            "credential_ref": null,
            "sudo": true,
            "options": {
              "key_file": "/var/lib/cyberthunder/auth/credentials/apply_account/id_ed25519"
            }
          }
        }
      ]
    }
  ]
}
```

The scan account needs the application `analyst` role; the apply account needs
`approver`. Roles and policy grants are both required. This example grants no
approval authority and is not a complete remediation workflow: separately
authorize required `discover`, `plan`, `verify` and `rollback` operations and
their credential bindings, plus the
[independent human approval workflow](SEPARATION_OF_DUTIES.md).
Preserve any existing version-2 person-association policy instead of replacing
it with this version-1 example.

Use distinct target accounts/keys for scan and apply. `sudo: false` prevents
the selected scan binding from requesting sudo; the target must also deny
writes/elevation for that account. Scans needing privileged evidence may be
incomplete under a read-only account. `sudo: true` permits sudo requests but
does not create OS privileges: restrict the remote apply account to required
operations. It is not a temporary privilege lease. Do not grant blanket sudo
to make a scan pass. Keep a verified host key pin or provisioned `known_hosts`
in the target's trust options; the selected private key does not verify the host.

## Provision protected regular files

For Linux native operation, provision under an administrator-controlled local
directory using the actual service UID/GID. For the canonical container, the
existing state PVC can hold `auth/credentials/...`; a storage administrator must
provision it while the application is stopped, preserving existing state.
For container files, use UID/GID 10001 (1000 only for the alternate image), directories mode
`0700`, and private key/password files mode `0600` or `0400` readable by that UID.
Review every ancestor for trusted ownership and no group/other writes. The
reader trusts root or the effective UID and has a narrow root-owned sticky
directory exception. `fsGroup` is not a replacement for these requirements.

Use regular, singly linked files and real directories, with no symlink or
projected path components. Review the source provenance/content before explicit
administrative installation from a protected file; never automatically copy a
projected Secret or shared writable input into a trusted location. Neither the
application nor its preflight repairs ownership/permissions or provisions keys.

Native Windows uses absolute local paths, for example beneath
`C:/ProgramData/CyberThunder/auth/credentials/`, and native owner/DACL checks.
Provision for the actual service logon, with no foreign read/write/delete or
ownership/DACL-changing rights on private files and protected ancestors.
The trusted SID set is the process user, SYSTEM, Administrators and
TrustedInstaller. Reparse points and hardlinks are rejected; POSIX `chmod`
is not Windows ACL provisioning. See [SSH key credentials](SSH_KEY_CREDENTIALS.md)
for the full native contract, supported unencrypted key formats and 32 KiB limit.
Encrypted keys, automatic agent/home-key fallback and adjacent certificate
discovery are not supported by the selected-key path.

## Password sources for SSH and WinRM

Fleet target passwords require `CT_CREDENTIAL_SOURCES` to name an absolute,
protected regular JSON registry. `CT_AUTH_MODE` must be `oidc` or `mesh`.
There is no environment provider in its schema and no fleet `CT_CRED_*`
password fallback. An explicitly configured missing/unsafe registry fails
startup/use; the application does not generate one.

Example registry at `/var/lib/cyberthunder/auth/credential-sources.json`:

```json
{
  "version": 1,
  "sources": {
    "NAMED_ACCOUNT_SCAN_PASSWORD": {
      "provider": "mounted",
      "root": "/var/lib/cyberthunder/auth/credentials/scan_account",
      "key": "password",
      "layout": "regular"
    }
  }
}
```

For password-based SSH, replace only the corresponding grant's `credential`
object with this reference; do not retain `options.key_file`:

```json
{
  "username": "replace_scan_user",
  "credential_ref": "NAMED_ACCOUNT_SCAN_PASSWORD",
  "sudo": false,
  "options": {}
}
```

The separately provisioned password file must be nonempty UTF-8, at most 16 KiB,
without NUL. Its bytes are used exactly, including trailing newlines. No password
belongs in the registry, policy, inventory or command arguments. Provision
distinct aliases/files and grants for other accounts/actions. For bound WinRM,
use `options: {"transport": "ntlm"}` with `sudo: false`, an explicit remote
username and password alias; retain fleet HTTPS/certificate trust. Ambient
Kerberos is not a fallback for a bound account.

Native Windows can instead use `provider: "wincred"` with the exact
`target_name` derived by `windows_target_name(binding, principal, target)`.
This name binds issuer, subject, action, target environment/endpoint/generation
and remote username. Provision the generic credential under the application's
actual Windows logon and use a separate alias for each scope. See
[Credential resolvers](CREDENTIAL_RESOLVERS.md#native-windows-provisioning-contract)
for the blob/persistence contract. No packaged CLI creates these entries;
service-logon provisioning and real authentication still need acceptance.

## Container limitations and acceptance

The optional `cyberthunder-target-credentials` volume projects mode `0444` files.
Its SSH key path fails both the no-symlink and private-permission requirements.
Read-only mounting or changing the mode alone does not fix this. The password
resolver has a separate, explicit POSIX `layout: "kubernetes"` option with
strict projection/ownership/mode checks and optional dedicated `reader_gid`;
it does not extend the SSH key reader. World-readable `0444` passwords are
rejected there too. See [projection requirements](CREDENTIAL_RESOLVERS.md#mounted-file-trust-and-kubernetes-projections).
That capability is not acceptance of the current package's mount.

The package does not provision protected target files, a credential registry,
per-account target grants or remote accounts. For passwords, the operator must
also supply `CT_CREDENTIAL_SOURCES` through reviewed runtime configuration;
there is no Zarf variable that installs/configures the registry. The identity
preflight checks application settings/policy, not target credential usability.
No init container copies Secrets into trusted files. Rebuilding the image and
package does not close these provisioning gaps.

Kubernetes target credentials likewise need a protected per-account kubeconfig
and exact context binding. The bootstrap pod `tokenFile` configuration is not
accepted, even if copied into a regular file. Follow the
[account Kubernetes provisioning contract](../packages/cyberthunder/docs/IDENTITY_REVIEW.md#account-kubernetes-credentials-required-provisioning-seam)
for the supported explicit static token or client certificate/key configuration
and least-privilege target RBAC.

Before operational acceptance, verify protection/readability as the actual
runtime account and validate each authorized account/action against the intended
target, including denial of another account and scan-to-apply escalation.
Exercise the required scan, independent approval, apply, verify and rollback
flow in the isolated range. Offline schema checks cannot attest pod mount flags,
remote privileges, real login or authentication. These remain deployment work
under [BACKLOG.md](BACKLOG.md), ZT-19 and ZT-13; this document does not close them.

Registry/policy changes are rechecked at guarded use boundaries. Password
rotation is seen on the next lease; SSH key replacement is seen on the next
connection. Deleting a static key does not revoke an already authenticated
connection or stop a remote command already running. Retain authorization and
kill-switch controls and the target's own revocation procedures. Short-lived
issuance, SSH certificates and broker-driven revocation remain open.
