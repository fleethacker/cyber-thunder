# Account and target authorization

Integration contract (implementation in this branch):

- `cyberthunder.control.access.AccessPolicy(path)` exposes `allows(principal,
  action, target=None)`, `require(...)`, `credential(principal, action, target)`
  and `visible_targets(principal, targets)`. `AccessDenied` is a `PermissionError`.
  The server chooses `state/auth/access.json`; requests cannot supply or edit it.
- `cyberthunder.security.credentials.bind_target(target, binding)` returns a
  `dataclasses.replace` copy, with detached options and the selected account.
  `CredentialBinding` and its options/provenance are immutable. No package-level
  security imports are needed; identity validation can coexist independently.
  This change does not add `security/__init__.py`; the namespace works without
  one and an independently supplied package initializer can coexist.
- Principal inputs are server-created objects with `verified is True`, exact
  `issuer`, `subject`, trusted `groups`, and an unexpired numeric `expires_at`.
  Roles and scopes are never ACL grants. The parent must independently intersect
  application role permissions, human approval, inventory scope and this policy.
- Target identity uses exact `id` and `environment` (default `default` only when
  the attribute is absent). A credential decision also binds transport, address,
  port and asset type, so a copy cannot silently be used for another endpoint.
- Every decision rereads and validates the whole bounded local file. Missing,
  malformed, changing or unreadable policy denies access. There is no last-good
  authorization cache. Credential selection and ACL matching use one snapshot.
- For SSH the resulting options set `credential_bound=True`,
  `credential_source=environment|key_file`, `allow_agent=False`,
  `look_for_keys=False`, and `interactive_auth=False`. The transport MUST honor
  this source, never reinterpret an environment reference as an existing local
  filename, and fail on missing credentials. It MUST enforce `sudo=False` on
  execution and file-read fallback. The integrated SSH transport enforces these
  declarations; the application operation guard remains independently required.
- WinRM bindings use an explicit username and environment reference with NTLM.
  Ambient Kerberos is excluded. TLS/host trust remains an independent transport
  requirement. Kubeconfig bindings require an absolute path and explicit context;
  the caller must trust/protect that file and reject ambient credential plugins
  before live execution. The helper never opens credential files.
- `binding.evidence()` supplies the exact principal, action, resource, selectors,
  policy SHA-256, selected username/sudo and a credential-reference fingerprint.
  It does not resolve, expose, or cache secret material. The parent writes this
  to audit alongside the application decision. Re-select at each action; never
  persist a binding as an authorization token.

## Policy schema

```json
{
  "version": 1,
  "entries": [
    {
      "issuer": "https://id.example",
      "subject": "alice",
      "node_actions": ["read"],
      "grants": [
        {
          "actions": ["read", "scan"],
          "environments": ["A"],
          "credential": {
            "username": "alice_scan",
            "credential_ref": "ALICE_SCAN",
            "sudo": false,
            "options": {}
          }
        }
      ]
    },
    {
      "issuer": "https://id.example",
      "group": "approvers-B",
      "node_actions": [],
      "grants": [
        {
          "actions": ["read", "approve"],
          "target_ids": ["host-b"],
          "environments": ["B"]
        }
      ]
    }
  ]
}
```

This example lets Alice scan environment A. A verified member of the issuer's
`approvers-B` group can read and approve host-b while it is in environment B.
There is no access to environment C, no target administration, and no live
transport credential for the approval grant. Approval does not inherently need
an OS account; executing a remote operation does. `ALICE_SCAN` refers only to
`CT_CRED_ALICE_SCAN`, resolved later by the transport.

The root requires exactly `version` (integer 1) and `entries` (array). Each entry
requires `issuer`, exactly one of `subject` or `group`, `node_actions`, and
`grants`. Empty entries, grants and node-actions arrays grant nothing. Subjects
and groups have separate namespaces: a subject named `operators` does not match
a group selector named `operators`. Issuer comparison is exact and case-sensitive,
including trailing slashes. Names/display names, application roles, scopes and
request-supplied actor strings do not participate in ACL selection. The identity
validator must establish that group claims are trusted for the configured issuer.

Each resource grant requires a nonempty `actions` array and at least one nonempty
`target_ids` or `environments` array. When both dimensions appear, BOTH must match.
Use separate grants to express a union. Names are exact and case-sensitive; there
is no substring, prefix, glob or regular-expression matching. A singleton `["*"]`
explicitly grants all values in that resource dimension; `["*", "A"]` is invalid.
Wildcard subjects, groups, issuers and actions are invalid. Selector names cannot
contain `*`, `?`, `[` or `]`. Empty names, control characters and surrounding
whitespace are invalid. IDs/environments in runtime targets have the same rules.
`in_scope` must be an actual boolean. Out-of-scope targets cannot be scanned,
discovered, proposed, approved, planned, applied, rolled back or verified; other
actions still require an explicit matching grant. This preserves the parent
checkpoint's scope predicate, including metadata visibility. The parent supplies
a fresh persisted Target; the policy does not refresh inventory or trust a
caller-provided environment.

These action names are accepted; `read.all` is allowed only in `node_actions`:

```text
read read.all scan discover propose explain plan import approve deny cancel apply
rollback verify review admin policy audit export kill.engage kill.release
```

Unknown actions always deny, even for an application administrator. There is no
action wildcard. New actions require an explicit policy implementation update.
A node grant applies only when `target=None`. A resource grant never confers node
permission, and a node grant never confers target permission. Listing a target
requires `read` on that target; `scan` or `approve` alone does not imply visibility.
An `admin` role does not bypass any resource or account grant. The policy itself
does not enforce roles; the parent must intersect both decisions.

`read.all` is an explicit global grant for unfiltered node-wide history and
metadata that may span environments, including historical records outside the
principal's current target visibility. Grant it only through
`"node_actions": ["read.all"]`; it is evaluated with `target=None`. A resource
grant containing `read.all` invalidates the entire policy, including when mixed
with valid actions or an environment wildcard. Ordinary node `read` does not
imply `read.all`, and `read.all` does not imply ordinary node `read`, node
`export`, or any per-target permission. Targeted `read` and `export` still require
their exact matching resource grants. Target listing remains filtered by
per-target `read`. The parent owns role intersections and which unfiltered API
routes require this action; this policy addition does not change API routing.

Unknown/missing fields, wrong types, duplicate JSON keys, duplicate list values,
duplicate `(issuer, selector kind, selector value)` entries and duplicate grants
invalidate the entire document, including otherwise valid unrelated entries.
Structurally contradictory credential sources also invalidate the whole policy.
Grant duplication is determined by actions and resource dimensions, independent
of list ordering or credential contents. Overlapping but different grants are
allowed; their account bindings are checked for ambiguity at selection time.

## Credential bindings

An optional grant `credential` object requires exactly `username`,
`credential_ref`, `sudo` (a JSON boolean), and `options` (an object). The only
accepted option names are `key_file`, `kubeconfig`, `context` and `transport`.
Values must be strings. Raw passwords, tokens, PEM data, key material, executable
providers and arbitrary option dictionaries are not accepted. References must
be a suffix matching `[A-Za-z0-9_.-]{1,64}` (excluding `.` and `..`) or an absolute
POSIX/Windows path. Path expansion, relative paths and wildcards are excluded.
References and paths are declarations, never proof that the secret exists.

| Transport | Required binding | Restrictions |
| --- | --- | --- |
| SSH | Nonempty username; exactly one credential reference or `options.key_file` | A suffix uses `CT_CRED_<ref>`; an absolute reference is overlaid as `key_file`. Agent, default-key and interactive fallback are disabled in the resulting options. |
| WinRM | Nonempty username and environment-reference suffix | Only `options.transport="ntlm"` is accepted (also the explicit default); sudo must be false. Kerberos, Basic and CredSSP are excluded from this helper. |
| Kubeconfig | Null username/ref; absolute `options.kubeconfig` and explicit `options.context` | Sudo must be false. Context identifies the selected configuration; the helper cannot attest the cluster-side username or permissions. |
| Simulated | No credential object, or null username/ref, false sudo and empty options | Only actual `transport="simulated"` skips OS authentication. A real transport with `simulated=true` still requires a binding. |
| Local, fixture, file or unknown | Denied | No delegated runtime-host account design exists here. ACL-only metadata reads do not construct a transport. |

Examples of credential objects:

```json
{"username":"alice_scan","credential_ref":null,"sudo":false,"options":{"key_file":"/accounts/alice/id_ed25519"}}
{"username":"DOMAIN\\alice","credential_ref":"ALICE_WINRM","sudo":false,"options":{"transport":"ntlm"}}
{"username":null,"credential_ref":null,"sudo":false,"options":{"kubeconfig":"/accounts/alice/kubeconfig","context":"alice-A"}}
```

Credential selection uses only grants matching the same verified principal,
action and current target. A credential from an `apply` grant cannot satisfy a
`scan` grant. All matching credentials must be identical; distinct usernames,
references, sudo permissions or options deny. There is no subject-over-group
precedence and no attempt to select the most privileged or least privileged
account. Identical bindings from multiple selectors are accepted and all matching
credential selectors are recorded. Different configurations pointing at the same
external material are conservatively treated as distinct bindings. A grant with
no credential adds ACL access only; it never supplies inventory credentials.

`bind_target` checks that the binding's target stamp still matches the target,
then detaches the options and overlays the selected account. It removes known
inventory authentication fields and aliases, including key files, kubeconfig,
context, passwords, tokens, agent flags, Kerberos caches and environment overrides.
Inventory-selected `kubectl` executables are removed. Operational options such as
critical services and allowed registries are deep-copied. Host-trust options such
as known-hosts and certificate verification are preserved for the transport's
independent enforcement. The original inventory object is never modified.

The binding, options mapping and policy-created provenance are immutable. Use
`binding.evidence()` for a detached, JSON-serializable audit record; do not serialize
the dataclass as application configuration. The evidence includes the principal's
issuer/subject, action, selected account, sudo flag, target endpoint/environment,
matching policy selectors, policy-content SHA-256 and a reference fingerprint.
It excludes external secret contents and credential filesystem paths. It is a
selection record, not proof that the remote login succeeded or remote privileges
match the declaration. Ordinary `repr(binding)` still contains reference names;
use `evidence()` when logging provenance.

## Reload and integration requirements

Policy reads are bounded to 256 KiB, nesting depth 12, 256 entries, 64 grants per
entry, 2,048 grants total and 128 values per action/resource list. Text fields are
bounded to 512 characters; credential references/paths allow 2,048. Principal
groups are bounded to 64 and must be an array/tuple of distinct exact names.

Every public decision reads one regular, single-link file through a descriptor.
The path must be absolute, have no `..` components, and contain no more than 128
components. The loader inspects every ancestor with `lstat`, without resolving
away links. Symlinks, Windows reparse points/tags (including junctions),
non-directory ancestors, multiply linked files, and nonregular final files are
denied. Descriptor checks repeat the final-file type, link count and protection
checks. The loader compares device/inode identity, type/mode, link count,
owner/group, relevant reparse metadata, size and modification time across the
path and open descriptor. It checks descriptor ctime before/after the read and
path ctime before/after parsing; Windows ctime meanings can differ between those
interfaces. Ancestor identity and security metadata must also remain stable.
Detected replacement or modification denies the decision; the next call can
accept a complete new file. Directory timestamps/link counts are not identity
checks, since unrelated sibling activity changes them.
There is no mtime authorization cache, retry to old content, or last-good policy.
`visible_targets` performs an independent read decision for each target; it is
not a transactional inventory snapshot.

On POSIX, the file and every ancestor must be owned by root or the process's
effective UID. The file cannot have group- or world-write permission, including
when a sticky bit is set. Parent directories likewise cannot be group- or
world-writable, except root-owned sticky ancestors such as `/tmp`, where each
subsequent component must still be trusted-owned. No exception applies to the
policy file itself. Ordinary `0600`/`0644` policy files are accepted when the
ownership and parent checks pass. Descriptor-relative traversal with
`O_DIRECTORY` and `O_NOFOLLOW` anchors each component to its checked parent;
the final open also uses `O_NOFOLLOW` and `O_NONBLOCK`. Every directory descriptor
is closed on success or failure. This assumes a local filesystem with ordinary
POSIX ownership/mode enforcement; it does not independently evaluate richer
platform-specific ACL models.

On Windows, mode bits and `st_uid` do **not** verify a security descriptor, DACL,
owner SID, inherited permissions, or effective account rights. This loader checks
file shape, link count, reparse metadata and observed identity stability; it does
not retrieve or certify Windows ACLs. Deployment must protect the policy and
all ancestor directories against unauthorized writes, replacement/deletion, and
changes to permissions or ownership. Validate the effective ACL for the actual
service identity and untrusted local accounts, including inherited entries.
Windows ACL validation remains an external acceptance requirement; a passing
load is not proof of restrictive ACLs or immunity to an attacker allowed to
rewrite the path. See [Microsoft's file security and access-rights model](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)
and [reparse-point behavior](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points).

Provision the policy and its parent directory using server OS permissions. A
local administrator writes a complete UTF-8 JSON temporary file in the same
directory, flushes it and atomically replaces `access.json`. Preserve restrictive
ownership/ACLs. A truncated write, absent policy or invalid replacement denies
all subsequent decisions until repaired. This phase exposes no ACL editing API.
The loader is designed for a local filesystem; the POSIX checks above do not
protect against the service identity or a host administrator modifying process
memory or intentionally rewriting trusted policy. No atomicity with a remote
operation after the decision returns is promised.

The parent integration sequence is:

1. Establish the verified current principal and `operation_scope` action; check
   principal expiry, application roles and human-approval requirements.
2. Reload the target from persisted inventory, including its environment and
   current scope. Check `policy.require(principal, action, target)` for a resource
   operation, or explicitly use `target=None` for a node operation.
3. Immediately before constructing any live or adapter-specific transport, call
   `binding = policy.credential(principal, action, target)` and then
   `bound = bind_target(target, binding)`. This repeats ACL selection using the
   same fresh snapshot as the credential selection. Use only `bound` downstream.
4. Record `binding.evidence()` with the operation's principal provenance, then
   construct the transport and enforce its independent host/TLS trust checks.
5. Wrap every generic and adapter-specific transport in the operation guard.
   Recheck current principal/action, persisted target/scope and fresh policy at
   each operation. A reused connection must remain attached to its selected
   account, endpoint and action; reject/rebuild it when the binding changes.

The guard MUST reject `run`/`execute`/`write_file` requests with `sudo=True` when
the selected binding says false, and must cover file-read escalation and adapter
methods that directly use options or construct transports. Checking a flag only
in the generic factory is insufficient. Transport internals must also honor the
selected sudo restriction. It is not a substitute for remote account privileges
or restrictions on command payloads.

SSH must obey `credential_source` and the three false fallback flags even in range
mode. Missing `CT_CRED_<ref>` or missing/invalid key files must fail rather than
trying another account source. A filename equal to an environment reference must
not change its meaning. WinRM must not substitute ambient Kerberos credentials.
Kubernetes services that consume `target.options` directly must receive the bound
copy, use both explicit kubeconfig and context, and avoid ambient `KUBECONFIG`,
current-context or default-user fallback. Kubeconfig files can contain executable
or ambient authentication providers; the parent must reject those or establish
a separately reviewed account-bound provider before live verified use. This
helper deliberately does not open kubeconfigs or fetch credentials.

Bindings are short-lived selection results, not reusable capabilities. Holding
an old Python binding does not automatically revalidate the policy; the parent
operation guard must reselect it before each action. There is no credential
retrieval, secret cache, vault API or credential rotation service in this change.
Runtime local execution stays denied pending a safe delegated-host design.

## Validation and remaining acceptance

Focused Windows validation used the shared Python environment with this checkout
first on `PYTHONPATH`. From this checkout, with the test environment activated:

```powershell
$env:PYTHONPATH = (Get-Location).Path
python -m pytest tests/security/test_access.py tests/security/test_credential_binding.py
```

Initial account-selection result: 136 passed, 1 skipped (POSIX FIFO test on Windows). These tests use fake
verified principals and isolated files. They cover exact account/group selection,
independent node/resource permissions, explicit visibility, unknown actions,
wildcard boundaries, invalid schema, size/depth limits, same-mtime revocation,
atomic replacement and in-place races, expiry, account ambiguity, target moves,
detached inventory copies, SSH/WinRM/kubeconfig selection, simulated/local limits,
and audit evidence without secret resolution.

No live login, host privilege test, identity-provider validation, route wiring,
operation-wrapper enforcement, full integration gate or external validation is
claimed here. The parent owns those acceptance checks, inventory environment
schema, API/CLI/worker enforcement, cluster-service wiring and backlog updates.
No dependency changes are required.

## Guarding selected Kubernetes credentials

The followup module `security/kube_credentials.py` exposes:

```python
validate_kubeconfig(binding: CredentialBinding, *, trusted_uid: int | None = None) -> KubeconfigBinding
guard_kubeconfig(binding: KubeconfigBinding) -> None
```

The input is the fresh account-policy binding for a kubeconfig target. The
immutable result supplies `path`, `context`, `cluster`, `user`, `server`, file
identity/content-hash bindings, `kubectl_args()` and secret-free `evidence()`.
The parent must guard immediately before each Kubernetes subprocess, use all
returned selection arguments, and reject caller-provided connection or identity
overrides. This module does not modify central services or transport factories.

The accepted file contains exactly one selected context, cluster and user. The
validator rejects unsafe fields rather than producing a temporary kubeconfig
containing secret material. POSIX ownership/mode checks and Windows reparse-point
rejection apply to the config and referenced files. Windows DACL verification
remains a deployment responsibility. A hash guard detects prior changes; it does
not make an external process reopening the path race-free.

The subprocess-input contract adds:

```python
validate_kubectl_args(args: Sequence[str]) -> tuple[str, ...]
kube_subprocess_env(environ: Mapping[str, str] | None = None) -> dict[str, str]
```

`args` must be a list or tuple of operation arguments, excluding both the executable
and the fixed connection arguments returned by `kubectl_args()`. Validate the
complete operation tail, including any arguments added by the caller. Do not
validate a prefix and subsequently append unchecked flags. All four public
helpers raise `KubeCredentialError`, a `PermissionError`, with fixed error text
and no original parser exception attached. Do not log raw commands, source files,
library exceptions, private keys, tokens or unfiltered subprocess stderr.

The complete parent sequence for a subprocess is:

```python
selected = access.credential(principal, action, current_target)
kube = validate_kubeconfig(selected)
operation_args = validate_kubectl_args(["get", "pods", "-A", "-o", "json"])
environment = kube_subprocess_env()
# Recheck parent principal/action/scope and policy here too.
guard_kubeconfig(kube)
argv = [trusted_absolute_kubectl, *kube.kubectl_args(), *operation_args]
# subprocess.run(argv, env=environment, shell=False, ...)
```

Use a server-approved executable; the helper does not locate or attest kubectl.
Pass the returned environment directly, without merging ambient variables back.
Neither a kubeconfig selection nor command-shape validation grants permission to
perform the operation. The parent must retain role, resource, human-approval and
kill-switch enforcement. The file guard does not reload the access policy or
inventory. A cached connection/selection is not an authorization capability.

The config source must come from a policy-selected `CredentialBinding` with
provenance for an in-scope Kubernetes kubeconfig target. There is no bare-path
or default-context convenience entrypoint. Root fields are exactly `apiVersion`
(`v1`), `kind` (`Config`), `contexts`, `clusters`, and `users`, optionally an empty
`preferences` map and a `current-context` equal to the selected context. Each
array contains exactly one named entry. The context must explicitly select that
cluster and user; a valid namespace is optional. Unselected accounts and clusters
are rejected rather than silently removed from a secret-bearing file.

Cluster fields are limited to an HTTPS `server` and exactly one explicit
`certificate-authority-data` or absolute `certificate-authority` file. URLs with
credentials, queries, fragments or backslashes are rejected. CA bytes must contain
only PEM certificates carrying CA basic constraints. No system-CA fallback is
accepted. `insecure-skip-tls-verify`, `tls-server-name`, `proxy-url`, extensions and
unknown cluster fields are rejected, even when a bypass flag is set to false.

The selected user has either a nonempty static bearer token or exactly one source
for each client certificate and private key. Certificate/key sources may be
base64 embedded `*-data` or absolute protected files. The first client certificate
must match the private key. Encrypted keys, extra PEM payloads, malformed material,
token-plus-certificate combinations, `tokenFile`, Basic authentication, executable
or auth-provider plugins, impersonation fields and unknown credential fields are
rejected. Token and key bytes are used only within validation and are not returned
or cached. This does not attest the remote identity, RBAC, certificate revocation,
expiry acceptance or successful TLS handshake; those remain connection-time checks.

Source reads are limited to 256 KiB for a config, 128 KiB for each public CA or
client certificate source, and 32 KiB for a private key. There are at most four
source files. Embedded data has the same decoded limits. YAML is bounded to
4,096 events and depth 12. Aliases, anchors, explicit tags, duplicate mapping keys
and multiple documents are rejected. Static tokens are limited to 16,384 ASCII
bearer-token characters. Certificate bundles are limited to 16 certificates.

All file paths must be absolute on the executing host. There is no tilde,
environment-variable, relative-path, parent-traversal, UNC/network-share or
Windows alternate-data-stream expansion. All parent path components are checked
for symlinks or reparse points. Sources must be regular files with one hard link.
On POSIX, owner must be root or `trusted_uid`, which defaults to the effective
service UID. Configs and private keys must have no group/other access. Public CA
and client certificates may be world-readable, but group/other writes are denied.
Parent directories must have a trusted owner and reject group/other writes, with
an exception for trusted sticky directories such as `/tmp`. The caller must set
any `trusted_uid` override from server configuration, never request data.

Windows paths and source handles are checked for reparse points; this does not
verify the owner or DACL. `evidence()["protection"]` explicitly reports
`windows_dacl_not_verified` on Windows, and `posix_owner_mode` on POSIX. Provision
restrictive Windows file/directory ACLs separately before verified live use.
The loader does not claim to attest extended filesystem policy or remote filesystems.

`FileIdentity` binds each source path, role, SHA-256, file identity, size, timestamps,
mode/owner metadata and parent-directory identities. Validation checks all files
again before returning. `guard_kubeconfig` rereads and rehashes all sources, so a
same-size edit with restored mtime, atomic replacement, owner/mode change, missing
source or changed key/CA cannot reuse the old result. Audit evidence exposes only
file roles/hashes, exact selection, server, authentication kind, policy hash and
principal/target provenance. Raw source paths are available for execution but
omitted from the evidence and dataclass representation. No temporary kubeconfig
is written, and no secret-containing file contents remain in the returned object.

This is a prelaunch snapshot check, not an immutable subprocess file handle.
An administrator or otherwise authorized writer can change the path after the
guard returns and before kubectl opens it; a later guard detects the change but
cannot undo the earlier external operation. Keep these sources in protected,
server-managed directories and coordinate credential rotation with active jobs.
Do not describe this path-based integration as race-free. OS-protected immutable
deployment material or a separately reviewed descriptor-based subprocess design
would be required for that stronger guarantee.

The command allowlist includes `get`, `describe`, `version`, `api-resources`,
`api-versions`, `apply`, `replace`, `patch`, `delete`, `rollout status` and
`auth can-i`, with a small set of their operation flags. There are at most 128
arguments, 32,768 characters per argument and 65,536 total characters. The helper
rejects all unreviewed flags, short-flag bundles and `--` delimiters. It rejects
endpoint, user, context, cluster, kubeconfig, token, impersonation, CA, client key,
TLS-name, verification-bypass, proxy, preference-file, logging and profiling
overrides in either `--flag value` or `--flag=value` form. New flags require review.
Raw GET requests must use relative API paths, not absolute URLs. Manifest inputs
accept only stdin (`-f -`); filesystem/URL manifests and Kustomize are excluded.
Unreviewed commands, plugins, config inspection, editing, external diff, exec,
debug, run and proxy operations are excluded. The parent still owns validation
and authorization of manifests and patches supplied on stdin or as arguments.

The environment helper retains only executable-path, Windows runtime,
temporary-directory, locale and timezone variables. It drops Kubernetes defaults,
in-cluster variables, cloud/OS credentials, proxy variables, alternate trust stores,
home/profile settings, dynamic-loader hooks and other ambient variables. It sets
both `KUBECTL_KUBERC=false` and `KUBERC=off`. This prevents kubectl preferences from
adding defaults or aliases; see the official [kuberc reference](https://kubernetes.io/docs/reference/kubectl/kuberc/).
The rejected authentication and cluster fields are documented in the official
[kubeconfig schema](https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/).

Focused followup validation: `python -m pytest tests/security/test_kube_credentials.py`
completed with 199 passed and 3 skipped on Windows. The skips are real POSIX
permission tests; owner/mode rules are also exercised with explicit metadata on
all hosts. Tests use generated certificates, protected temporary config/key/CA
files, real symlinks/hardlinks where supported, duplicate-key and malicious YAML,
injected plugins, extra accounts, same-mtime edits, replacement/deletion, key/CA
changes, appended CLI overrides and ambient environment inputs. No network or
live cluster was used. Existing PyYAML and cryptography runtimes are used; no
dependency manifest or global config changes are included. Parent context,
cluster-service and adapter wiring, Windows DACL provisioning, live TLS/RBAC
acceptance and the full integration gate remain parent-owned.
### Protected-file validation

The file-trust follow-up is based on parent checkpoint `0749705`, retaining its
exact `_matching` scope predicate. Only `control/access.py`, this document, and
the new `tests/security/test_access_file_trust.py` are changed. The parent working
tree was read but not edited.

Windows Python 3.12.10 with pytest 9.2.0: **156 passed, 12 skipped** (9.20 s).

```powershell
$env:PYTHONPATH = 'C:/Users/joshu/.codex/worktrees/transport-trust/cyber-thunder'
& 'C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe' -m pytest -o addopts='' -q -rs tests/security/test_access.py tests/security/test_access_file_trust.py tests/security/test_credential_binding.py
```

The exact Windows skip reasons are:

- One existing test: `requires POSIX FIFO`.
- Eleven new cases: `requires POSIX owner/mode and descriptor-relative filesystem semantics`.

Ubuntu WSL Python 3.14.4 with pytest 9.2.0: **167 passed, 1 skipped** (3.03 s).
The pure-Python pytest installation from the shared environment was reused,
with plugin autoload disabled; filesystem operations and temporary policies ran
on native Linux under `/tmp`. No runtime package installation was needed.

```powershell
wsl -d Ubuntu -- env PYTHONPATH=/mnt/c/Users/joshu/.codex/worktrees/transport-trust/cyber-thunder:/mnt/c/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Lib/site-packages PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -o addopts= -q -rs -p no:cacheprovider tests/security/test_access.py tests/security/test_access_file_trust.py tests/security/test_credential_binding.py
```

The exact Linux skip reason is `requires Windows NTFS junction support` (one
test). Windows exercised the real junction case; both platforms exercised real
symlinks and hard links. No symlink capability skips occurred in these runs.

Adversarial coverage includes file/parent/grandparent redirection, reparse-tag
metadata even without symlink mode, a hard link added during parsing, replacement
of a parent containing the same policy file, descriptor metadata mismatch,
POSIX writable files/directories, an untrusted-owner metadata fixture, a
permission change during parsing, and a real POSIX parent-to-symlink swap during
opening with descriptor cleanup checked. Existing malformed/changed/FIFO tests
remain in the focused commands. The owner fixture does not claim a privileged
cross-user `chown` test, and the Windows tests do not establish DACL protection.
Deployment ACL review, hostile privileged-writer scenarios, the complete
application gate, and external per-user login acceptance remain separate work.

The subsequent `read.all` addition passed the same three-suite Windows command:
**161 passed, 12 skipped** (4.78 s), with the unchanged platform skip reasons
above. Focused Linux checks for exact node-action separation, invalid resource
grants, targeted read/export preservation, and the retained scope predicate
passed **6 tests** (30 deselected, 1.63 s):

```powershell
wsl -d Ubuntu -- env PYTHONPATH=/mnt/c/Users/joshu/.codex/worktrees/transport-trust/cyber-thunder:/mnt/c/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Lib/site-packages PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -o addopts= -q -rs -p no:cacheprovider tests/security/test_access_file_trust.py -k 'global_history or read_all or trusted_file_content'
```
