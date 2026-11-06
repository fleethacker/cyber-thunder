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
  execution and file-read fallback. The base transport does not yet meet all
  these requirements; transport integration is owned separately.
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
`in_scope` must also be exactly true. The parent supplies a fresh persisted Target;
the policy does not refresh inventory or trust a caller-provided environment.

These action names are accepted in `node_actions` and resource `actions`:

```text
read scan discover propose explain plan import approve deny cancel apply
rollback verify review admin policy audit export kill.engage kill.release
```

Unknown actions always deny, even for an application administrator. There is no
action wildcard. New actions require an explicit policy implementation update.
A node grant applies only when `target=None`. A resource grant never confers node
permission, and a node grant never confers target permission. Listing a target
requires `read` on that target; `scan` or `approve` alone does not imply visibility.
An `admin` role does not bypass any resource or account grant. The policy itself
does not enforce roles; the parent must intersect both decisions.

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

Every public decision reads a regular file through a descriptor and compares
file identity, size and timestamps before/after reading and parsing. Symlinks,
directories and nonregular files are denied. Replacement or modification during
the read is denied; the next call can accept a complete new file. Windows path
and descriptor ctime values are compared only within the same stat interface.
There is no mtime authorization cache, retry to old content, or last-good policy.
`visible_targets` performs an independent read decision for each target; it is
not a transactional inventory snapshot.

Provision the policy and its parent directory using server OS permissions. A
local administrator writes a complete UTF-8 JSON temporary file in the same
directory, flushes it and atomically replaces `access.json`. Preserve restrictive
ownership/ACLs. A truncated write, absent policy or invalid replacement denies
all subsequent decisions until repaired. This phase exposes no ACL editing API.
The loader is designed for a trusted local filesystem; it does not attest OS
ownership/ACLs, protect against a host administrator modifying process memory,
or promise atomicity with a remote operation after the decision returns.

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

Result: 136 passed, 1 skipped (POSIX FIFO test on Windows). These tests use fake
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
