# Account and target authorization

In `oidc` and `mesh` modes, an operation requires both a verified identity with an
application role that permits the action and a matching server-owned access grant.
Target operations also require the current inventory scope and, for a connection,
an explicit account binding for that action. Signing in or receiving the `admin`
role does not grant access to a target.

Start with [identity and browser configuration](AUTHORIZATION.md) and
[BROWSER_IDENTITY.md](BROWSER_IDENTITY.md). `AppContext.authorize()` and
`AppContext.transport_for()` enforce the policy described here.
Use [STEP_UP.md](STEP_UP.md) for fresh authentication
requirements and [SEPARATION_OF_DUTIES.md](SEPARATION_OF_DUTIES.md) for approval quorum.

## Identity, roles and grants

The server validates signed tokens and creates the current principal. Policy
selection uses exact verified `iss`/`sub`, or `iss` plus a trusted `groups` claim.
A display name, `X-Actor`, a request-body flag, or an application role name cannot
select another account. The issuer must control human/workload classification,
role and group claims; a missing `ct_kind` means `workload`. Audit attribution uses
a stable issuer/subject fingerprint and retains verified principal evidence.

Roles are additive, but their permissions are intersected with policy grants:

| Role | Role permissions before the policy intersection |
| --- | --- |
| `viewer` | `read`, `read.all`, `kill.engage` |
| `analyst` | Viewer permissions plus `scan`, `discover`, `propose`, `explain`, `plan`, `import` |
| `approver` | Viewer permissions plus `approve`, `deny`, `cancel`, `apply`, `rollback`, `verify`, `plan`, `review` |
| `admin` | Viewer permissions plus `admin`, `policy`, `kill.release` |
| `auditor` | Viewer permissions plus `audit`, `export` |

An `admin` does not inherit `analyst`, `approver` or `auditor`. Human-only actions
are removed from workload permissions even if the token contains those roles.
Fresh authentication requirements are additional checks, not additional grants.
The UI's displayed role permissions are not a list of accessible targets.

## Practical policy example

Provision `<CT_STATE_DIR>/auth/access.json` through server administration. Requests
cannot choose this path or edit the file. The following is a schema-valid example,
not a configured realm or real credentials. Replace the issuer, stable subject IDs,
group, target IDs and account references with provisioned values.

Assume `host-a` is an in-scope SSH target in environment `A`, and `host-b` is an
in-scope SSH target in `B`. All three accounts have issuer-asserted `ct_kind: human`.
Alice has the signed `analyst` role. Bob has the signed `approver` role and trusted
group `approvers-B`. Charlie has the signed `admin` role.

```json
{
  "version": 1,
  "entries": [
    {
      "issuer": "https://id.example/realms/operators",
      "subject": "alice-subject",
      "node_actions": ["read", "kill.engage"],
      "grants": [
        {
          "actions": ["read", "scan"],
          "target_ids": ["host-a"],
          "environments": ["A"],
          "credential": {
            "username": "alice_scan",
            "credential_ref": "ALICE_A_SCAN",
            "sudo": false,
            "options": {}
          }
        }
      ]
    },
    {
      "issuer": "https://id.example/realms/operators",
      "group": "approvers-B",
      "node_actions": [],
      "grants": [
        {
          "actions": ["read", "approve", "deny", "cancel", "review"],
          "target_ids": ["host-b"],
          "environments": ["B"]
        }
      ]
    },
    {
      "issuer": "https://id.example/realms/operators",
      "subject": "bob-subject",
      "node_actions": ["read", "kill.engage"],
      "grants": [
        {
          "actions": ["plan", "apply", "verify", "rollback"],
          "target_ids": ["host-b"],
          "environments": ["B"],
          "credential": {
            "username": "bob_change",
            "credential_ref": "BOB_B_CHANGE",
            "sudo": true,
            "options": {}
          }
        }
      ]
    },
    {
      "issuer": "https://id.example/realms/operators",
      "subject": "charlie-subject",
      "node_actions": ["read", "admin", "kill.engage"],
      "grants": []
    }
  ]
}
```

| Account | Allowed by this role/policy intersection | Not granted |
| --- | --- | --- |
| Alice | Read and scan `host-a` while it is in `A`, using `alice_scan` | Apply anywhere; access to `host-b`; proposal creation despite the analyst role |
| Bob | Read/review/approve `host-b` through the group grant; plan/apply/verify/rollback there using his own `bob_change` binding | Scan `host-b`; access to `host-a`; target administration |
| Charlie | Explicit node permissions, subject to each operation's other checks | Target visibility, target administration, scanning or approval |

The group grant supplies no OS credential. Other group members do not inherit
Bob's connection account. Approval itself does not require a remote login; apply,
plan probes and verification do. On the server, `ALICE_A_SCAN` and `BOB_B_CHANGE`
select only the exact aliases provisioned in the protected credential-source
registry. Legacy range installations without that registry use
`CT_CRED_ALICE_A_SCAN` and `CT_CRED_BOB_B_CHANGE`; fleet SSH/WinRM password
references require a resolver. See [credential sources](CREDENTIAL_RESOLVERS.md).
Provision the actual accounts and secrets separately, with the remote privileges
needed for their intended operations. `sudo: true` permits requested elevation;
it neither grants remote sudo rights nor bypasses command/approval controls.

These permissions do not manufacture a proposal or bypass approval. Bob needs a
valid proposal from another authorized proposer, the required reviewed assessment
or explicit permitted bypass, fresh authentication for approval, and the full
quorum. CAT I/high or unknown severity requires two distinct human approvers;
the proposer cannot count. The example supplies only Bob's eligibility, not the
second person's grant. Automatic post-scan proposals likewise need their own
`propose` authority; Alice's scan-only grant does not acquire it implicitly.

## Exact policy schema and administration boundaries

Version 1 contains exactly integer `version: 1` and an `entries` array. Each entry
requires `issuer`, exactly one of `subject` or `group`, `node_actions`, and `grants`.
Empty arrays grant nothing. A subject and a group with the same name are distinct
selectors. Comparison is case-sensitive, including issuer trailing slashes.

[Version 2](PERSON_ASSOCIATION.md) adds explicitly provisioned person associations
for independent approval counting. It preserves these account grant and credential
rules; linking accounts never combines their privileges. Use the complete v2
schema and migration instructions there rather than adding person fields to v1.

Each resource grant requires a nonempty `actions` array and at least one nonempty
`target_ids` or `environments` array. If both dimensions appear, **both must match**.
Separate grants express a union. There is no substring, glob or regular-expression
matching. A singleton `["*"]` is an explicit all-values resource selector;
`["*", "A"]` is invalid. There are no wildcard actions, issuers, subjects or groups.

The accepted actions are:

```text
read read.all scan discover propose explain plan import approve deny cancel apply
rollback verify review admin policy audit export kill.engage kill.release
```

Unknown fields/actions, duplicate JSON keys, duplicate selectors/grants/list
values, invalid types and incompatible fields within a credential invalidate the
whole file. Distinct credentials in otherwise valid overlapping grants deny that
connection when selected. A malformed unrelated entry does not leave another entry
usable. Role names and scopes are not ACL grants. The parser is bounded to 256 KiB, 256 entries,
64 grants per entry and 2,048 grants total; do not use an unbounded generated policy.

`node_actions` apply only to node operations. They do not authorize any target.
Conversely, a resource grant does not authorize node administration. Updating or
removing an existing target requires node `admin` plus `admin` on that target;
changing environment also checks the proposed target/environment combination.
Adding a target checks the new resource grant as well as node authorization.
Other route requirements, including global metadata visibility, still apply.
An application administrator cannot edit the protected policy through the UI.

Target lists require target `read`; `scan` alone is not visibility. Scoped views
filter unauthorized records before their counts and pagination. Unfiltered node
read routes require node `read` and `read.all`, plus the applicable current-inventory
checks. `read.all` is **node-only**: putting it in any resource grant invalidates
the file. It is broad historical-data authority, not a shortcut for target actions.
Audit is a separate node `audit` permission.

Reports require node `export` and `export` on each original contributing target;
rendering lifecycle/audit information also requires node `audit`. A target-selected
report checks its actual contributors; an all-target report checks all contributors.
Report history filters unauthorized reports before search/counts. Neither node
export nor a query filter bypasses artifact ownership. Outbox listing requires node
`read` and original-contributor `read`; enqueue/sync require node and contributor
`export`. See [report guidance](REPORT_ASSURANCE.md) and [saved provenance](IDENTITY_PROVENANCE.md).

## Per-account target credentials

A grant's optional `credential` requires all four fields: `username`,
`credential_ref`, boolean `sudo`, and object `options`. Nullable values are explicit.
The only option keys are `key_file`, `kubeconfig`, `context` and `transport`; arbitrary
transport options, inline passwords, tokens and key bytes are rejected.

| Transport | Verified-mode binding | Independent requirements |
| --- | --- | --- |
| SSH | Username and one `credential_ref` or absolute `options.key_file`; key-file form uses null `credential_ref` | SSH host trust; remote account privileges. Agent/default-key/interactive fallback is disabled. |
| WinRM | Username, opaque password alias, false sudo, empty options or `{"transport":"ntlm"}` | Validated HTTPS and configured CA in fleet. No ambient Kerberos, Basic or CredSSP substitution. |
| Kubeconfig | Null username/ref, false sudo, absolute `options.kubeconfig`, explicit `options.context` | Guarded kubeconfig and TLS material; cluster-side account/RBAC provisioning. |
| vSphere | Username, environment-reference suffix, false sudo, `{"transport":"vsphere"}` | Discover-only binding on a `vsphere` target; see [vSphere account access](VSPHERE_ACCOUNT_ACCESS.md). |
| Simulated | No credential object, or null username/ref, false sudo and empty options | Only actual `transport="simulated"` avoids OS authentication. |
| Local, fixture, file | Refused for delegated verified execution | Available for development/replay; metadata access does not create a connection. |

SSH/WinRM password references use an opaque alias such as `ALICE_A_SCAN`, resolved
through the exact configured mounted-file or Windows Credential Manager source.
Unconfigured range compatibility uses only `CT_CRED_<ref>`; a configured missing
or invalid source cannot fall back to it. vSphere retains its separately documented
environment-reference contract. SSH key paths remain explicit absolute paths.
File paths must be absolute on the executing host. A matching local filename
cannot change the meaning of an alias.
Examples of separate credential objects (not a whole access policy):

```json
{"username":"alice_scan","credential_ref":null,"sudo":false,"options":{"key_file":"/accounts/alice/id_ed25519"}}
```

```json
{"username":"DOMAIN\\bob","credential_ref":"BOB_WINRM","sudo":false,"options":{"transport":"ntlm"}}
```

```json
{"username":null,"credential_ref":null,"sudo":false,"options":{"kubeconfig":"/accounts/bob/kubeconfig","context":"bob-B"}}
```

Selection considers only grants matching the same principal, target, environment
and operation. Distinct matching credentials deny access; there is no subject-over-
group or most-privileged-account precedence. Identical bindings may overlap.
A grant without credentials adds ACL access only. Verified connections never fall
back to inventory credentials, the process's SSH agent, default keys or ambient
Kubernetes context. Existing inventory connection/trust options do not confer rights.

The application reloads inventory, selects the account, records `credential.use`
provenance and wraps generic and adapter-specific transports. Guards recheck the
principal/session, action, target generation/scope, policy and account before and
after guarded I/O. Internal SSH/WinRM fallbacks honor the selected sudo restriction.
Kubernetes node-SSH inspection requires a separate grant/binding for that node;
cluster permission does not grant access to arbitrary containers or hosts.

Guarded kubeconfigs have exactly one selected context, cluster and user; validated
HTTPS trust; and either a static bearer token or matching certificate/key material.
Executable/auth-provider plugins, `tokenFile`, Basic authentication, impersonation
and extra credential fields are refused. The guarded kubectl path fixes kubeconfig
and context, restricts operation arguments and removes ambient credential variables.
The files are checked again before use, but external kubectl opens paths afterward;
protect them with OS permissions and coordinate rotations with active jobs. This is
not a claim of a race-free file handoff or verified remote RBAC.

## Original saved artifact ownership

Findings and proposals retain `authorization_scope`; scans, reports and queued
exports retain `authorization_scopes`. Each scope records version 1, target ID,
environment and the server-controlled `authorization_id`. New reports preserve the
scope of their historical contributors rather than assigning today's inventory owner.

Removing/recreating a target, or changing its environment, address, asset type or
transport, changes its authorization generation. Moving it away and back does not
revive old evidence, approvals or suppression. Read/export/action checks compare the
saved scope with the current target and current grants. A legacy artifact with missing
or unclassifiable ownership is unavailable in verified mode; collect a new authorized
observation instead of adding ownership or verification flags by hand. A mixed-target
artifact requires permission for every contributor it includes.

Verified review and approval provenance retains canonical audit actors and signed
issuer/subject evidence. Legacy typed labels remain explicitly unverified. See
[IDENTITY_PROVENANCE.md](IDENTITY_PROVENANCE.md) for display/export behavior.

## Provisioning, reload and operating limits

Every policy decision rereads the complete protected file; missing, unreadable,
malformed or changing policy denies access. There is no last-good authorization
cache. Replace a complete UTF-8 file atomically in the same directory, retaining
restrictive ownership and permissions. Do not persist a selected binding as a token.

The policy and every ancestor must be real stable paths: links, reparse points,
hardlinked or special files are refused. POSIX checks require root or the effective
service UID as owner, no group/other writes, and descriptor-relative no-follow
traversal. Root-owned sticky ancestors such as `/tmp` are the bounded exception;
the file itself has no sticky exception. Selected kubeconfigs and private keys
require private permissions; public CA/certificate files may be readable by others.

Windows access-policy, selected Kubernetes credential and OIDC cache reads validate
native owners and DACLs on held file/ancestor handles. Unsafe or unverifiable paths
are refused; private kubeconfig/key files also require confidentiality. The checks
conservatively reject dangerous allow entries rather than infer domain group
membership or subtract deny entries. Provision protected local paths for the actual
service identity using [WINDOWS_FILE_TRUST.md](WINDOWS_FILE_TRUST.md). Service-account,
domain, SMB/remote-filesystem and ReFS deployment acceptance remains open; network
paths are currently refused. Host administrators and the service runtime remain
trusted. Binding provenance records selectors, endpoint, policy hash and
credential-reference fingerprints, not secrets or proof of successful remote login.

Logout, expiry and policy changes stop subsequent guarded work; they cannot recall
an already-issued remote command. Credential distribution, short-lived credential
issuance, rotation and remote privilege verification remain operator responsibilities.
[TRANSPORT_SECURITY.md](TRANSPORT_SECURITY.md) covers host/TLS trust separately.

`CT_AUTH_MODE=dev` bypasses verified role/account isolation and records typed actors
as unverified. Keep it on loopback with scratch state for local rehearsal; a forwarded
port does not add authentication. `fleet` refuses development authentication.
For verified remote CLI operations, use [human device login and the authenticated
API command namespace](CLI_AUTH.md). Ordinary local state-changing commands remain
restricted; serving the API, emergency `kill engage` and the read-only local node
assessment have distinct documented purposes. A typed `--actor` cannot substitute
for login or grant access to target operations.

Native and container servers enforce the same policy. Browser sessions currently
require one process/worker; source deployment manifests also use one replica and an
identity/policy preflight. Use [PACKAGE_IDENTITY.md](PACKAGE_IDENTITY.md) and the
[container guide](../deploy/kubernetes/README.md) for required configuration, mounts
and build limitations. A Ready pod, a passing fixture or a UDS gateway login is not
live realm, target-account, PKI or overall compliance acceptance.
