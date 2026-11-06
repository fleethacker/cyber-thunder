# Node hardening and state protection

`node-hardening` observes the ownership and permissions of an **existing** state
directory. It is a read-only local operator command. It does not harden the host,
change ACLs or services, mount or encrypt disks, install software, open a database,
read file contents, or issue an approval. No startup hook or automatic repair is
installed. Run it as the OS identity that will run the application.

This addresses a different boundary from application roles and target grants.
Someone who can read or replace node state may reach audit records, collected
configurations, before-state snapshots, approvals, queued exports or credentials
without using the application API. Use [ACCOUNT_ACCESS.md](ACCOUNT_ACCESS.md) for
application authorization, [STATE.md](STATE.md) for storage layout and
[WINDOWS_FILE_TRUST.md](WINDOWS_FILE_TRUST.md) for the shared native Windows checks.

## Read-only assessment

Use an absolute state path. These examples assess an already-provisioned directory;
they do not create it or provide a sample credential:

```powershell
python -m cyberthunder --state-dir C:\CyberThunderState node-hardening --json
```

```bash
python -m cyberthunder --state-dir /var/lib/cyberthunder node-hardening --json
```

Omit `--json` for a short text report. The command is available in development,
OIDC, mesh and fleet configurations, including when identity configuration is
unavailable. It relies on the caller's local OS access and bypasses application
initialization only for this metadata assessment. Other CLI authentication rules
are unchanged. A typed `--actor` adds no authority, and there is no `--force`,
repair, recursive chmod, service-start or installation option.

Exit code `0` means every enumerated object's current owner/permission metadata
met the assessment rules. Exit code `2` means unsafe or unproved metadata, an
incomplete walk, an unsupported path/platform or invalid invocation. Encryption,
backup recovery and organizational authorization remain pending even after exit 0.

The JSON result separates:

| Field | Meaning |
| --- | --- |
| `state_tree.status` | `protected`, `unsafe` or `unknown` for observed permission metadata |
| `state_tree.complete` | False when any entry could not be proved or a bound was reached |
| `state_tree.observations` | Per-entry kind, category, status and bounded diagnostic code |
| `runtime_file_guards` | Selected runtime loaders protect policy, Kubernetes files and JWKS cache; `whole_state_enforced` is false |
| `pending` | Operational acceptance that this command cannot establish |

`unsafe` means a concrete metadata condition failed the conservative rules, such
as group/other permissions on Linux or an unsafe directory inheritance grant on
Windows. `unknown` includes unreadable descriptors, sharing conflicts, extended
ACLs that cannot be interpreted, races and unavailable native APIs. The shared
Windows validator deliberately sanitizes failures, so some unsafe DACLs appear as
`unknown / permissions_unproved`. Neither outcome is a pass. If both occur,
`unsafe` takes precedence in the summary; inspect the individual observations.

Reports omit absolute paths, arbitrary filenames, account SIDs and exception
messages. Entries have report-local numeric IDs and categories such as `audit`,
`sqlite_database`, `sqlite_wal`, `sqlite_shared_memory`, `keys_and_auth`,
`rollback_snapshots`, `scan_evidence` and `export`. All other files are still
assessed as `other_state`. Inspect permissions locally to locate a failing object;
assessment of a smaller directory covers only that directory, not the original
whole-state scope. The report does not discover secrets referenced outside state.

## What is checked

Every directory and regular file reached under the supplied root is checked,
including JSON documents, `state.db`, any existing `state.db-wal`, `state.db-shm`
or journal, audit/head files, raw scan data, snapshots and files under `auth` or
`keys`. The assessment does not infer a backend from file contents, validate JSON,
verify the audit chain, inspect SQLite rows, or certify that required files exist.
An empty protected directory proves only its current directory permissions.

The default bounds are 2,048 entries including the root, 24 descendant levels and
10 seconds checked between metadata operations. The Python API permits bounded
limits up to 8,192 entries, 48 levels and 30 seconds; the CLI has no bypass. A bound
produces incomplete/unknown output. Blocking kernel calls cannot be interrupted
by the between-entry timer. Larger trees need an operator assessment outside this
bounded tool; successful checks of separate subtrees are not an atomic whole-node
attestation.

Links/reparse points and hardlinked or special files cannot become protected
observations. Traversal never follows a link. Directory/file identity and metadata
are rechecked while handles are held. A different filesystem below the root is
not traversed further and remains unknown. A live write or SQLite sharing conflict
can invalidate the observation. Arrange a controlled maintenance window if a
stable result is needed; the command never stops the running service itself.
Directory enumeration may update filesystem access timestamps.

### Native Windows

The assessment reuses `security/file_trust.py`, including the native SID trust
set, DACL validation, persistent-ACL volume checks, held parent/file handles and
reparse/device/network-path restrictions. It does not substitute Python mode bits
for DACLs. Regular state files use the private-file check, including protection
from other accounts reading file data. Directory checks additionally reject
foreign listing/child-creation rights and dangerous inheritable allow entries,
including inherit-only entries that could expose newly created children.

Use a dedicated service identity and a protected local state directory. Provision
all ancestors and inherited child ACLs during deployment using the procedure in
[WINDOWS_FILE_TRUST.md](WINDOWS_FILE_TRUST.md). Keep private credentials separate
from public trust material and review the actual service token, inherited rights,
backup access and administrator access. The assessment changes none of them.

LocalSystem, Administrators, TrustedInstaller and the current process identity
remain trusted under the shared validator. A successful administrator-run check
does not establish the service account's ability to run. Denies do not cancel
dangerous allows in this conservative proof. Domain conditional ACLs, service
account rollout, SMB/remote storage and ReFS deployment acceptance remain open;
network paths are refused. This is not enterprise effective-access certification.

### Native Linux

Run the service under a dedicated unprivileged UID. Provision state directories
with private mode `0700` and regular files with `0600`, owned by that UID or root;
the service still needs its actual working access. Keep ancestors owned by root
or that UID and not writable by other accounts. The bounded exception for
root-owned sticky ancestors such as `/tmp` does not apply to the state root.

The assessment uses descriptor-relative, no-follow traversal and native
owner/mode metadata, never shell commands. Any group/other permission on state
objects fails its strict private-state rule. Detected access/default ACL metadata
is unknown and requires separate review; it is not interpreted as ordinary mode
bits. Unavailable extended-attribute inspection also remains unknown. Other POSIX
platforms are currently unsupported, rather than assumed equivalent to Linux.

Provision a restrictive service umask (typically `0077`) and review defaults for
atomic replacements, database sidecars and external tool output. The assessment
does not read or change the current umask, create a test file to infer inheritance,
or guarantee the permissions of future writes. SELinux/AppArmor, capabilities,
namespaces, bind mounts and filesystem encryption require separate validation.
Same-device bind mounts and network-filesystem semantics are not proved by this
metadata walk.

### Containers

Use a dedicated non-root service UID/GID, one supported session worker, constrained
capabilities and a protected local persistent volume. Align the host volume owner
with the container's actual identity; review user-namespace mappings, supplementary
groups and orchestrator security context. A read-only image root does not protect
a writable state volume. Do not mount a container-engine socket or unrelated host
credentials into the service. Run the assessment inside the service's filesystem
and identity context, then assess the host volume and backups separately.

Follow [PACKAGE_IDENTITY.md](PACKAGE_IDENTITY.md) for existing package configuration,
identity preflight and runtime limits. Keep SQLite and its WAL/shared-memory files
on a suitable local volume; a CSI driver or mounted path alone is not evidence of
safe locking or durability. No container, VM, cluster or service is started by this
feature, and fixture results do not establish a live deployment's acceptance.

## Operator acceptance record

Keep the following record with the deployment's evidence, under the organization's
own review process. All fields below are **pending** until an authorized person
supplies actual evidence. Do not infer a reviewer, date, STIG result or ATO from a
successful command or a passing test suite.

| Review item | Evidence to record | Current acceptance |
| --- | --- | --- |
| Service identity and privileges | Actual UID/SID, groups, capabilities/privileges and service definition reviewed by the owner | Pending |
| State and external credentials | Assessment output, root/ancestor and child inheritance review, external key/config locations, backup ACL review | Pending |
| Volume and encryption | Local volume/driver, encryption-at-rest status, key custody/recovery and unlock procedure; Windows/Linux/container host coverage | Pending |
| Restore and rollback | Consistent whole-state backup, SQLite/WAL handling, encrypted backup custody, isolated restore drill and audit-head verification | Pending |
| Node STIG | Applicable OS/container baseline and version, real scan/manual checks, exceptions and corrective-action evidence | Pending |
| ISSO/security review | Named authorized reviewer, actual review date, findings, accepted limitations and review record reference | Pending |
| Deployment authorization | Authorizing organization's decision/reference, scope, conditions and expiry if applicable | Pending |

Preserve the entire state directory and referenced external secrets according to
the backup procedures in [STATE.md](STATE.md). Audit hashes provide tamper evidence,
not access control, encryption or proof that backups can restore a node. Retain
an independently protected audit head and rehearse recovery without overwriting
live state. This feature supplies permission observations and documentation;
ZT31 deployment hardening and human acceptance remain open.

## Focused implementation validation

The new assessment tests exercise both JSON and SQLite state, including actual WAL
files, without opening databases during assessment. They check unchanged fixture
file bytes/modes/timestamps, no context initialization, sanitized output, bounded
walks, unsafe permissions and the existing verified-CLI refusal for other commands.

- Windows: `test_node_hardening.py`, `test_windows_file_trust.py` and
  `test_identity_boundary.py::test_local_cli_cannot_bypass_verified_mode`:
  **73 passed, 7 Linux-specific skips, 1 framework deprecation warning in 3.64s**.
  Native disposable DACLs cover public file reads, directory listing/inheritance,
  junctions and the distinction between a protected file and private whole state.
- Native WSL Linux, Python 3.12.16 on its native filesystem: the new assessment
  tests and that CLI boundary test: **29 passed, 5 Windows-specific skips,
  1 framework deprecation warning in 2.45s**. Real modes, default ACL metadata,
  no-follow descriptors, symlinks and a FIFO are exercised. The foreign-owner
  predicate uses real stat ownership with a simulated different caller; no
  accounts, ownership or host policy were changed.

These are isolated fixture results. They do not fill any acceptance field above.
