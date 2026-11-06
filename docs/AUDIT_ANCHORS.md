# Signed audit checkpoints and local anchors

The optional operator utility signs a fully verified local audit head with an
explicitly provisioned Ed25519 key. A separate local store accepts signed heads
monotonically and refuses rollback, conflicting heads, and successors that do not
name its exact current checkpoint. These operations do not contact a receiver or
establish off-node delivery. Every receipt includes
`"off_node_delivery": "not_established"`.

Existing application audit appends and unsigned `.head` files are unchanged.
There is no implicit key generation, ambient key selection, environment secret,
application API, automatic signing schedule, or outbox integration. An explicit
operation fails closed on invalid configuration, unsafe files, missing trust,
bad signatures, or an invalid chain. A failed export is never reported as signed.

## Operator boundary and protected files

Run `python -m cyberthunder.audit.anchors --help` from the installed environment.
Authority is the native OS account's access to protected files, not a typed actor
name, an application admin role, or an HTTP session. Do not expose this utility to
untrusted shell users through a privileged wrapper. No production keys or external
destinations are provisioned by the utility or its tests.

Provision a node key through the enclave's approved process. The current reader
accepts exactly one PEM-encoded, unencrypted PKCS8 Ed25519 private key and one PEM
SubjectPublicKeyInfo Ed25519 public key. Private bytes belong only in the protected
key file, never in command arguments, environment variables, configuration JSON,
logs, or receipts. Encrypted PEM/password handling, hardware key providers, PIV
approval signatures, and secure memory erasure are not implemented. Keys are read
fresh for each operation and are not cached between operations.

All paths must be explicit absolute local paths. There is no home/environment
expansion, network path, or default key/store/log location. Existing files must be
regular files with one link. Symlinks, Windows reparse points, and unsafe parents
are refused. Windows native checks also reject path aliases and alternate streams.
Directories must already exist.

On POSIX, files and parents must be owned by the effective user or root, without
group/world write access. Private keys must additionally exclude all group/world
access; provision them with mode `0600`. Trusted sticky ancestors such as `/tmp`
are supported. Create dedicated operator-owned directories with mode `0700`.

On Windows, the shared native file-trust implementation checks owner, DACL,
volume type, file identity, and ancestors using pinned handles. Its trusted set is
the executing user, SYSTEM, Administrators, and TrustedInstaller. Untrusted read
grants are forbidden on the private key; untrusted mutation grants are forbidden
on public inputs and parents. Creation also refuses untrusted child creation in
the immediate directory. Unsupported ACLs or unavailable native checks refuse
the operation. Deploy on a supported local filesystem, with a DACL restricted to
the intended operator and trusted system administrators. FAT, network shares,
untrusted parent directories, and managed policy changes need separate acceptance.

## Protected configuration

The following paths and identities are examples only. The operator provisions a
unique 32-character lowercase hexadecimal `log_instance` for each logical log and
pins it independently in receiver trust. Do not reuse an instance after clearing
or rotating a log. `node` must exactly match every audit record's node name; it is
not inferred from the machine running verification.

Signing configuration, for example `C:/AuditTrust/signer.json`:

```json
{
  "version": 1,
  "node": "ship-node-01",
  "log_instance": "724953c6a80449e297563de5bc391236",
  "key_id": "node-2026",
  "log_path": "C:/CyberThunder/state/audit.jsonl",
  "private_key": "C:/AuditTrust/node-2026.pem"
}
```

Trust configuration, for example `C:/AuditTrust/trust.json`:

```json
{
  "version": 1,
  "streams": [
    {
      "node": "ship-node-01",
      "log_instance": "724953c6a80449e297563de5bc391236",
      "keys": {"node-2026": "C:/AuditTrust/node-2026.pub"}
    }
  ]
}
```

These schemas have no optional extra fields. Duplicate fields or stream entries
are rejected. Trust matches exact node, instance, and key ID; there are no wildcard,
prefix, or issuer-name heuristics. A bundle cannot nominate a public-key path.
Public trust and configuration files need integrity protection even though they
do not contain secrets. The signer checks its private key against the configured
public key before signing. The receiver needs only public keys.

## Local commands

Each command prints one JSON receipt on success and exits zero. Refusals exit 2
with a bounded diagnostic containing no input path, key material, or audit record.
Example commands assume the paths above have already been provisioned:

```text
python -m cyberthunder.audit.anchors export --signer C:/AuditTrust/signer.json --trust C:/AuditTrust/trust.json --out C:/AuditExchange/checkpoint-001.json
python -m cyberthunder.audit.anchors verify --trust C:/AuditTrust/trust.json --bundle C:/AuditExchange/checkpoint-001.json
python -m cyberthunder.audit.anchors check-log --trust C:/AuditTrust/trust.json --bundle C:/AuditExchange/checkpoint-001.json --log C:/CyberThunder/state/audit.jsonl
python -m cyberthunder.audit.anchors init --trust C:/AuditTrust/trust.json --store C:/AuditTrust/anchors.json
python -m cyberthunder.audit.anchors import --trust C:/AuditTrust/trust.json --store C:/AuditTrust/anchors.json --bundle C:/AuditExchange/checkpoint-001.json
```

`export` verifies the entire chain and its current unsigned `.head` while holding
the same OS file lock used by `AuditLog.append`. It refuses missing/behind heads
on nonempty logs and malformed, duplicate-field, oversized, or mixed-node records.
It publishes a new artifact without overwriting an existing path. An empty but
explicitly provisioned log may have a genesis checkpoint without a `.head`.

`verify` checks configured trust, schema, and signature only. Its receipt says
`log_verification: not_performed`. `check-log` separately checks the full local
chain and requires the anchor's exact hash at its sequence; the local log may
have advanced beyond that sequence. Signature validity does not prove the
truthfulness of events, authorization decisions, or record timestamps.

`init` explicitly creates an empty local receiver store and never overwrites an
existing store. `import` will not create missing state. Its first checkpoint for
a trusted stream must have `previous: null`; this establishes a baseline, not a
proof that earlier events were externally retained. Retain that baseline artifact.

After appending more events, export a successor with the previous artifact:

```text
python -m cyberthunder.audit.anchors export --signer C:/AuditTrust/signer.json --trust C:/AuditTrust/trust.json --previous C:/AuditExchange/checkpoint-001.json --out C:/AuditExchange/checkpoint-002.json
python -m cyberthunder.audit.anchors import --trust C:/AuditTrust/trust.json --store C:/AuditTrust/anchors.json --bundle C:/AuditExchange/checkpoint-002.json
```

The signer verifies the previous signature and its prefix in the complete log.
Sequence must advance to produce a successor; if no events were added, resend
the existing artifact. Import accepts an identical checkpoint idempotently.
At the same sequence any differing signed body is a conflict, including a changed
key ID or predecessor. A lower sequence is a rollback. A higher sequence must
name the exact accepted sequence, head hash, and checkpoint identifier. Transfer
all intermediate checkpoints in order: skipping a predecessor fails. The local
store retains the latest signed bundle per stream, not the complete archive.

For key rotation, provision a new public key under a new key ID in the protected
trust file, retaining the old public key. Export/import the next checkpoint under
the new key with the exact old predecessor. Only then remove the old key if no
latest stored anchors or required historical verifications depend on it. Every
stored current anchor is verified against current trust on every import. A key
revocation can therefore deliberately stop imports until the operator resolves
the trust/retention policy; there is no last-good authorization fallback.

## Signed format and integration seams

`cyberthunder.audit.anchors` exposes these filesystem-only functions, all returning
receipt dictionaries and raising safe `AnchorError` on refusal:

```python
export_checkpoint(signing_config, trust_config, output, *, previous=None)
verify_checkpoint(bundle_path, trust_config)
check_log(log_path, bundle_path, trust_config)
initialize_store(store_path, trust_config)
import_checkpoint(bundle_path, trust_config, store_path)
```

A bundle has exactly `checkpoint` and `signature`. The checkpoint has exactly
`schema`, `algorithm`, `key_id`, `node`, `log_instance`, `sequence`, `head_hash`,
and `previous`. Schema is `cyber-thunder.audit.checkpoint.v1`, algorithm is exactly
`Ed25519`. `previous` is null or an object with `sequence`, `head_hash`, and
`checkpoint_id`. Hashes are lowercase SHA-256 hex; sequence is a nonnegative
integer at most `2**53 - 1`, never a JSON boolean or floating-point value. Only
sequence zero may use the all-zero genesis hash.

The detached signature covers the bytes
`b"Cyber Thunder audit checkpoint signature v1\x00" + canonical(checkpoint)`.
It is stored as canonical unpadded URL-safe base64, exactly 86 ASCII characters
encoding 64 bytes. `canonical` is the module's versioned ASCII JSON encoding:
sorted object keys, compact comma/colon separators, JSON ASCII escaping, no NaN
or Infinity. The checkpoint contains no floats. This is an explicitly defined
encoding, not a claim of a general JSON canonicalization standard. Checkpoint ID
is SHA-256 of
`b"Cyber Thunder audit checkpoint identifier v1\x00" + canonical(checkpoint)`.
The signature is not part of that identifier. Audit record hashes retain their
existing UTF-8 canonicalization; it is not replaced by checkpoint canonicalization.

Bounds: configuration 64 KiB; at most 64 streams with 8 keys each; private PEM
16 KiB; public PEM 8 KiB; bundle 4 KiB; store 512 KiB/64 latest anchors; log
256 MiB/1,000,000 records; each record 1 MiB; JSON nesting 32. Limits fail closed;
there is no silent truncation. Segmented logs are a separate integration task.

The implementation acquires one audit or store lock at a time and never calls
`AuditLog.append` or `AuditLog.verify` under the audit lock. Existing approval
validation already calls `verify` with that lock held; changing `verify` to lock
itself would deadlock. The existing lock context now yields its acquired file
handle for protection checks; existing callers ignore that value. This avoids
opening a conflicting Windows read handle while another writer holds the lock.
Large full-chain reads hold the writer lock and can delay appends; schedule them
accordingly. Lock acquisition times out after 15 seconds on Windows and POSIX;
it never enters the critical section on timeout, and only a successfully acquired
lock is released. A busy-lock refusal does not publish an artifact or reset state.
Retry explicitly after resolving contention. No automatic append/configuration
seam is required in this phase.
Any future automatic signing needs a deliberate failure/commit policy because an
event append and detached artifact publication are separate filesystem writes.

Input protection and bytes are checked afresh and rechecked before publication.
Files are flushed and fsynced before atomic publication/replacement. POSIX also
fsyncs the directory. Windows relies on native file/rename behavior; power-loss
durability must be accepted on the actual storage system. New artifacts use an
atomic no-clobber hard-link operation; readers refuse its brief two-link interval.
Imports use the store lock and compare prior bytes before atomic replacement.
A crash may leave a temporary public bundle; the command never reports success
before final readback. A crash during hard-link publication can leave two links,
which validation refuses until an operator checks and removes the temporary link.
A failure after publication can leave the published file
but no success receipt: verify it before retrying. These checks are not a global
transaction with privileged configuration edits or malicious filesystem writers.

## Evidence limits and remaining acceptance

The predecessor reference is a signed assertion of continuity. Without the log,
import cannot independently prove that the new head extends the old hash chain;
`check-log` performs that proof when the complete local log is available. A writer
who also holds the private key can fabricate valid statements, fork an unanchored
history, or lie about event content. A receiver rejects conflicting checkpoints
relative to its retained anchor, but separate receivers can be shown separate
forks until their anchors are compared.

A privileged operator can replace or restore the local store, trust file, or
private key. Rolling back the entire store to an older valid backup cannot be
detected using that same store alone. Preventing this requires independently
retained off-node state, protected receiver administration, and reconciliation.
Deletion never silently initializes new state, but explicit `init` is an operator
action that establishes a new baseline and must be governed accordingly.

External SIEM/shore receivers, actual transfer, acknowledgements, independently
retained anchors, log rotation, automatic approval/kill-switch checkpointing,
hardware key custody, and live enclave/platform acceptance remain open. Local
export/import success must not close those acceptance items or be described as
off-node delivery, hardware non-repudiation, or protection against a compromised
signing authority. Tests use only disposable keys and local temporary files.
