# Scan evidence retention: planning and verified archival

This is the first stage of SCL-04, based on release `a2a33c6`. It provides an
explicit dry-run plan and a verified copy of eligible historical scan evidence.
It does **not** complete SCL-04. There is no delete, purge, automatic schedule,
restore-to-live-state, or retention policy for other kinds of state.

## Eligible evidence and conservative pins

`cyberthunder.state.retention.plan()` accepts an absolute state directory and an
explicit backend. Supply exactly one exclusive UTC completion cutoff or positive
integer age in days. Age is resolved to a UTC cutoff in the returned plan. A scan
must have `status=done`, valid explicit UTC start/completion timestamps, both
state documents, and a completion time strictly before that cutoff.

The planner reads a bounded snapshot twice. The returned JSON contains eligible
scan IDs, reasons for pinned scans, the resolved cutoff, limits, an opaque source
fingerprint, and a source manifest with each selected logical path, exact byte
count, SHA-256, and storage origin. It contains no copied proposal, inventory,
policy, session or credential bodies. Plans can still disclose scan IDs and file
names, so keep them private too.

Pins include:

- The latest scan, latest full scan, and latest scan for each target/producer.
- Every scan containing a finding ID in the existing store's current observation
  projection, including unresolved findings preserved by partial or incomplete
  scans and scans of other hosts. Pinning all occurrences of a current finding
  ID deliberately retains more history than the minimum.
- Incomplete terminal scans, incomplete coverage/results, unclassified observations without a scan ID, and
  explicit references from another scan.
- Every scan supplying a proposal's finding, regardless of proposal state.
- All scans when rollback handles, snapshot payloads, outbox/synced payloads,
  unknown reference fields, other state documents or unrecognized files prevent
  a complete reference classification. These pins can leave no eligible scans.

Active scans/jobs/proposals, malformed or unsupported records, mixed backends,
missing run/findings pairs, foreign scan references, and missing or foreign raw
references refuse planning. Raw references must be absolute paths inside that
scan's raw directory or state-relative `scans/<id>/raw/...` paths. Content-hash
references such as imported `sha256:...` evidence have no resolvable local custody
contract here and are refused. Unknown adapter snapshot formats are never guessed.
Known `collected.json` manifests must bind their target and working directory to
the enclosing scan and every listed artifact to a present raw file in that scan.
Unknown collector fields and missing/foreign collector paths are refused.

The planner uses the existing observation projection with captured documents; it
does not create an application context or initialize a state backend. The SQLite
reader opens the existing version-1 documents database with `mode=ro` and
`query_only`. It can participate in SQLite SHM read-mark management; it does not
update rows, migrate schemas, or checkpoint the audit log. A JSON source with a
database, or SQLite with leftover JSON documents, is deliberately refused.

## Exact export and verification

`archive(root, plan, output)` recomputes eligibility and compares the whole plan
against current sources before creating output. It includes exactly the selected
`run.json`, `findings.json`, and raw artifact files in a stored (uncompressed) ZIP,
plus `manifest.json`. JSON files retain their exact bytes, including whitespace
and line endings. SQLite rows retain their exact `body` text encoded as UTF-8;
this is a logical document export, **not** a SQLite database backup. Raw artifact
bytes are unchanged. No archive entry names an absolute path.

The source fingerprint binds file identities/metadata, directory membership,
document/raw hashes, SQLite row update values, DB/WAL hashes and source location.
Audit, inventory, policy and credential/session/token files are never opened for
export; only their filesystem metadata participates in change detection. Known
credential filenames found inside scan evidence cause refusal. This path boundary
is not a content classifier: scanner evidence can itself contain sensitive data.

The output must be a new absolute local path outside the state tree, with existing
protected parents. Existing paths are never overwritten. Every source path is
checked for symlinks, Windows reparse points, hardlinks, special files and unsafe
names. Read files must pass native owner/write-protection checks. Windows uses the
existing native DACL/ancestor protection implementation; output files must deny
foreign read/write access before any evidence is written. On POSIX, output's
immediate directory must belong to the effective user with no group/other access;
the new file is created exclusively with mode `0600`. Ancestors are pinned and
checked with directory descriptors and no-follow opens. Root-owned sticky shared
ancestors such as `/tmp` are allowed; the immediate output directory stays private.
Unsupported protection platforms fail closed. No source permissions are changed.

Default hard ceilings are 10,000 filesystem entries/documents, 16 MiB per evidence
file/document, 128 MiB total captured payload, and 160 MiB archive bytes. A physical
SQLite DB or WAL is individually capped at 128 MiB for hashing. The manifest and
inspection count against bounds. Callers can lower limits, never raise these hard
ceilings. ZIP64, compression, encryption, comments, multi-volume archives, duplicate
or unsafe members, missing/extra members and invalid hashes are refused. Inspection
checks the central-directory bounds before allocating member objects and never
extracts files.

The writer flushes and fsyncs its file, reopens it through the private-file boundary,
checks the whole-file digest and every member against the manifest, then captures
the source again and rechecks the output. Only success returns an accepted receipt
containing the archive SHA-256, source fingerprint, selected IDs, byte/member counts,
and `deletion_enabled=false`. A detected change or output error returns no receipt.
A failed operation can leave an empty or partial private output or a complete but
unaccepted archive. It is preserved for manual review; this module never deletes
or replaces that path. Filesystem/power-loss durability of the directory entry is
not promised by file fsync alone.

`inspect_archive(path, expected_sha256)` repeats private-file and manifest/member
verification against a separately retained whole-file digest. Hashes prove byte
agreement, not who created or authorized an archive. An attacker able to replace
both the archive and its trusted receipt can forge agreement.

## Local CLI contract

These commands extend the existing local `state` CLI. Its verified/fleet-mode
refusal remains in place: a typed actor is not an authenticated human identity.
This batch adds no API routes, per-account export policy, or offline identity mode.
The Python functions are storage primitives, not an authorization service; an
embedding application must enforce its existing authorization boundary.

Examples below are for an explicitly authorized disposable/local development
state. Use absolute paths on the current platform. Create and protect the custody
directory first using the OS, then save the plan there with private permissions.

```text
cyberthunder --state-dir /absolute/test-state state retention plan --backend json --cutoff-utc 2026-02-01T00:00:00Z
cyberthunder --state-dir /absolute/test-state state retention plan --backend sqlite --age-days 90
cyberthunder --state-dir /absolute/test-state state retention archive --plan-file /private/custody/plan.json --output /private/custody/evidence.zip
cyberthunder --state-dir /absolute/test-state state retention inspect /private/custody/evidence.zip --sha256 <separately-retained-receipt-sha256>
```

All successful commands print JSON. Review the plan's eligibility, pins, source
manifest and limits before archiving. Redirected plan output inherits the shell's
permissions; the archive command refuses a plan file that is not private. A stale
or edited plan must be regenerated and reviewed. Protect receipts independently.

The archive is **ordinary unencrypted data**. Private permissions restrict local
access; they do not encrypt removable media, backups, cloud copies or a subsequent
transfer. The operator owns custody, destination access controls, any required
external encryption, and verification of each recovery copy. This selected scan
export does not replace a complete local recovery copy of the whole state tree.
Complete recovery still requires quiescing every writer and preserving all state,
including audit/checkpoint, inventory, proposals, policy, rollback data, database
and WAL where applicable, under the existing backup procedure.

## Open interfaces and SCL-04 remainder

Snapshot comparisons detect observed mutation; they cannot prove that no writer
will create a reference immediately after a check. File read protection and store
lifecycle locks do not freeze all proposal, snapshot, outbox, API, adapter, or
other-process writers. **No plan or successful archive receipt authorizes deletion.**

Before deletion can be enabled, a proven cross-process maintenance/transaction
boundary must cover admission and every reference owner, and hold through source
validation and deletion. This needs a complete, versioned reference index across
proposals, snapshots, queues, reports, findings/reviews and future extensions, with
defined handling for unsupported producers. Native filesystem race checks are
defense in depth, not that transaction boundary.

Further work includes authenticated API/user authorization for planning/export,
account/resource filtering with complete reference visibility, audit events for
authorized retention decisions, deletion approval and recovery semantics, archive
custody/restore tooling, schedules, and all-kind retention policy. Those changes
belong to their interface owners. This batch does not change store/context,
security, core, API, UI, adapters, inventory or audit behavior.

## Validation

The dedicated retention tests use temporary fixtures only, for JSON and SQLite.
They cover exact-byte/hash round trips, current unresolved observations, rollback
and proposal preservation, stale plans, separate-process reference/document writes
during archival, malformed/foreign sources, output collisions, byte/count bounds,
corrupt archives and native private-file negative calibration. Native Windows DACL
tests use only registered disposable roots; native Linux tests use private local
temporary directories. Validation receipts and complete source recovery exports
are retained separately under the batch's local build evidence directory. No live
state retention, target access, full gate, dependency installation or network
operation is part of this validation.

Final focused selection on 2026-11-06:

```text
python -m pytest tests/state/test_retention.py tests/state/test_backends.py tests/test_store.py tests/state/test_cluster_overlays.py tests/security/test_identity_boundary.py::test_local_cli_cannot_bypass_verified_mode -ra --tb=short
```

- Windows Python 3.12.10: **206 passed**, 79.58 seconds.
- Native Linux Python 3.12.16, serial on CPU 1: **206 passed**, 7.15 seconds.
- No skips. Both reported the existing Starlette/httpx test-client deprecation
  warning. No dependencies were changed.
- Tested source tree: `1c5472ba900b0592a4d593d17b88a4928344c885`. All 1,140
  files in the native export matched their Git blob hashes, with zero mismatches.
  The final documentation-only addition records these results; implementation and
  test bytes remain those tested. Local sanitized receipts, hashes, complete source
  archive and Git recovery bundle are under `.build/state-retention-20261106-a2a33c6/`.
