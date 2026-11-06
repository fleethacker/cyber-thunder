# Content publication and recovery

This is a controlled-rollout feature for local content stores. It does not assert operational, human or ISSO acceptance. Stop old writers before enabling it, retain a complete backup, and test the selected backend on disposable state first. Do not run older binaries against a managed store. There is no automatic downgrade or migration switch.

## Commit and read contract

The old low-level `delta.apply` mutation helper refuses writes; callers must use the authorized ingestion service. All import/upload/direct STIG ingestion and pull publication enters the same cross-process publication lock. Validation and signature policy precede publication. Source bytes, extracted catalogs/datastreams and complete delta reports are prepared in immutable paths. A required `content.publication_intent` audit append must succeed before activation, and current authority, signature evidence and kill-switch state are checked again before commit.

One replacement of `content/index.json` is the activation point. The configured StateStore routes that document to JSON or SQLite; both use the same OS publication lock to coordinate artifacts and writers. The ledger holds generation, complete records, active benchmark references, release floors, consumed request IDs and the durable audit-intent reference. Artifact presence, filenames, job progress and audit completion markers alone never establish activation. Composite content/library reads pin one ledger snapshot. Historical artifact paths are not overwritten. Callers configured to old catalog/datastream paths continue reading historical bytes; configuration changes are outside this feature.

The release order is derived from validated benchmark identity and internal release metadata, with a shared catalog lineage for manual STIG/SRG and a separate SCAP lineage. Changing a catalog title from STIG to SRG cannot bypass its floor. The direct STIG diff entrypoint continues to accept a validated single XCCDF Benchmark containing automated checks; it does not treat a datastream collection as a manual catalog. DISA version/release pairs and explicit numeric triples are comparable only within their scheme. Recognizable filename, archive-member and declared release claims must match the content. Duplicate identities, incompatible release schemes, same-release changed package bytes and partial replacement of an active multi-benchmark package are refused. Packages with unknown releases remain readable references and cannot establish verified active authority. Even a repackaged ZIP with changed bytes is a distinct package and cannot silently replace the same accepted release.

Signatures attest provenance; they are not freshness proof. Normal upgrades raise the accepted release floor. Explicit downgrades preserve that floor. An exact active package with the same assurance class returns its existing receipt. Development-only unsigned imports remain `unsigned_dev` and never supply a verified floor or verified provenance. A later verified import cannot silently certify those bytes. A genuinely empty verified node can perform its first authorized import without baseline review.

## Exceptional local maintenance

Use the library's Import/transfer view, or the existing local-import API. Automatic pulls and actual network acquisition cannot carry exceptional publication intent. The legacy STIG route/CLI directs exceptional cases to Import/transfer; a typed actor name is never consent.

1. Choose the candidate file, or a server folder containing exactly one package (with its lock/request documents where applicable). Submit the normal import. Authenticity requirements still apply: for unsigned or unknown-signer content, explicitly request the existing authenticity exception and give its separate reason.
2. A bounded HTTP 409 review response displays candidate/current release and SHA-256, accepted floor, and whether this is a legacy baseline or deliberate downgrade. Nothing activates because of that refusal.
3. Review these values, enter a separate activation reason, check the explicit review confirmation, and select **Confirm this activation**. The caller must still be a verified human with import and admin authority and satisfy existing step-up checks.
4. Changing the file, folder, account/session or observed generation discards the pending review. A 409 or reauthentication never automatically resubmits it. A new refusal requires a new explicit confirmation.

The optional `publication_intent` input is an object on `POST /api/v1/ingest/import-dir` and a JSON text form field on `POST /api/v1/ingest/content/upload`. Existing response keys remain. Each package commits independently. A later package or cleanup failure returns the already committed records, refused processing details and additive `status: partial` / `commit_status: committed_with_bookkeeping_pending`; it does not claim the whole bundle failed. For an exceptional decision, isolate the candidate in a one-package folder. It contains exactly:

```json
{
  "mode": "downgrade",
  "expected_generation": "<64 lowercase hex characters from review>",
  "candidate_sha256": "<64 lowercase hex characters from review>",
  "review_sha256": "<64 lowercase hex characters from review>",
  "request_id": "<unique 16-80 character letters/digits/underscore/hyphen identifier>",
  "reason": "Separate, explicit reason for this activation"
}
```

`legacy_baseline` is the other mode. The 409 detail has code `content_publication_review`, the three binding digests, candidate/current release arrays, candidate byte count, a legacy-state digest and session/policy digest. It is bounded to 16 validated identities and uses `Cache-Control: no-store`. The service recomputes the review over current state, the verified identity/session and policy. A stale review cannot authorize a commit. This is a binding protocol, not a bearer approval token.

A consumed request ID cannot authorize another intent, candidate or owner. Repeating the exact request returns the existing committed outcome, including whether it is still active; it cannot reactivate a historical generation. The UI consumes its local confirmation before sending and does not automatically retry an uncertain response. An API caller reconciling a lost response can submit the exact same request ID and intent with current authentication and authenticity evidence.

## Legacy and corruption

Pre-generation files and catalogs remain readable history with unverified provenance and inactive status. Saved trust labels, generation-looking metadata and filenames cannot bootstrap authority. A first verified publication alongside legacy bytes requires explicit baseline review bound to those bytes. Each lineage needs its own baseline decision; the decision does not certify legacy history or suppress the current signature policy.

Unindexed legacy files (including content beside a missing legacy index), unreadable legacy files, mismatched saved hashes, malformed catalogs, missing/corrupt active artifacts, inconsistent floors and incompatible/missing managed ledgers fail closed. Baseline review cannot repair corruption. Do not delete the guard or ledger to simulate an empty node. Retain evidence and restore a separately validated complete state backup in a stopped-writer recovery procedure. Backend switching needs a controlled, validated state handoff; this feature intentionally provides no online JSON/SQLite conversion or corruption-repair endpoint.

## Interrupted publication

| Interruption | Read/retry behavior |
| --- | --- |
| Before required audit or before ledger replacement | Previous snapshot remains active; prepared files are uncommitted orphans. A new explicit normal import may prepare another generation. |
| Audit succeeds, process stops before commit | Audit intent alone is not activation. No completion is inferred. |
| Backend raises near the commit | Re-read the authoritative ledger and match the generation. A visible committed generation returns its receipt; no automatic second activation. |
| Commit succeeds, audit outcome/transfer/job bookkeeping fails | Return `committed_with_bookkeeping_pending`. Durable job receipts reconcile stale progress on reads. No replay or false failed activation. |
| Process stops just after commit | Fresh readers see the committed generation and pending bookkeeping. Exact retry returns that generation; it does not generate another delta or consume another intent. |

Records add `generation`, `active` and `commit_status`; held-content snapshots add `generation`. Status is `committed`, `committed_with_bookkeeping_pending`, or `legacy_history` for legacy records. A committed reference can have `active: false`. Postcommit audit completion is best effort; the required precommit intent is not. Reads do not fabricate a missing audit completion or silently retry audit delivery. Durable publication bookkeeping can remain pending until a separately controlled repair is provided. A cleanup failure is reported on that response; the committed ledger itself may already be complete. Orphans are retained; no automatic garbage collection touches historical content. A stopped, uncommitted pull may retain stale progress; operators must reconcile it rather than assume it is still executing or completed.

## Acceptance boundary

Internal DISA release claims must agree across the version and release-info fields. Missing active-lineage references and split activation of a multi-benchmark package require controlled recovery; readers cannot fall back to a legacy catalog in those states. Upload batches stop before sending another file when the account/session, selection or mounted view changes. A late completion cannot overwrite the replacement view; reconcile committed outcomes through the library.

Dedicated tests use isolated JSON/SQLite stores, real local signing keys, injected failures, abrupt child-process termination, competing processes and pinned readers. Network-related regression fixtures use loopback only. Process interruption is different from power loss: the existing JSON metadata writer does not fsync its directory, and SQLite uses its configured durability mode. This feature does not claim power-loss durability, network-filesystem/SMB/ReFS acceptance, protection from privileged local state tampering, or detection of whole-state rollback from backup. Detecting whole-state restore requires an external monotonic anchor and an operational recovery policy; hashes and signatures alone cannot provide it. Neither signature verification nor publication review proves a release is the publisher's newest release.
