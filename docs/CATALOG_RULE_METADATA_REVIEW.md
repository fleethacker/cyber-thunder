# Native catalog reference review

Review basis: `e5e7beaf3c88ea100c7e16526af79b110c08bdb5`, on the local
`catalog-metadata-review` work branch. The five candidate Git blob hashes match
the supplied validation handoff. The review is limited to the catalog metadata
reader, additive finding field, scan annotation/authorization hooks, metadata
tests, and these two catalog documents.

This remains reference metadata only. Every annotation is `not_assessed`, and
every collection summary adds zero coverage. A stable STIG ID, a renamed SV ID,
a changed title, and a trusted catalog receipt establish neither semantic
compatibility nor platform applicability. The original native evaluated
ID/title/severity/release/result, confidence, evidence fingerprint, approval
scope and executable fix remain authoritative and unchanged.

## Findings fixed

1. **Pinned integrity gap.** The candidate rehashed the selected catalog XML but
   an outer read scope bypassed fresh validation of its source package and other
   active artifacts. Development publications returned before the XML recheck.
   The reader now rechecks every active publication's committed artifacts in
   that same pinned generation, including development content. It still hashes
   the exact XML bytes it parses, detecting a change after the artifact pass.

2. **Private receipt disclosure.** Copying the entire authenticity receipt
   exposed authorized override reasons and operator identities in ordinary
   findings. A real protected-policy fixture with a human override reproduced this.
   An explicit public subset now retains assurance labels/booleans and digests;
   private reasons, actors, scopes, signer labels, URLs and key paths remain in
   local publication records. Source types are enumerated and filenames are
   sanitized basenames. Unknown assurance never supplies rule references, even
   if a malformed retained ledger marks it trusted.

3. **Unbounded or ambiguous metadata.** Bundled JSON previously had no byte,
   depth or duplicate-key protection. XML's general bounds did not constrain
   per-record annotation growth. Explicit reader/output limits now fail before
   mutating any findings. Duplicate bundled rows/keys, oversized values, unsafe
   identifiers and misleading control characters are rejected. Empty or
   duplicate titles, duplicate versions, foreign namespace metadata and embedded
   check content cannot become a unique reference. Benchmark titles and
   withdrawal status participate in conservative mapping decisions.

4. **Authorization gap before scan publication.** A node read grant could be
   revoked during coverage processing after annotation. The existing scan-only
   check did not cover that grant. Configured metadata now receives another
   node read authorization immediately before collected results are written.
   A real protected-policy revocation test proves the target fails, no newly
   annotated findings or collected document is published, and prior findings
   remain intact.

5. **Lineage and constructor consistency.** The explicit benchmark ID now must
   match the selected lineage itself; the catalog's parsed release must match
   the committed lineage. Malformed pinned-ledger fixtures exercise these
   checks, without claiming protection against privileged whole-state tampering.
   The optional dataclass field is appended after existing fields to preserve
   legacy positional arguments as well as deserialization.

The public `catalog_rule_metadata` name, version-1 envelope, mapping statuses and
reference-only contract remain available. Authenticity is deliberately a public
subset, not an arbitrary receipt mirror. No display/API integration is included.

## Validation

| Run | Passed | Failed / errors | Skips | Metadata JSON / SQLite | Seconds |
| --- | ---: | ---: | ---: | ---: | ---: |
| windows-regression.xml | 964 | 0 / 0 | 0 | 75 / 75 | 290.534 |
| linux-regression.xml | 964 | 0 / 0 | 0 | 75 / 75 | 167.175 |

These are 964 distinct tests per platform, including 150 metadata cases.
Both final processes exited zero. No test was skipped or deselected in these
focused runs. The source hash manifest was verified in the Linux snapshot
`/home/joshua/ct-catalog-review-o0k_p9y7` and rechecked in the Windows
checkout after validation: zero source drift.

The initial negative calibration ran 44 cases (22 JSON, 22 SQLite): all 44 failed
against the candidate implementation, with zero errors or skips. The failures
covered pinned source/development corruption, private receipt/path disclosure,
unknown assurance, ambiguous or foreign metadata, and JSON/XML/record limits.
An intermediate 124-case run had 122 passes and two stale error-message
expectations after corruption began failing earlier; those expectations were
corrected. The next run passed 142/142, followed by 8/8 additional text/race
boundary cases. Final totals include these cases once, not as extra coverage.

The final selection is:

```text
tests/ingest/test_catalog_rule_metadata.py
tests/linux
tests/windows
tests/cisco
tests/kubernetes
tests/test_schema_and_parsers.py
tests/parsers
tests/engine/test_scan.py
tests/engine/test_rollback_identity.py
tests/findings/test_review_identity.py
tests/ingest/test_scanner_import.py
```

Every state fixture in this selection runs against JSON and SQLite. The 150
metadata cases divide evenly between them. Native Windows and Linux simulator
findings retain their entire original document, confidence, approval scope and
fingerprint after annotating a changed requirement plus an additional
unimplemented catalog rule. The selected native fix digest stays unchanged;
apply/verify/rollback still completes and restores the original failing check.
No imported check or fix executes. External scanner findings remain unchanged.

The suite runner blocks socket connect, connect-ex, connection creation and DNS
resolution. Tests use isolated local state, fixture content and simulators.
There is no full release gate, live target, network acquisition, push or merge.

Windows interpreter: existing Python 3.12.10 from the coverage-report checkout's
`.venv/Scripts/python.exe`. The exact machine path is retained in
`windows-regression.txt`.

Linux interpreter:
`/home/joshua/cyber-thunder-linux-validation-20261105-f7018959/venv312/bin/python`
(Python 3.12.16). The Linux run uses a separate native filesystem snapshot with
the exact regression-manifest bytes, not the Windows checkout.

## Source and retained evidence

Evidence directory:
`C:/Users/joshu/AppData/Local/Temp/ct-catalog-review-rg8bjwxi/`.
It contains XML results, logs, the offline runner, candidate/reviewed path
hashes, the source archive and manifests, and build-evidence verification.

The regression source manifest covers 1,092 tracked files. Its SHA-256 is
`00298dea68a0e0df4fa0fa77a44d84f73973a921675f97c77902b8dcea9f9a46`.
This review document is added after the regression snapshot. A separate final
manifest includes it; implementation and test bytes remain identical to the
regression snapshot.

| Reviewed path | Bytes | SHA-256 |
| --- | ---: | --- |
| `cyberthunder/catalog_rule_metadata.py` | 17589 | `80d3d61a21e652853c2d53b01946f566c24ad46d25f454f973988e638005cc29` |
| `cyberthunder/findings/schema.py` | 9430 | `7b7813dc23c868f5014f74ac139d97d9d0a65b6f669595cf064d4779667f8535` |
| `cyberthunder/scan.py` | 19795 | `b96b56b54d1904d8c764fb987107efa964178a69ed0149b6d88ead92c0eb0399` |
| `tests/ingest/test_catalog_rule_metadata.py` | 32785 | `7fe4c7170a3251f046980ca854ddc1240c1793826ea2e7398d49e5eb77005105` |
| `docs/CATALOG_RULE_METADATA.md` | 12855 | `3dade5b81befb63f6e81df9ebde0051ec857c6d79bb2de36eded175892e3d7a6` |

The four bundled extracts remain unchanged: Linux 29 rows, Windows 19, Cisco 30,
Kubernetes 20. These are 98 metadata rows, not 98 validated controls. The source
manifest records their exact hashes. Inputs are synthetic; no real catalog was
downloaded or accepted operationally.

All 2,462 pre-existing readable `.build` files in this checkout were inventoried
and rehashed: zero changed or missing. This checkout's baseline contains zero
reparse entries. It is distinct from the supplied handoff's earlier inventory.
Baseline inventory SHA-256:
`b11f767c58ca58c38005a59a10337cfa2c8986ca1dabf06f930d52a98e2c1017`.
No ignored prior review evidence was removed, reset or overwritten.

## Open limits

- External real-catalog and semantic acceptance remains open. No new validated
  controls, platform applicability, release freshness or full VAL-03 completion
  is claimed. Conservative metadata bounds and XHTML handling still require
  evaluation against separately acquired operational catalogs.
- The existing publication ledger remains the trust authority. This change does
  not redesign its JSON/storage bounds, signing-key lifecycle, durability,
  privileged-tamper model or atomicity with authorization policy updates. The
  added checks enforce read-time integrity and authorization at the documented
  checkpoints; they are not a transactional filesystem/security boundary.
- No release pins, product aliases, inferred OS equivalence, new-ID targeted
  rescans, historical rewrites or imported remediation are introduced.
- Direct adapter calls, remediation verification and native findings merged into
  external OpenSCAP results retain their existing paths. Display consumers must
  respect `not_assessed`; downstream integration remains separate work.
- The current release remains frozen elsewhere. This is a local reviewed
  backlog candidate with no changes to UI/API, authorization internals,
  maintenance/publication internals, global backlog, README, CI or distribution.
