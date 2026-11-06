# Offline release inventory candidate review

Reviewer: Joshua Ott. Date: 2026-11-06.

This bounded review covers candidate `48663d961acbe6eae07593298ff89f22ecba9056`
against parent `96c18233f2d8c8234e01109e04229613ac73e829`, on
`codex/release-inventory-review`. The parent-to-candidate diff added only the
collector, its tests, and its documentation. Corrections are limited to those
files and this review. The candidate remains FUTURE work, outside the current
release. No full gate, publication, push, deployment, or vulnerability scan ran.

## Findings reproduced and corrected

| Severity | Reproduction on the candidate | Correction and evidence |
| --- | --- | --- |
| P2 | A lock entry with a 1,025-character version was accepted, although the primary CycloneDX component-version schema permits at most 1,024. | Enforce the schema limit for every component version. The negative case fails before correction and passes afterward; a 1,024-character version still succeeds. Independent schema validation rejects the overlong fixture. |
| P2 | An unused JSON field containing 65 nested arrays was accepted. The byte limit and eventual interpreter recursion error were the only nesting constraints. | Scan all JSON text before decoding, with a 64-container nesting ceiling. Tests cover the exact boundary, escaped quotes/backslashes, delimiters inside strings, malformed and duplicate-key inputs, and a 1,000-level CLI input producing neither artifact nor receipt. This strengthens resource bounds; no exploit or network access was demonstrated. |
| P2 | The application appeared among peer components, without a designated BOM subject in `metadata.component`. | Move the declared repository application to the root, without duplicating its reference. Missing project metadata remains an explicit gap. Root absence is schema-valid, so this was an identity/interpretation gap rather than an original-artifact schema failure. |
| P2 | Running the collector against a repository containing a different `scripts/release_inventory.py` recorded only that repository copy's digest. | Add `generator-sha256` for the executing script file, retain the target copy in source evidence, and recheck the executing file at completion. A fixture with differing copies verifies both digests remain distinct. |

The original 18 tests passed independently. Four new regression checks then
failed on the original implementation (two failed assertions, two missing-field
errors), recorded in `before-fixes-tests.txt`. After corrections, all 27 focused
tests pass without skips on Windows Python 3.12.10 and native Linux Python
3.12.16. Additional negative coverage includes hard-linked UI assets and dirty
source edits whose Git status bytes remain identical while source digests change.

## Evidence interpretation and security review

The collector records declarations and observed bytes honestly. It does not
invent installed components, dependency closure, package licenses, image contents,
build provenance, or vulnerability results. Whole-wheel hashes and CRC checking
do not authenticate RECORD, publishers, installation, or platform compatibility.
Lock integrity strings are declarations. Image references and build argument
defaults remain declarations. No dependency graph or verified license fields are
manufactured. Incomplete composition and explicit unresolved coverage remain.

Path checks reject traversal, absolute/drive paths, symlinks, junctions, hard-linked
files, and non-regular inputs. ZIP checks bound directory allocation, member count,
compression ratio, expanded bytes, and metadata size, reject duplicate/link/encrypted
members, and read members for CRC checks without extraction. Text, cumulative
bytes, directory entries, components, and encoded artifact size have finite bounds.
The depth limit now applies even to ignored JSON fields. Existing negative tests
exercise traversal, symlinks on both platforms, CRC corruption, expansion/metadata
budgets, count tampering, and directory/byte budgets.

Static review found no network client in the collector and no dependency-package
import, extraction, metadata execution, or package-manager invocation. The focused
test blocks Python sockets, restricts subprocess invocation to Git without a shell,
and uses a wheel with an import-time failure payload. Git reads use a limited
environment, bounded output/time, and disabled filesystem monitoring. This is
bounded evidence under a trusted local Python/Git installation, not a process
sandbox or proof against a hostile executable on PATH.

HEAD commit/tree, dirty-state hash, consumed-source hashes, and executing-script
digest have distinct meanings. Dirty and ignored bytes are not represented by
the HEAD tree. Rechecks detect ordinary changes but do not create an atomic
snapshot: a hostile concurrent writer, file replacement race, or script mutation
between loading and hashing remains outside the assurance. Use quiescent inputs.
Missing inputs produce gaps; malformed present inputs fail. Output I/O failure
can leave a partial artifact, so require successful completion and a matching
receipt. Manifest extraction remains limited to documented literal line forms.

## Reproduced counts and platform comparison

The preserved original artifact independently validates against the primary schema,
and its receipt matches its bytes. An independent candidate run produced 241 array
entries with the same category counts. After correction there are 240 array
entries plus one root application: 47 wheels, 165 npm lock entries, 3 UI assets,
21 image references, 2 requirements files, 1 UI declaration, and 1 build argument.
There are 75 consumed-source records. These are observed inventory counts, not
installed-package or shipped-bundle counts.

The corrected Windows/Linux artifacts are byte-identical. Linux generation and
tests ran on the native Linux filesystem at
`/home/joshua/release-inventory-review-48663d9`, using the requested native 3.12
environment. Its bounded sparse snapshot retained the exact candidate HEAD/tree,
consumed bytes, and matching dirty status; unrelated tracked blobs were omitted
with skip-worktree index entries. This establishes collector portability for
identical selected inputs, not a full Linux build or whole-repository test.

Independent validation used task-local `jsonschema` 4.26.0, Draft 7, the primary
[CycloneDX 1.6 schema](https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json)
and its local SPDX/JSF references. Retrieval occurred during validation setup;
schema checks ran with sockets blocked. Actual artifacts, missing/unknown root,
and external-model fixtures validate. Schema validity does not establish coverage.
No mandatory runtime dependency was introduced.

## Exact retained evidence

Original evidence remains untouched under the `oidc-validation` worktree's
`.build/release-inventory/`. Review evidence is retained under this worktree's
`.build/release-inventory/`; it is intentionally not published or committed.

| Evidence | SHA-256 |
| --- | --- |
| Original `windows-48663d9.cdx.json` | `5f8eac9f9aeefc1d5c3d0425afe78757022755e507b92a9962e99e3a589aad1e` |
| Original `windows-48663d9.receipt.json` | `3ddc0b38f6454a13a0b376d332269203feae963d8f82a64b41473bfb209e72e5` |
| Both `windows-reviewed-dirty.cdx.json` / `linux-reviewed-dirty.cdx.json` | `3d1d6b7a9494a81f640ce00eff0914ae521412c54eb48bd44996f9b93493388f` |
| `windows-reviewed-dirty.receipt.json` | `b14e7c0cc9743309b6fc682c041e49d0cd9259074b08bf7c53816e410c544154` |
| `linux-reviewed-dirty.receipt.json` | `5fd12bffe222dcabb3e8fa75fc8eb2b1c6a675f7b81e222f4eb7f09c4453bd26` |
| `reviewed-validation.receipt.json` | `6969d43bda35860cfd4e976146dfdaf8ef7f61c723452649514e3bde33f66ac6` |
| Corrected `scripts/release_inventory.py` | `485ff3904e0e3eeac879618a7d3e22c9ada92e8ee5ee01c1393ab901c6f676b1` |
| Corrected `tests/test_release_inventory.py` | `8f08369a1f5f09b343aa396ecca8f34e5abc0ebc4bae20cf213b0f0b393993bf` |

The reviewed-dirty artifacts explicitly identify candidate HEAD above, HEAD tree
`f6e0d864a987c1bf0793a25dcb0d63f3783deb72`, dirty inputs, and source-set SHA-256
`a944a71407a28bb521bc0a3a7ed1862e2d852010455c0c35fef386ffab865b8a`.
They were captured before adding this review document. Their receipt metadata
contains every consumed path/size/digest. The independent validation receipt also
retains exact primary schema hashes and validator version. Test logs are
`windows-tests.txt` and `linux-tests.txt`; the baseline reproduction log is
`before-fixes-tests.txt`. Later clean-commit evidence, if produced, must use new
filenames and preserve these receipts.

The corrected collector is suitable for further FUTURE partial-evidence review.
It does not complete ATO-02 or authorize the current release. Dependency closure,
licenses, trusted build provenance, release image selection/content, deployed
runtime/model identity, and vulnerability scanning remain separate work.
