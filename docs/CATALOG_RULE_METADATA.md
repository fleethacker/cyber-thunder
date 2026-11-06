# Native check catalog metadata candidate

This is a bounded part of VAL-03. A scan can attach metadata from an explicitly
selected, active local manual catalog to findings produced by existing native
Linux, Windows, Cisco and Kubernetes checks. Importing another authorized release
of that same lineage changes the annotation on the next scan without changing
check code. A renamed SV rule ID is matched through the exact stable STIG ID in
the XCCDF Rule/version field.

This does **not close VAL-03**. The imported release has not been assessed by the
old native implementation. Metadata is stored under
the optional finding field `catalog_rule_metadata`; existing top-level IDs, title,
severity, references, benchmark/release, result and remediation fields continue
to describe the bundled native check. Consumers must not present a native pass
as a pass against the annotated release. Every annotation explicitly records
`assessment: not_assessed`; the collection summary records `coverage_added: 0`.
No compatibility inference is made from stable STIG IDs, including when the
current catalog's check requirements have changed or are unknown. The native
evaluated release remains separate from the current catalog reference; neither
confidence nor standing-policy authorization is upgraded by that reference.

## Explicit selection

Use the existing inventory target options, through its authorized editing path.
No configuration, authorization or publication format changes are required.
For example, a target whose native RHEL 9 metadata should reference the exact
local benchmark identity `RHEL_9_STIG` can declare:

```json
{
  "native_catalog_bindings": {
    "linux_rhel9": {
      "product_key": "RHEL_9",
      "benchmark_id": "RHEL_9_STIG"
    }
  }
}
```

The benchmark ID must be copied exactly from the intended local publication;
the example is not an alias. A binding is an operator declaration of the intended
product/lineage, not proof of platform applicability. Selection does not infer
equivalence from titles, filenames, discovered OS names or `stig_products`.
There is no automatic RHEL/Rocky/Alma, Windows Server/Windows 11 or IOS/IOS-XE
equivalence. Each binding accepts exactly `product_key` and `benchmark_id`.

| Family key | Native adapter/source | Required product key | Stable STIG ID prefix |
| --- | --- | --- | --- |
| `linux_rhel9` | Linux / `native` | `RHEL_9` | `RHEL-09-` |
| `windows11` | Windows / `windows-stig` | `MS_Windows_11` | `WN11-` |
| `cisco_ndm` | Cisco / `cisco_ios` | `Cisco_IOS-XE_Switch` | `CISC-ND-` |
| `cisco_l2s` | Cisco / `cisco_ios` | `Cisco_IOS-XE_Switch` | `CISC-L2-` |
| `cisco_rtr` | Cisco / `cisco_ios` | `Cisco_IOS-XE_Router` | `CISC-RT-` |
| `kubernetes` | Kubernetes / `kubernetes` | `Kubernetes` | `CNTR-K8-` |

Only STIG IDs actually present in that adapter's bundled extract are eligible.
Cisco families require separate exact benchmark bindings. Unknown families,
wrong adapter/product combinations and extra binding fields are errors.
Release pins are deliberately unsupported: a `release` field is rejected, never
silently treated as a request for the current release. Historical catalog paths
and SCAP lineages are not selected by these bindings.

## Read and provenance contract

Configured reads require the existing node `read` authority in addition to the
scan's target authorization. Reads use `publication.read_scope`, honoring an
outer pinned snapshot. One snapshot supplies all configured families for one
target. Different targets in a long scan can observe different generations;
each target/finding records its exact snapshot. Authority is checked again after
the read and before annotation; the scanner retains its existing authorization
check before publishing results. Configured metadata also requires a fresh node
`read` authorization immediately before the scanner writes collected results,
after coverage and known-good processing.

Only the active `catalog` lineage is considered. Its committed product must
exactly match the binding, its publication must be trusted under the existing
publication policy, and its catalog must be a matching single Benchmark.
The receipt exposes only assurance status, attestation/signature booleans,
document/key digests when present, and the original unsigned/unknown-signer status
for an authorized exception. Private override reasons, actor identities, key
locations, scopes, signer labels and URLs remain in the authoritative local
receipt. Source type is an enumerated label; filenames are sanitized basenames.
No receipt is relabeled a publisher signature or evidence of the newest release.
Only the existing `operator_attested`, `human_override`, and
`trusted_https_source` assurance classes can supply rule references, and only
when the ledger also marks the publication trusted. Development and unknown
assurance classes are explicitly untrusted for this feature.

The ledger's integrity checks remain authoritative. Every active publication's
source and derived artifacts are rechecked even inside an outer pinned read
scope; this includes untrusted development publications. The exact catalog bytes
being parsed are also checked against their committed size and SHA-256, even
inside an existing pinned read scope. XML uses the existing bounded parser that
refuses DTD/entity declarations. Legacy state is validated by the existing
generation reader but never promoted to active metadata. Missing/corrupt managed
ledgers, artifacts, inconsistent lineage/product references, unreadable content
and read-authorization failures propagate as scan target errors. They do not
produce a successful bundled fallback. Previously persisted findings are not
rewritten or cleared by such a failure. The catalog's parsed release must also
match its committed lineage, and the explicit benchmark identity must match the
lineage itself.

The additional reference reader limits each bundled JSON file to 2 MiB and a
nesting depth of 32, catalog XML to 32 MiB, rules/bundled rows/annotations to
10,000, metadata text to 4,096 characters, each emitted record to 16 KiB, and the
combined annotations plus collection summary to 8 MiB. Existing XML depth and
element limits still apply. JSON duplicate keys and duplicate bundled STIG IDs
are errors. Limits fail before attaching any annotations or publishing a scan;
metadata is never silently truncated. These limits apply to this reader; they
do not replace the shared publication ledger's existing read/size policy.

Each annotation contains:

- The original finding ID, source, rule ID, stable STIG ID, native result and
  bundled benchmark/release; the original evidence stays in the finding.
- The bundled extract's relative source path and SHA-256.
- The pinned ledger generation and selected publication generation (which can
  differ when another product was published later).
- The source package's SHA-256/size, sanitized filename, source type, public authenticity facts
  and publication bookkeeping status.
- The exact catalog SHA-256/size, benchmark ID/title, version, release text,
  normalized release/scheme and catalog rule count.
- For a unique match, the current catalog rule ID, STIG ID, enclosing group ID,
  title, severity and CCIs. These are reference metadata, not new check coverage.

The collection's `raw.catalog_rule_metadata` summary retains the configured
catalog receipts and counts by mapping status, including when no eligible native
findings were emitted. Unknown catalog severity remains `unknown`.

## Mapping outcomes

| Mapping status | Meaning |
| --- | --- |
| `not_configured` | Bundled extract only; no local catalog was requested or read. |
| `no_active_catalog` | Explicit binding has no active manual-catalog lineage in the validated snapshot. |
| `untrusted_active_catalog` | Active development content is labeled, but its rule metadata is not used. |
| `matched` | Exactly one catalog Rule/version matches the original stable STIG ID. |
| `missing` | The active catalog does not contain that exact stable STIG ID. Absence alone does not establish withdrawal. |
| `withdrawn` | A unique match explicitly carries withdrawn, deprecated or obsolete status on the rule or benchmark. |
| `ambiguous` | Duplicate STIG IDs, multiple Rule/version values, or missing/empty/ambiguous title fields prevent a unique match. |

Only fields in the benchmark's XCCDF namespace participate. Foreign versions do
not establish a match. Titles allow plain text or a bounded set of XHTML text
formatting; embedded check/fix elements do not become titles. Duplicate benchmark
titles also prevent a unique rule reference. Explicit benchmark or rule
withdrawal remains conservative even alongside an accepted status.

All outcomes have `assessment: not_assessed`. Missing or ambiguous mappings do
not borrow an ID from a similar title or reference. Unmatched annotations label
their available metadata as `bundled_extract`. No new findings are synthesized
for unimplemented catalog rules, and absent native findings are not counted as
passes. Existing native findings retain their original status, including a pass
against the bundled check; that status is separate from catalog assessment.

## Execution and identity boundary

No imported descriptions, check text, fix text, scripts, OVAL references, Ansible,
commands or fix attributes enter executable checks or the remediation library.
Only the listed metadata fields are read into annotations. The scanner annotates
fresh output after adapter detection and existing rule filtering. It does not
relabel saved results, rerun detection, change finding IDs or alter approvals,
known-good matching, evidence, fix selection or verification selectors.
Catalog metadata is separate from `collection_provenance` because collector
provenance participates in the existing evidence fingerprint. The new optional
field preserves that fingerprint and review scope across catalog-only changes;
older findings deserialize with a null field. No review or approval policy is
changed, and stored historical documents are not migrated.
The optional field is appended after the existing dataclass fields so legacy
positional construction keeps its meaning. Its name, version-1 envelope, mapping
statuses and `not_assessed` contract are unchanged. Consumers must tolerate the
documented public subset of authenticity facts; private receipt extensions are
not a display contract.

External OpenSCAP, SCC, Evaluate-STIG and PowerSTIG results retain their actual
scanner metadata. Linux native results already merged into an OpenSCAP finding
are intentionally excluded. Hunt, CVE, CIS and custom non-STIG checks are also
excluded. Direct adapter calls and remediation verification calls outside the
scan orchestrator keep their existing behavior. Filters continue to use the
native/bundled identifiers; selecting by a newly imported SV ID is not added.

## Validation and remaining work

Focused tests use disposable JSON and SQLite stores, local signing keys and
synthetic single-benchmark XML, with network access blocked in the metadata test
module. They cover every listed family, renamed IDs across release upgrades,
historical result preservation, explicit fallback, withdrawal, missing/ambiguous
rules, wrong products/lineages, unsupported pins, authorization revocation,
corruption after snapshot pinning, concurrent publication and actual scanner
integration. Imported script content is never executed or copied into findings.
Assertions preserve the existing evidence fingerprint, review scope and entire
confidence assessment even when a matched catalog has different check text,
title, severity and rule ID.
Native rule, parser, scan and remediation-identity regressions supplement them.
The independent review adds calibrated failures for source corruption inside a
pinned scope, private receipt disclosure, unknown assurance, metadata ambiguity
and resource limits, plus authorization revocation after annotation. Real native
Windows/Linux simulator findings retain their complete semantics and selected
fix payload through apply/verify/rollback despite changed catalog requirements
and an additional unimplemented catalog rule. Exact runs, hashes, counts and
remaining limits are recorded in `docs/CATALOG_RULE_METADATA_REVIEW.md`.

A separate structural inspection on 2026-11-06 UTC parsed the repository's
`STIG/U_RHEL_9_STIG_V2R10_Manual-xccdf.xml` (1,400,286 bytes, SHA-256
`3fcb716d5ca2bf539460b7baca42c1a6a65e1faff619737b1e88ffb25db87541`).
It read all 445 unique rule IDs with no ambiguous or withdrawn rows, and found
reference matches for all 29 bundled Linux IDs. The reader used an in-memory
synthetic publication envelope only; it activated no content, created no
attestation, verified no publisher identity and evaluated no targets. This
confirms structural compatibility with those exact local bytes, not current
release freshness, publication acceptance or native-check compatibility.

The [finding detail panel](CATALOG_REFERENCE_UI.md) displays reference metadata
separately from the recorded native release, with an explicit `Not assessed`
label. It does not add coverage or change confidence and approval decisions.

Before full VAL-03 closure, a separately reviewed design must establish when a
new release's changed requirement is still implemented by an existing check,
represent newly withdrawn/missing controls as assessment outcomes without losing
native observations, and expose active metadata in downstream consumers without
breaking historical findings, targeted rescans, approvals or remediation keys.
Explicit historical release pinning and product applicability validation remain
open. No operational platform acceptance, live downloads or full release gate is
claimed by this candidate.
