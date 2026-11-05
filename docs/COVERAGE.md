# Check and fix coverage

Open **Reports > Check & fix coverage**, or run:

```sh
python -m cyberthunder report coverage
```

```sh
python -m cyberthunder report coverage --format json --out coverage.json
```

HTML and Markdown downloads are available in the Reports page. The API is
`GET /api/v1/reports/coverage?format=html|md|json`. A report does not need a scan
and never connects to a target. Rendering is recorded in the audit chain.
The commander report includes the supplied-benchmark counts and their limitations.

## What is counted

The installed native-check table reports implemented checks separately from
catalog entries. Descriptive metadata alone is not a check. Built-in catalogs
are subsets, so they never provide a full-benchmark denominator.

The supplied-benchmark table reports six counts per document and release:

1. Published rules: every XCCDF Rule in that document, before selecting a profile.
2. Native ID matches: distinct rules matched to an implemented native check.
3. SCAP eligible: distinct rules with structurally resolvable OVAL definitions;
   the Windows path also requires the installed evaluator's supported probes.
4. Rules with executable fixes: distinct rules mapped to a library payload of a
   kind the adapter can execute, with a rollback declaration.
5. Rules with runbooks only: a manual procedure exists, with no executable fix.
6. No mapped check: rules with neither a native match nor an eligible SCAP mapping.

Native and SCAP sets overlap; adding them overcounts. A native catalog entry,
an XCCDF fix-text paragraph, a shared CCI citation, a patch entry or a hunt entry
does not create executable STIG coverage. Rule IDs identify mappings, not proof
that old check logic implements a newer release's text (VAL-03 remains open).

The separate fix-library inventory counts every contributed entry once per adapter
and fix reference, grouped by kind and source. These counts include hunt and patch
entries. They do not equal the number of unique STIG rules with fixes. Entries
generated from scan-time ComplianceAsCode output are excluded. Cisco entries
derived from shipped range configurations may be absent from an installation
that does not include those fixtures; counts describe what is actually installed.

## Content and deployment

Default sources are the repository's `STIG/`, the node's imported
`ingest/catalog/`, and extracted datastreams in `content/scap/`, all under its
configured state directory except `STIG/`. Native installations and containers
use the same report. Container images need imported content in their mounted
state volume because the repository's `STIG/` is not necessarily in the image.

To inspect a particular directory instead of those default sources:

```sh
python -m cyberthunder report coverage --benchmark-dir /path/to/xml-content --format html
```

The override is CLI-only and cannot be combined with `--queue`; use `--out` to
export selected content. Queued coverage reports use the node's default content
sources. The HTTP endpoint cannot select arbitrary filesystem paths.
Import/extract ZIP files through the existing Content updates workflow;
coverage reads XML, deduplicates identical content by SHA-256 and lists unreadable
or malformed sources as errors. Different releases remain separate. A manual
benchmark borrows SCAP eligibility only from a matching benchmark ID and release.
For a split XCCDF/OVAL pair, content identity includes the companion files and
whether each is missing; a complete pair is never discarded because an identical
XCCDF without its companions was found first. Companion changes are re-read on
each report. JSON includes source and content hashes, companion hashes, and
individual mapped/unmapped rule IDs for review. Unavailable adapter catalogs are
listed as incomplete inventory without breaking reports for the other adapters.

With no usable benchmark XML, totals and gaps are **unknown**, not zero and not
100 percent. The report does not download content, scan an asset or change state
apart from the normal report audit record.

## Capability is not a successful scan

Linux eligibility counts content that can be handed to external OpenSCAP; the
report does not run that evaluator or establish its probe support. Windows counts
use the current evaluator's structural preflight. Both still depend on host OS,
profile, privileges and collection results. RHEL content can be not applicable
on Rocky. Unknown/error/not-reviewed scan outcomes must not be read as passes.

As checked against the content shipped on 5 Nov 2026, the RHEL 9 V2R10 manual
benchmark has 445 rules and its SCAP datastream has 393. Their 52-rule difference
is visible even when every seeded range item is detected. The bundled native
Linux checker has 20 STIG-ID checks plus four local checks; its metadata catalog
contains 29 STIG entries. The Kubernetes catalog has 20 entries, but the active
check functions reference 17. These are implementation counts, not certification.

No executable-fix count proves a payload safe on every version. Approval,
scope, host prerequisites, before-state capture and verification still apply.
Use [VALIDATION](VALIDATION.md) for recorded real-host evidence.
