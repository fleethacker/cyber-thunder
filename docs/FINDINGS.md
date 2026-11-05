# Finding and sorting results

The Findings page searches the current findings picture: the latest full scan with newer targeted
rescans and bulletin matches overlaid. Its baseline scan label identifies the full scan; it does not
mean partial results have been excluded. Explicit historical scan IDs remain available through the
[findings API](API.md#findings-query-contract).

## Quick views and search

- **Open STIGs** selects STIG-category results that remain open.
- **Open CVEs** selects CVE-category results that remain open.
- **All open** selects every open result, including hunts and other checks.
- **All results** includes passed, not applicable, not assessed and collection errors as well as open results.

Each quick view replaces the filters and clears search, keeping the chosen sort. **Clear filters**
also shows all results. **Reset defaults** returns to all open results with the original priority sort.
Search, filters and sorting persist in this browser through refresh and navigation using local preferences.
Pagination returns to page one when a filter or sort changes.

Search matches CVE and STIG references, rule IDs/versions, group IDs, title, machine ID, source,
benchmark and release. It is a case-insensitive substring search, not a query language. Multiple
selections in one filter mean any of those values; different filters must all match.

## Categories and available metadata

Categories use the finding's existing evidence of provenance:

| Category | Evidence used |
|---|---|
| STIG | STIG rule/ID references; recognized `SV-…r…_rule`, `V-…` or STIG ID patterns; STIG-specific sources (`evaluate-stig`, `powerstig`, `windows-stig`, `ckl`, `cklb`); or a benchmark name containing the word STIG |
| CVE | CVE references or `CVE-yyyy-nnnn…` identifiers, or sources `cve`, `nvd`, `iavm` |
| Hunt | `hunt` source, a `hunt` segment in the rule identifier, or `attack`/`mitre_attack` references |
| Other | No evidence for any of the categories above |

A finding can belong to STIG, CVE and Hunt together. Selecting more than one category returns their
union without duplicating rows. Other is the fallback category. Merely mentioning STIG, CVE or hunt
in a title does not classify a finding. OpenSCAP, SCC, ACAS and Trivy may emit different kinds of
checks, so their source names alone do not establish a STIG or CVE category.

Benchmark and release filters use only recorded finding metadata. They do not infer releases or
join to downloaded catalogs. **Not recorded** selects absent or blank fields. Unrecognized asset
types and sources remain visible and selectable.

Every selector is searchable. Option counts come from the entire selected findings view, before
filtering and pagination, so narrowing one filter does not remove choices from another. Selected
values absent from a refreshed view remain available with a zero count and can be cleared.
The page displays matching versus total counts and the range shown on the current page.

## Scanner result and remediation

| Display | Existing API status |
|---|---|
| Failed / open | `open` |
| Passed | `not_a_finding` |
| Not applicable | `not_applicable` |
| Not assessed | `not_reviewed` |
| Collection error | `error` |

These statuses primarily describe scanner/check outcomes. Kubernetes known-good exceptions can also
change matching open results to Not applicable on later scans; their tags and evidence record the
exception and reason. That exception mechanism is not a confidence score or a separate review disposition.
Confidence and human review are separate columns and filters. High, Medium, Low and Unknown are
deterministic evidence-strength categories with reasons, not probabilities; see [CONFIDENCE](CONFIDENCE.md).
The drawer records Confirmed, False positive, Not applicable, Needs investigation or a reversal to
Unreviewed, with reason, supporting evidence and history. Suppression requires a future expiry and
reopens when relevant evidence changes. Reviewer names are self-asserted until identity integration lands.
See [FINDING_REVIEW](FINDING_REVIEW.md). These decisions never change stored scanner observations.
Human approval remains in the proposal workflow. Existing verified fixes display as passed; the
original scanner status stays in `scanner_status` and remediation metadata. A newer scan finding the issue open again takes precedence.
The API retains that existing remediation decoration even when an explicit scan ID is requested.

**Explain all open** queues the existing explanation operation for all open findings, independent of
the page filters. Open a finding using its rule/identifier button to inspect evidence and any proposal.

## Ordering and scale

Default priority keeps the original order: highest severity, open first, machine, then STIG ID/rule.
Choose an explicit field and ascending/descending direction for severity, machine, asset type,
category, title, rule ID, STIG ID/rule version, source, observation time, benchmark, release, confidence or review.
Observation time compares actual instants across time zones. Text sorts ignore case; releases sort
as text, not semantic versions. Category sorting compares each finding's alphabetically ordered
category names. Equal sort values always use finding ID ascending. Missing values and unknown
severity stay last in either direction for explicit sorts.
Unknown confidence also stays last in either direction. Review order is Unreviewed, Needs investigation,
Confirmed, False positive, Not applicable (reversed for descending).

The API filters and sorts before returning pages of 200 rows. Facets describe all findings, not just
those 200 rows. Processing uses the public StateStore API and works with JSON and SQLite; it currently
loads the selected view into memory. There is no database index or new persistence format in this change.

## Local verification

Focused API tests cover both backends, overlapping categories, combined filters, identifier search,
facets beyond the first page, missing values, stable ordering, observation time zones, current partial
overlays, explicit historical scans, verified remediation, empty views and invalid input:

```text
python -m pytest tests/api/test_findings_query.py tests/api/test_core.py tests/api/test_review_fixes.py
```

Build the UI from `cyberthunder/ui` with `npm run build`.
