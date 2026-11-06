# DISA publication accounting and index availability

The STIG Library accounts for each raw row in an accepted DISA catalog, including
duplicate publications, missing links, malformed rows, tools, documents and
retired releases. Browse all includes a publication search above the existing
product maintenance controls. Downloaded files and saved maintenance selections
retain their separate meanings.

The bundled 2026-11-04 snapshot reconciles **417 of 417 rows**: **242 supported**,
**59 unsupported**, and **116 sunset**. These are publication classifications,
not counts of executable checks or supported targets.

## Classification and search

| Classification | Meaning |
| --- | --- |
| Supported | Recognized ingestion format, valid publication fields, and a URL permitted by the content policy. Files still require the existing integrity and content checks on receipt. |
| Unsupported | Metadata remains searchable, but the format is not ingested, required fields are malformed, or the download URL is unusable or outside policy. Reasons accompany each row. |
| Sunset | DISA's download-type metadata marks the publication retired. It remains searchable and is excluded from automatic selection; any other format or URL problems remain visible. |

Supported formats are manual STIG, SRG, SCAP benchmark, automation ZIP, and
compilation ZIP. Automatic maintenance continues to select only the existing
manual STIG/SRG/SCAP choices. Automation and compilation downloads require their
existing explicit opt-in; their scripts are never executed by the content
library. Documents, tools and unrecognized formats are metadata only. Unsupported
formats and malformed publication records are rejected before a pull creates a
download; they cannot enter automatic selections or generated manifests.

Publication search examines the full saved list before pagination. It includes
title, filename, product, release, publisher date, DISA record name, download
types, classification, reasons, URL, and all original publication metadata (for
example Topic, Classification, and DocumentLibrary). Duplicate names and URLs
remain separate rows. The row's original metadata is available in an expandable
detail. Missing or invalid metadata is retained rather than silently dropped.
Publisher dates are not replaced with local retrieval times.

Product maintenance remains limited to recognized STIG/SRG/SCAP products. A
previously selected product remains in saved preferences even if it disappears
or becomes unavailable. Publication search does not change these preferences,
download files, stage content on targets, or establish scanner coverage.

## Live index unavailable and snapshot operation

A failed/non-catalog or empty live answer triggers one bounded class-ID
rediscovery through the download page and its view bundle. An all-malformed
answer is also rejected. An accepted response must contain at least one
identifiable publication, but every row in that response is retained, including
malformed neighbors. A newly discovered Apex class ID is persisted only after
it returns an accepted catalog. Changed pages/bundles, a second empty response,
network errors, and invalid compressed responses produce an explicit
**Live index unavailable** state.

A failed index fetch preserves the prior catalog, its saved timestamp, the last
successful check timestamp, and the prior check report. The failed attempt and
index error are recorded separately. With no usable cached entries, browsing
falls back to the supplied snapshot. An old empty cache does not count as a
successful live catalog. `source: live` describes the origin of saved data; it
does not mean the live service is currently reachable or the data is fresh.

Use **Check supplied snapshot** in the library, or run:

```console
cyberthunder ingest check --snapshot
```

This works while disconnected. The result reports snapshot comparisons for the
saved selections; the UI shows the publication and update-candidate counts. A
snapshot check does not advance live success timestamps, erase a live error,
replace the last live catalog, or download files. The main library continues
using its saved catalog (or snapshot when no usable cache exists). Existing
manifest export and offline import remain available as documented in
[Content updates](CONTENT.md).

## Compatibility and integration

`content/catalog.json` adds `schema_version: 2` and `accounting`, while preserving
the existing `entries`, `source`, `saved_at`, and `stats` structure. Each entry
adds `raw_position`, `publication_metadata`, and `record_errors`; serialization
also exposes its derived classification, reasons, and format eligibility.
Raw positions are one-based and preserve duplicate rows. UI publication IDs
identify positions within this particular saved catalog, not permanent identity
across catalog refreshes.

The library response adds `publications` and
`catalog.accounting = {raw_entries, represented_entries, complete, supported,
unsupported, sunset}`, plus `catalog.live_status` and `catalog.live_error`.
These are additive fields; existing products, preferences, held files, selection,
and timestamp fields remain available. Content-check reports also include the
accounting summary. The UI declares the optional additions in its library
component; no generic client, authentication, API routing or dependency change
is required.

Older cache entries are still readable and classified. Because an older parser
may have dropped rows, their reconciliation says `complete: false` and
`raw_entries: null`; a successful new live check is needed to establish complete
accounting for that cached live catalog. Snapshot checks can independently
reconcile the full supplied snapshot. Unknown derived fields are ignored when
reading entries, preserving compatibility with older readers' existing field
filtering. File and SQLite state stores are covered by the tests.

## Acceptance and validation

- CON-05 implemented: full snapshot reconciliation, searchable raw metadata,
  explicit classifications/reasons, duplicate and malformed-row retention,
  guarded selections/downloads, and backward-compatible cache reads.
- CON-02 implementation and fixture acceptance implemented: changed Apex ID
  recovery, refusal to persist an unverified ID, empty/unusable index rejection,
  changed-page unavailability, preserved successful state, and explicit offline
  snapshot comparison.
- Connected metadata acceptance: a bounded canary at 2026-11-06 02:06:38 UTC,
  against source commit `24489ca4e331a60817e0406335bdf22d2163857d`, used the
  normal HTTPS client and the public catalog endpoint. The response contained
  417 entries, all accounted for: 242 supported, 59 unsupported and 116 sunset.
  It transferred 16,059 compressed bytes (192,854 decoded bytes) in 0.594
  seconds. The known class ID still worked; rediscovery remained fixture-tested.
  No benchmarks were downloaded or imported, and no targets were contacted.
  This is evidence for that deployment and time, not a guarantee of future
  availability or measured physical link bandwidth.

Focused regression coverage is in
`tests/ingest/test_catalog_accounting.py`, the existing content index/selection/
library/service/fetch/upload tests, the library API tests, and the STIG library
component/page tests. It covers malformed object and scalar rows, malformed URLs
and ports, embedded credentials, controls/encoded path separators, oversized
version numbers, false sunset metadata, unsupported formats, duplicate rows,
missing links, saved preferences/local provenance, both store backends, empty
responses, changed deployment IDs/pages, and offline snapshot behavior.

Measured worker results (2026-11-05):

- Shared Python interpreter with `PYTHONPATH` set to this checkout:
  `python -m pytest -o addopts= tests/ingest/test_catalog_accounting.py tests/ingest/test_content_index.py tests/ingest/test_content_select.py tests/ingest/test_content_library.py tests/ingest/test_content_service.py tests/ingest/test_content_fetch.py tests/ingest/test_content_uploads.py tests/api/test_content_library.py -q`
  — **380 passed, 41 deprecation warnings, 99.07 seconds**. The warnings concern
  existing Starlette TestClient and FastAPI lifecycle APIs.
- From `cyberthunder/ui`:
  `node --test src/components/LibraryTables.test.mjs src/components/LibrarySelections.test.mjs src/components/ContentUpdates.test.mjs src/pages/ContentTasks.test.mjs`
  — **26 passed, 0 failed**.
- `npm run build` — **passed**, including `tsc -b` and the Vite production build.

The integration owner runs the combined repository gates and builds the final
UI distribution. Generated UI distribution files are not part of this change.
