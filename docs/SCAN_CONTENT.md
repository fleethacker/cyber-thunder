# Scan content and coverage

The Scans page reads a local preflight before a scan. It lists inferred or configured product applicability, manual STIG holdings, SCAP holdings, and the last observed scanner capability separately. Missing OS facts leave applicability unknown. The first scan can collect those facts and refine the next preflight.

Preflight does not contact a target, cyber.mil, or a model. It does not inspect configured network paths, download content, install software, or write an audit event. A recorded capability includes its observation time and age. Observations older than 24 hours, invalid timestamps, or a changed target/scanner declaration are marked stale. Even a recent observation is not a current probe or a readiness guarantee.

## Getting content

Use a product link to open the STIG Library. Browse the relevant manual guide or SCAP benchmark, explicitly check for updates and download the selected release when connected, or use the existing import workflow for content brought in offline. Maintained-product preferences govern automatic update selection. Starting a scan never initiates a content pull.

A manual STIG guide is reference material. A SCAP ZIP held in the local library is a download record, not proof that executable content is configured or readable by the scanner. Imported catalogs and executable datastreams serve different purposes.

- Linux runs `oscap` on the target. `options.benchmark_path` names content already on that target; `options.profile` optionally selects its profile. Downloading a ZIP to the operator node does not stage it on the target. Any installation or staging remains a separate, explicit operator action.
- Without an explicit Linux benchmark path, automatic SSG selection requires a filename matching the observed distribution identifier and release under `/usr/share/xml/scap/ssg/content/`. Ubuntu selection includes the release's minor version. Missing facts, mismatched releases, or no unique match stop SCAP selection. Compatible-family product recommendations do not authorize a RHEL datastream for Rocky or Alma. A filename match is limited evidence, not validation of the XML's actual applicability.
- Windows native checks run independently. Optional SCAP evaluation uses `options.scap_datastream`, an extracted datastream on the operator node, and optional `options.scap_profile`. A configured path remains unverified until collection attempts it. Benchmark applicability is displayed as unverified; unsupported or unevaluated rules are not passes.

## Reading results

Each new scan stores coverage and warnings in the per-target result and in `collected.json` under `raw.coverage`. A successful collection can still have incomplete STIG coverage. The `done` scan status means the run finished, not that every applicable control was assessed or that the host is clean. Legacy runs without coverage metadata display unknown coverage.

Linux reports missing OpenSCAP, missing or mismatched content, missing profiles, failed evaluation, and missing result artifacts. Native findings continue to be returned. A failed OpenSCAP evaluation does not fetch an old remote results file as if it were fresh. Windows reports unconfigured or unreadable optional SCAP content while preserving native findings.

The current coverage service deliberately does not assert complete control coverage. New runs carry `coverage_incomplete: true`; individual scan findings remain only the observations from that run. The current findings view overlays those observations and retains unobserved historical finding IDs with their original timestamps and provenance. An explicit newly observed pass can replace an earlier failure for the same finding. A missing observation cannot manufacture a pass or clear a previous finding. The run remains selectable as the newest full scan; requested scan scope and proven coverage are separate.

Older retained findings are historical evidence, not proof that the condition still exists. Review their collection times and reassess the relevant checks. Independently assessed cluster-image scopes retain their own reconciliation rules. JSON and SQLite integration tests cover these boundaries and the finding-review lifecycle.

## Interface

`GET /api/v1/scans/preflight` accepts repeated `target_ids` and `modules` query parameters; omission uses in-scope inventory targets and the normal module set. It returns `version`, `generated_at`, `local_only: true`, `automatic_downloads: false`, `modules`, and `targets`.

Each target contains `applicability`, `products` with separate manual/SCAP holding status, `native`, `scanner`, `warnings`, and local UI action links. `scanner.last_observation` retains the previous capability record when the current status is unknown or stale. `TargetScanResult.coverage` uses this same shape with `phase: observed`, observed finding counts, and `complete: false`. This is coverage evidence, never approval authority.
