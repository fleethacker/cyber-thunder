# Nessus / ACAS findings import (SCAN-06)

For existing container OS OpenSCAP XCCDF results, use the separate
[SCAP result importer](SCAP_RESULTS.md). It requires explicit target, evaluation
and container provenance and preserves incomplete outcomes. Neither importer
establishes platform applicability or executes a scanner.

Import an offline `NessusClientData_v2` `.nessus` export as a persisted scan run and normalized findings.
The existing `parse` command remains a JSON export utility. Inventory host import is also unchanged.
This workflow does not contact a scanner or target, collect data, propose fixes, approve changes, or apply
remediation. No new runtime dependency is required.

## Host mapping and actor

Every `ReportHost name` must be mapped explicitly to an existing inventory target ID. Names match exactly;
IP, DNS and operating-system guesses are not used. Include every host, even one containing only informational
items. Missing or extra mappings, unknown targets, duplicate source host names, duplicate JSON keys, and
multiple source hosts mapped to the same target are refused before scan/findings writes.

For the bundled `tests/fixtures/parsers/sample.nessus`, a mapping file can contain:

```json
{
  "ws-014.enclave.example": "workstation",
  "10.20.1.30": "server"
}
```

The `workstation` and `server` targets must already exist. Passive imports are allowed for targets marked
out of scope, but their scope flags, credentials, options and other inventory fields remain unchanged.
Importing observations never authorizes access or changes. The target inventory determines `asset_type`.

An authorized actor is required. In verified mode, HTTPS API requests use the
authenticated principal and require both node `import` and `import` grants for
every mapped target; `X-Actor` cannot replace that identity. Grants and original
target generations are rechecked before publication. Import is not a human-only
decision action: a deliberately granted workload principal may import, but this
does not authorize it to approve or apply changes. See [account access](ACCOUNT_ACCESS.md).
Blank, reserved machine/policy actor labels and the generic `operator` fallback
are refused. The local CLI and `X-Actor` examples below are explicitly for
loopback development/replay with scratch state; they are unverified attribution.
Use authenticated API upload in verified mode; a typed local actor cannot bypass it.

## CLI

```powershell
python -m cyberthunder --state-dir .\local-state --actor "IT2 Rivera" ingest scanner .\export.nessus --host-map .\hosts.json
```

Add `--include-info` to retain severity-zero items (including passed compliance checks). By default these
are skipped, matching the existing parser. An export yielding no findings is rejected, not treated as a
clean scan. The command prints a JSON receipt containing `scan_id`, `import_id`, `source_sha256`,
`imported_count`, `targets`, `repeated`, and `carried_forward_count`. Refusals exit with code 2.

## HTTP upload

`POST /api/v1/ingest/scanner` accepts only multipart form data:

| Field | Value |
| --- | --- |
| `file` | Uploaded `.nessus` XML bytes; the filename is ignored |
| `host_map` | JSON object mapping export host names to target IDs |
| `include_info` | Optional literal `true` or `false`; default `false` |

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/v1/ingest/scanner -H "X-Actor: IT2 Rivera" -F "file=@export.nessus" -F "host_map=<hosts.json"
```

Both a new import and an identical repeat return HTTP 200 with the same receipt shape as the CLI.
Invalid input is 400; failed verified authentication is 401 and refused permission is 403;
the generic development actor fallback is 403; an engaged kill switch is 423; a request exceeding
the upload envelope is 413; storage unavailability is 503. The existing actor dependency returns 400 for
missing or reserved actor headers. JSON server-path requests and unknown or duplicate multipart fields
are rejected. Uploads never cause arbitrary server-path reads or persist an original upload in state.

Default readers show the current picture: the latest full baseline plus newer partial imports, preserving
unrelated baseline findings and hosts. Import-only nodes also retain earlier observations as described below.

```text
GET /api/v1/findings
GET /api/v1/reports/poam.csv
GET /api/v1/reports/commander?format=md
```

Use an explicit scan ID to read that historical run alone:

```text
GET /api/v1/scans/<scan_id>
GET /api/v1/findings?scan_id=<scan_id>
GET /api/v1/reports/poam.csv?scan_id=<scan_id>
GET /api/v1/reports/commander?format=md&scan_id=<scan_id>
```

The findings response labels these modes with `view: "current"` or `view: "scan"`. For compatibility,
the top-level `scan_id` in the default response remains the baseline anchor returned by `latest_scan_id()`;
it does not claim that every finding came from that run. Each finding retains its actual producing
`scan_id`. With an explicit scan ID, the top-level ID identifies exactly the requested historical run.
Report scan labels and baseline run metadata likewise identify the anchor for the current picture;
explicit-ID reports restrict their findings to that one run. Omit `--scan-id` for current CLI reports;
passing the displayed baseline ID selects its historical findings. The command printed in a default
commander report likewise omits `--scan-id`, so it regenerates the current view.

## Overlay, provenance and repeat policy

The existing Nessus parser handles CVEs, advisory references, severity, compliance checks and merged ports.
Before invoking its merge, the importer checks individual normalized compliance results. Different statuses
or severities for the same source host/source/rule identity reject the entire export in either order,
including when a conflicting informational result would otherwise be filtered out. Consistent compliance
duplicates and ordinary same-plugin observations across ports still merge. This validation is local to
imports; the standalone parser's behavior is unchanged.

Its source remains `acas`. After host mapping, each finding ID is recalculated using the normal stable
`Finding.make_id(target_id, source, rule_id)` convention. A later import updating that target/source/rule
overlays the same ID. Unmentioned findings and hosts are not cleared or marked clean. Remapping a host
creates different IDs and leaves the earlier observations in history/current overlays.

Each finding retains the scanner benchmark, references and normalized evidence, adds `import:nessus` and
`source-host:<ReportHost name>` tags, and uses `raw_ref=sha256:<source digest>` instead of a temporary path.
The findings document metadata records the digest, complete host mapping, parser options and import ID.
The original XML (including its policy section) is not retained. Normalized evidence can still contain
sensitive scanner output; treat stored findings and reports accordingly.

Imports use `trigger=scanner_import` and a non-empty `rule_filter` containing saved rule IDs. The latter is
required by the current `store.is_partial_run` contract; no new trigger registration is needed.
With a full scan baseline, imports store only their own findings and overlay through `current_findings()`.
Before a full baseline exists, the current store instead uses the newest partial run as its baseline.
To preserve the prior picture in that case, imports carry earlier observations forward, retaining their
original finding scan IDs. `carried_forward_count` identifies those entries; scan totals include them,
while `imported_count` counts only newly supplied results.

The import ID hashes the exact source bytes, canonical host mapping, `include_info`, source label and
import format version. Repeating identical input returns the original scan ID without rewriting findings,
timestamps, inventory or scan history. Actor and filename changes do not create a new import. Repeats are
still human/kill gated and audited. Changed source bytes or options create another partial run, with stable
finding IDs where target/source/rule match. An identical historical import stays historical after a later
full scan; repeating it does not reassert old observations over that scan.

## Bounds and publication

XML is limited to 16 MiB; mapping JSON to 256 KiB; the complete HTTP envelope to their sum plus 64 KiB.
The request stream is checked incrementally even without a Content-Length header. Multipart input must be
one flat form with at most three fields and a 1-70 character boundary. Each part allows at most 8 KiB of
headers and 16 distinct headers. Nested multipart and message containers, duplicate headers, incomplete
delimiters, and non-empty preambles/epilogues are rejected with HTTP 400. Headers are parsed separately
and the body is traversed iteratively; nested bodies never enter recursive MIME parsing. Form parsing,
XML validation/normalization and import publication run in the existing worker thread pool, keeping the
API event loop available for other requests.

XML also has limits of 4,096 hosts, 50,000 report items, 250,000 elements, 32 nesting levels and
65,536 characters per text field
or attribute. Exactly one report is accepted. DTD/entity declarations (including UTF-16 input), malformed
XML, invalid plugin IDs, severity, ports, protocols and CVE identifiers are rejected. Large exports must
be split into bounded, one-report exports outside this workflow.

The complete XML and mapping are validated and normalized before scan/findings writes. A private temporary
file adapts validated bytes to the existing path-based parser and is removed after parsing. Importers share
a cross-process lock. The kill switch is checked on entry and immediately before publication writes.
Findings are saved before the run is published, so a failed findings write cannot expose an empty run.
Audit records contain named actor, digests, counts, inventory IDs and scan/import IDs, never XML, filenames,
source host names, scanner policy credentials or plugin output. Parser and file errors use fixed diagnostics.
`ingest.scanner.publish` records the publication attempt, `ingest.scanner` completion, and
`ingest.scanner.repeat` an already-published repeat. Kill refusals use the existing `action.blocked` event.

## Shared interface needs and current limits

- Persistence uses public `save_findings`, `save_scan_run`, `load_scan_run`, `list_scan_runs`, and
  `load_findings` methods, so scan documents can live in either backend. No new metadata JSON path is
  assumed to be routed into SQLite. The import lock and temporary parser file remain ordinary files.
- StateStore does not expose an atomic operation covering findings, run publication and audit. An interrupted
  import can leave unpublished findings or a publication-attempt audit record. A retry uses the same ID and
  can finish publication. The lock serializes imports, not independent scans/inventory edits. Atomic
  publication with a current-picture snapshot would need a shared storage interface; it is not implemented
  by bypassing the store. Existing full-scan replacement and timestamp ordering semantics remain in force.
- UI upload controls, other scanner formats, scanner connections, automatic mapping, automatic remediation,
  and source artifact retention are outside this import flow.
