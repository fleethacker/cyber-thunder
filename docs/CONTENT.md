# STIG Library and content updates

How new STIG releases and SCAP benchmarks reach a Cyber Thunder node, with the link up or down.

Open **STIG Library** (`/content`) for local files, catalog releases, product/type subscriptions,
downloads and offline imports. Settings links here. Opening the page or refreshing its local view reads
the cached catalog (or bundled snapshot); it does not check cyber.mil or download files.

Content pulls never change a host. They are read-only downloads from two DoD web hosts, verified before
use, and every step is written to the audit log.

## How content reaches the node

| Situation | Path |
|---|---|
| Link up | **Check live index** or `ingest check` reads the public index; **Download selected** or `ingest pull` downloads the chosen files. |
| Link down | `ingest manifest` writes the list of wanted-but-missing files. A connected machine runs `ingest fetch-manifest` and the folder comes back on removable media for `ingest import-dir`. |
| Hand import | **Transfers / import** uploads XML or ZIP files from the browser computer, even offline: one file per request, at most 32 MiB each. Multiple selections upload sequentially with individual results. Legacy `ingest stig <zip\|xml>` remains available. |
| Reconnect | After the outbox flush, saved `check_on_reconnect` enables a live check; saved `auto_pull` enables a check followed by a pull of matching updates. Defaults come from server settings (normally true/false). |

Every accepted manual STIG or SRG goes through the catalog import: the delta
against the catalog copy is stored, and the changed rules can be rescanned from the delta (the
**Rescan changed rules** button, or `ingest rescan <delta_id>`).

## Update selections and freshness

The default is **Follow inventory recommendations**, not every STIG in the index. **Choose products manually**
uses saved product checkboxes and works without inventory targets. **Use inventory recommendations** copies
the current recommendations into a manual selection. Type checkboxes select `manual_stig`, `srg` and
`scap_benchmark` (all three enabled by default); no products in manual mode or no types means no matching files.

**Save selections** before checking, downloading or exporting a manifest. Saving persists subscriptions only;
checkbox changes never start a download. All-matching pulls and manifests use saved subscriptions.
Download checkboxes choose files for a single transfer; they are separate from persistent product subscriptions.
Concurrent preference edits require reloading the latest saved revision before saving again.

`check_on_reconnect` and `auto_pull` apply only when the link reconnects. Auto-pull includes a fresh check even
if the check-only switch is off. Manual and scheduled checks do not auto-pull. Periodic checks are configured
on the server with `CT_CONTENT_CHECK_INTERVAL_SECONDS` (0 disables them), independently of the reconnect switches.

| Library field | Meaning |
|---|---|
| Last live index / Snapshot index | The locally cached public index or bundled snapshot used for comparisons; neither label means a network request just ran. |
| Index saved | When the live index was cached; absent for the bundled snapshot. |
| Last successful live check | Last completed live check; snapshot checks and local imports do not advance it. Failed attempts and their errors are shown separately. |
| Last download / Last local import | Separate successful receipt times; deltas created by pulls do not advance the local-import time. Publisher dates and catalog release versions describe the content, not when this node received it. |
| Local files / Imported catalog | Content held on this node, including earlier catalog imports. A legacy catalog import need not have a held-file record. |
| Bundled reference | XML shipped with the build, not downloaded or installed through content sync. |

Local event times include the date, time and timezone offset. **Matches index** means only that the held version
matches the local index. An old snapshot, no subscriptions or a node never checked live cannot establish that
everything is current. Retired and external-only products remain visible as unavailable.

Unverified local uploads remain visible as reference content but do not suppress official updates, even when
their product/version metadata matches. Downloaded files and legacy imports, including lock-file imports,
retain their existing update-comparison behavior.

Catalog rule counts and installed content are not executable scan coverage. Manual STIGs and SRGs provide
guidance; scanning depends on implemented checks or a supported scanner/benchmark configuration. See
[COVERAGE](COVERAGE.md) and [SCAP](SCAP.md).

## What is pulled for which assets

In inventory mode, the node uses in-scope targets and the platform facts its last scan recorded for each host
(`collected.json`). A host without facts can name its products in the target option
`stig_products` (a list of product keys, for example `["RHEL_9"]`).

| Asset type | Facts | Product keys |
|---|---|---|
| windows | os_name names Windows 11, 10, Server 2016, 2019, 2022 or 2025 | `MS_Windows_11`, `MS_Windows_10`, `MS_Windows_Server_<year>` |
| windows | domain controller (tag `dc`, option `role: domain_controller`, or a DC domain role) or `part_of_domain` | also `Active_Directory_Domain`, `Active_Directory_Forest` |
| linux | RHEL, Rocky, AlmaLinux 8, 9, 10 | `RHEL_<major>` |
| linux | Oracle Linux 8, 9 | `Oracle_Linux_<major>` |
| linux | Ubuntu 20.04, 22.04, 24.04 | `CAN_Ubuntu_<yy-mm>` |
| linux | SLES 15 | `SLES_15` |
| cisco_ios | os_name IOS or IOS-XE; role from option `role` or tag `router`/`switch` (default switch) | `Cisco_IOS_Switch`, `Cisco_IOS_Router`, `Cisco_IOS-XE_Switch`, `Cisco_IOS-XE_Router` |
| kubernetes | (none needed) | `Kubernetes` |
| containers | (none needed) | `Container_Platform` (an SRG) |

For each subscribed product the node selects the newest non-retired, allow-listed release of the enabled
types. Inventory mode considers SCAP for Windows and Linux; manual selection can request a product's SCAP
benchmark without a target. This selects content, not proof that every rule can execute. Automation packages
and the quarterly compilation are outside the three subscription types. A check lists what it skipped and why:
unsupported host, no matching entry, sunset release, superseded release, or a file on a host outside the allow-list.

## Allow-list, caps and checks

- Hosts: exactly `www.cyber.mil` (the index) and `dl.dod.cyber.mil` (the files). HTTPS only, certificate
  verification on, redirects followed only while they stay on those two hosts. The allow-list is in code,
  not in settings.
- User-Agent `cyber-thunder/<version> (content pull)`. The environment's HTTPS proxy settings apply.
- Index answers are capped at 4 MB; files at 512 MB (`content_max_bytes`), checked on Content-Length
  and on the bytes actually read.
- Downloads resume: an interrupted file stays as `<name>.part` and continues with `Range` and
  `If-Range: <ETag>`. A changed ETag, or a server that answers the range with the whole file, restarts it.
- Before a file is accepted: SHA-256, a zip CRC test with path and size limits, and for manual STIGs and
  SCAP benchmarks a parse of the XCCDF or datastream inside. A file that fails moves to
  `<state>/content/quarantine/` with a `.why.json` note.
- Downloaded content is never executed. Accepted guidance is imported into the rule catalog and SCAP
  datastreams are indexed for explicit scanner configuration. Zips are opened with `zipfile`; XML is parsed with
  ElementTree; no file name from inside an archive is used as a path.
- The kill switch stops live checks and pulls: a new live check or pull is refused, and a running pull stops within about half a second, mid-file, keeping the .part so a later pull resumes it. A link that goes down mid-file stops the pull the same way.
- Browser uploads require a named actor and a released kill switch. They accept supported XCCDF/SCAP XML
  or a single benchmark ZIP package, with archive and XML resource limits. Validation checks structure and
  integrity, not publisher authenticity. Unknown product/version metadata stays unknown; rejected content
  may appear in quarantine. Use the manifest/folder workflow for bulk offline transfers.
- Folder imports require a named actor and check the kill switch before starting and between files.
  Stopping an import leaves previously accepted files in place.

## What is logged

| Action | Details |
|---|---|
| `content.check` | url, bytes on the wire, seconds, source, entries, updates (or `blocked` when the link is down) |
| `content.fetch` | url, bytes, seconds, sha256 |
| `content.fetch_failed` | url, bytes so far, seconds, error |
| `content.quarantine` | url, seconds or bytes, sha256 when known, reason |
| `content.import` | source path, bytes, sha256 |
| `content.manifest` | manifest path, bytes, sha256, item count |
| `content.preferences` | previous and saved selections, revision, named actor |

The import of a manual STIG also writes the usual `ingest.stig` record with the delta id.

## Where content lives

```
<state>/content/
  files/<name>                   files as downloaded or imported
  scap/<product_key>/<name>.xml  SCAP datastreams extracted from benchmark zips
  quarantine/                    refused files with a .why.json note
  index.json                     one record per held file (product, version, sha256, ETag, source, ingest)
  last_check.json                the last check
  catalog.json                   the last index seen (used for manifests while the link is down)
  preferences.json               saved products/types, reconnect options, revision and actor
  sync.json                      live-check attempts/success, download and local-import times
  jobs/<id>.json                 pull jobs with per-file progress
  manifest.json                  the default manifest location
  source.json                    the cached cyber.mil class id
```

`ingest content` (or `GET /ingest/content`) prints the path of every extracted datastream.
The JSON document paths above (index, last check, catalog, preferences, sync, source and jobs) are logical:
with `CT_STATE_BACKEND=sqlite`, they live in `state.db`. Raw content and manifests remain files. Persist and
back up the entire state directory, not just the database; see [STATE](STATE.md).

## Making a scanner use a pulled SCAP benchmark

The scanners do not switch content on their own. The operator points a target at the datastream path
that `ingest content` prints:

| Adapter | Target option | Value |
|---|---|---|
| Windows | `scap_datastream` | `<state>/content/scap/MS_Windows_11/U_MS_Windows_11_V2R11_STIG_SCAP_1-3_Benchmark.xml` |
| Linux | `benchmark_path` | `<state>/content/scap/RHEL_9/U_RHEL_9_V2R10_STIG_SCAP_1-3_Benchmark.xml` |

Both adapters support these options. Windows reads `scap_datastream` on the Cyber Thunder node.
Linux reads `benchmark_path` on the target host: copy the extracted datastream to that host and set
the target-side path before scanning. A path under the node's content store is not automatically
available on a remote Linux host. See [SCAP](SCAP.md) for profile selection and applicability limits.

## The disconnected round trip

Save subscriptions first. In the UI, **Download manifest** exports the missing matching files;
**Import folder** takes a path on the server, not on the browser computer. Browser uploads transfer the
selected local files directly and do not require a connected link.

On the node, link down:

```
cyberthunder ingest check --snapshot
```

```
cyberthunder ingest manifest --out E:\manifest.json
```

On a connected machine with Cyber Thunder installed (no node state needed):

```
cyberthunder ingest fetch-manifest E:\manifest.json --out E:\stig-content
```

This writes `E:\stig-content\manifest.lock.json` with the SHA-256 of every file. Back on the node:

```
cyberthunder ingest import-dir E:\stig-content
```

```
cyberthunder ingest content
```

Files are checked against the lock file; any file that does not match is quarantined and listed. A folder
without a lock file (DISA zips copied by hand) is imported on the integrity checks alone.

Raw XML without a lock-file entry whose filename/index does not identify its type uses the same validated import as a
browser upload, capped at 32 MiB per file. New records show **Uploaded locally**, with import time/actor and
metadata read from the XML; invalid or oversized files are listed as refused. Lock-file entries and known
content retain the existing manifest/integrity checks and folder-import provenance.

With the link up the same result is one step:

```
cyberthunder ingest check
```

```
cyberthunder ingest pull --all --wait
```

## Settings

Server defaults below apply until library preferences are saved. The periodic interval and transfer limits
remain server-configured; the UI displays the interval without editing it.

| Setting | Default | Meaning |
|---|---|---|
| `content_check_on_reconnect` / `CT_CONTENT_CHECK_ON_RECONNECT` | true | initial `check_on_reconnect` preference |
| `content_auto_pull` / `CT_CONTENT_AUTO_PULL` | false | initial `auto_pull` preference; check and pull matching updates on reconnect only |
| `content_check_interval_s` / `CT_CONTENT_CHECK_INTERVAL_SECONDS` | 0 | periodic live checks in seconds; 0 disables; never auto-downloads |
| `content_max_bytes` | 512 MB | per-file size cap |
| `content_timeout_s` | 30 | per-request timeout |
| `content_snapshot` | bundled | index snapshot used by `check --snapshot` and for manifests before any live check |

## How the index is found

The STIG library page is a Salesforce site; its catalog comes from one anonymous Apex call
(`getCyberDocumentCatalogByDocumentLibrary` with `documentLibrary: STIGs`). The class id in that call
changes when the site is redeployed. If the known or cached id is refused or answers with something that
is not JSON, the node reads the downloads page, follows the `sTIGs_Document_Library_view` bundle it names,
takes the class id next to that method, retries once and caches the new id in `source.json`.
