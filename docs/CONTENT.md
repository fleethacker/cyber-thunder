# DISA content updates

How new STIG releases and SCAP benchmarks reach a Cyber Thunder node, with the link up or down.

Content pulls never change a host. They are read-only downloads from two DoD web hosts, verified before
use, and every step is written to the audit log.

## How content reaches the node

| Situation | Path |
|---|---|
| Link up | `ingest check` reads the public STIG index on cyber.mil, works out what the inventory needs, and `ingest pull` downloads it. |
| Link down | `ingest manifest` writes the list of wanted-but-missing files. A connected machine runs `ingest fetch-manifest` and the folder comes back on removable media for `ingest import-dir`. |
| Hand import | `ingest stig <zip|xml>` or the upload on the Settings page, as before. |
| Reconnect | After the outbox flush, the node runs a check on its own (`content_check_on_reconnect`, on by default) and, if `content_auto_pull` is set, pulls every update. |

Every pulled or imported manual STIG goes through exactly the same import as a hand import: the delta
against the catalog copy is stored, and the changed rules can be rescanned from the delta (the
**Rescan changed rules** button, or `ingest rescan <delta_id>`).

DISA publishes most operating-system STIGs quarterly (January, April, July, October), with the
quarterly `U_SRG-STIG_Library_<Month>_<Year>.zip` compilation a few weeks later. A check after each
quarterly release, or on every reconnect, is enough. One check costs about 16 KB on the wire: the index
is 190 KB of JSON and the site compresses it with gzip (about 2.5 s at 56 kbps).

## What is pulled for which assets

The node decides from the inventory and the platform facts its last scan recorded for each host
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

For each product key the node wants the newest manual STIG that DISA has not sunset (or the SRG where
only an SRG exists), and for Windows and Linux hosts also the newest SCAP benchmark, because a scanner
here can execute it. Automation content (Ansible, Chef, DSC, GPO packages) and the quarterly compilation
are pulled only when asked for by name. A check lists what it skipped and why: unsupported host,
no matching entry, sunset release, superseded release, or a file on a host outside the allow-list.

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
- Nothing downloaded is executed or imported. Zips are opened with `zipfile`; XML is parsed with
  ElementTree; no file name from inside an archive is used as a path.
- The kill switch stops pulls: a new pull is refused and a running one stops before the next file.

## What is logged

| Action | Details |
|---|---|
| `content.check` | url, bytes on the wire, seconds, source, entries, updates (or `blocked` when the link is down) |
| `content.fetch` | url, bytes, seconds, sha256 |
| `content.fetch_failed` | url, bytes so far, seconds, error |
| `content.quarantine` | url, seconds or bytes, sha256 when known, reason |
| `content.import` | source path, bytes, sha256 |
| `content.manifest` | manifest path, bytes, sha256, item count |

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
  jobs/<id>.json                 pull jobs with per-file progress
  manifest.json                  the default manifest location
  source.json                    the cached cyber.mil class id
```

`ingest content` (or `GET /ingest/content`) prints the path of every extracted datastream.

## Making a scanner use a pulled SCAP benchmark

The scanners do not switch content on their own. The operator points a target at the datastream path
that `ingest content` prints:

| Adapter | Target option | Value |
|---|---|---|
| Windows | `scap_datastream` | `<state>/content/scap/MS_Windows_11/U_MS_Windows_11_V2R11_STIG_SCAP_1-3_Benchmark.xml` |
| Linux | `benchmark_path` | `<state>/content/scap/RHEL_9/U_RHEL_9_V2R10_STIG_SCAP_1-3_Benchmark.xml` |

Both options are being added to the adapters on a separate branch; until they land the datastreams sit
in the content store ready for use.

## The disconnected round trip

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

With the link up the same result is one step:

```
cyberthunder ingest check
```

```
cyberthunder ingest pull --all --wait
```

## Settings

All optional; the defaults apply when unset.

| Setting | Default | Meaning |
|---|---|---|
| `content_check_on_reconnect` | true | check the index after the outbox flush on reconnect |
| `content_auto_pull` | false | also pull every update after that check |
| `content_max_bytes` | 512 MB | per-file size cap |
| `content_timeout_s` | 30 | per-request timeout |
| `content_snapshot` | bundled | index snapshot used by `check --snapshot` and for manifests before any live check |

## How the index is found

The STIG library page is a Salesforce site; its catalog comes from one anonymous Apex call
(`getCyberDocumentCatalogByDocumentLibrary` with `documentLibrary: STIGs`). The class id in that call
changes when the site is redeployed. If the known or cached id is refused or answers with something that
is not JSON, the node reads the downloads page, follows the `sTIGs_Document_Library_view` bundle it names,
takes the class id next to that method, retries once and caches the new id in `source.json`.
