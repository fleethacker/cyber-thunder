# State: documents and files

Everything a node knows lives under one state directory (`CT_STATE_DIR`, `--state-dir`; `/var/lib/cyberthunder`
in the container). Two kinds of thing live there, and the difference decides where each is kept.

**Documents** are JSON the application reads and writes only through `StateStore` (`cyberthunder/store.py`):
scan runs and findings, explanations, the link state, the presenter's demo switch, STIG delta and bulletin
records, discovery scopes, assets and sweep runs, Kubernetes known-good exceptions, the content index, update
check, cached catalog, library preferences (`content/preferences.json`), sync timestamps (`content/sync.json`),
source and pull jobs. Preferences include product/type subscriptions, reconnect behavior, revision and actor;
sync records distinguish live-check attempts/success, downloads and local imports. A
document has a logical path such as `scans/<id>/run.json`, and the backend chosen by `CT_STATE_BACKEND` holds it.

**Files** are read from disk by other programs, people or transports, so they stay files under every backend:

| Path | Why it is a file |
|---|---|
| `audit.jsonl`, `audit.jsonl.head` | the hash chain is the tamper evidence; `audit verify` reads the file |
| `proposals.json`, `policy.json`, `targets.yaml`, `killswitch.json`, `KILL` | their owners take a file path and hold their own cross-process lock |
| `scans/<id>/raw/<target>/*` | the scanner's working files (collected facts, XCCDF results, configs) that checklists and bulletin re-matching read |
| `snapshots/<proposal>/*` | before-state captured before a fix, needed by rollback |
| `cluster/baselines/*` | Kubernetes namespace risk baseline artifacts and Trivy image reports |
| `outbox/*`, `synced/*` | payloads queued for shore and their `.meta.json` sidecars, moved together |
| `content/files`, `content/scap`, `content/quarantine`, `content/manifest.json`, `ingest/catalog/*.xml`, `ingest/uploads` | downloads, extracted datastreams, the manifest that travels on removable media |
| `simulated/*` | the simulated hosts' state, written by the adapters |

The routing list is `is_document()` in `cyberthunder/state/__init__.py`. It is a positive list: a JSON path
not named there is a file, which is what every path was before the backends existed. A new area that writes
JSON through the store keeps writing files until it is added to the list, which is a one-line change once
nothing reads those files from disk.

## The two backends

`CT_STATE_BACKEND=json` (the default) keeps one file per document under the state directory, written by temp
file and rename. It is the layout the tool has always had: a state directory can be copied, diffed and synced
over a slow link with plain tools.

`CT_STATE_BACKEND=sqlite` keeps every document as a row in `state.db` in the state directory, in WAL mode with a
busy timeout. One writer at a time and readers that never wait is what lets two API workers and the CLI share
one state directory without losing each other's updates; a write that meets another writer waits instead of
failing. Files stay files, so `audit verify`, the proposals file lock and the inventory merge work as before.

Both backends pass the same test suite: the `state_dir` fixture in `tests/conftest.py` runs every state test
once per backend in one pytest run, which is what `scripts/gate.sh` executes (`CT_STATE_BACKENDS=json` narrows
a local run to one backend). `tests/state/test_concurrency.py` starts two API processes and the CLI against one
state directory, has them add targets, scan, propose and decide at the same time, and checks that nothing is
lost and the audit chain verifies, once per backend. Measured on the development laptop (Windows 11): a
concurrent phase of 17 s (json) and 20 s (sqlite) in which 27 targets were added (24 over HTTP by two workers,
3 by the CLI), 53 proposals were decided and 3 scans ran, ending with 80 proposals, all of it present
afterwards in every process's view, and 177 audit records in a verified chain. `tests/state/test_roundtrip.py`
moves the 39 documents of a simulated-range state each way and leaves its 23 files untouched.

Every process that shares a state directory must run with the same `CT_STATE_BACKEND`. The sqlite backend logs a
warning when it finds JSON documents that are not in `state.db` yet, and `state info` reports documents held by
the other backend, which is how an unmigrated directory shows itself.

### WAL on a local volume only

SQLite in WAL mode keeps `state.db-wal` and `state.db-shm` next to the database and coordinates processes through
shared memory. That works on a local disk and on a volume mounted into the container from local storage. It does
not work on a network file system (NFS, SMB, CIFS): locking and shared memory are not reliable there and the
database can be corrupted silently. Keep the state directory on local storage; for a shared or multi-node
deployment the next step is PostgreSQL (BACKLOG SCL-01). Durability is `synchronous=NORMAL`: a process crash
loses nothing, a power cut can lose the last transactions, which matches the json layout (no fsync there).

## Commands

```bash
cyberthunder --state-dir /var/lib/cyberthunder state info
```

prints the configured backend, where the documents are, how many there are, their size, the audit chain
status, and a note when the other backend holds documents too (`--backend sqlite|json` inspects the other one,
`--json` for scripts).

```bash
cyberthunder --state-dir /var/lib/cyberthunder state migrate --to sqlite
```

copies every document from the json files into `state.db`, then verifies that every source path is present,
compares a sample one by one (`--sample 0` compares all) and checks that the audit chain still verifies. The
source documents are left in place unless `--prune` is given and the copy verified. Running the command again
on a target that already holds the same documents changes nothing; a target with different or extra documents is
refused unless `--force` is given, which overwrites the copies and keeps what only the target holds.
`--to json` goes the other way. After migrating, set `CT_STATE_BACKEND` for every process that uses the
directory: the API server, the CLI, and the container environment.

## Backups

The backup instructions in [CONTRIBUTING.md](CONTRIBUTING.md) cover the repository. Back up the **entire state
directory** for operational data under both backends. SQLite holds scan runs, findings, discovery and the
library preference/sync documents, but raw scanner files, inventory, audit, rollback snapshots, downloaded
content and imported catalog XML remain outside the database.

Stop writers before copying the directory; under sqlite include `state.db` and any `state.db-wal` and
`state.db-shm` files. Alternatively migrate documents to JSON first and retain all other state files too.
Restore the complete directory with the corresponding `CT_STATE_BACKEND`. A container persistent volume
must mount the whole state directory (`/var/lib/cyberthunder` by default), not only `state.db`.

## What remains

Proposals, the policy and the inventory stay files because their owners (`ApprovalGate`, `load_policy`,
`Inventory`) take a file path and lock it themselves; moving them onto the document backend means giving them a
store instead of a path. PostgreSQL for the UDS deployment and more than one node are the rest of SCL-01 in
[BACKLOG.md](BACKLOG.md).

## Saved reports

Report snapshots are portable files under `reports/history/<id>.json` for both backends.
Each holds its metadata and original rendered content. Include `reports/` in backups;
opening an older report does not regenerate it from current state. Existing target
reports and retained outbox exports are imported into history when searched.
