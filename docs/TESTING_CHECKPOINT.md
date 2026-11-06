# Testing checkpoint

Use a recorded release revision and separate state to test the integrated application and rehearse the operator flow. The release's validation and backup receipts identify what was actually tested; this document does not declare a continuing feature freeze. [Backlog section 6](BACKLOG.md#6-requested-capabilities-at-the-testing-checkpoint) maps the requested capabilities to their implementation boundaries and remaining work.

## Start a separate simulated rehearsal

From the repository in the project Python environment, PowerShell can create a new local state directory:

```powershell
$env:CT_STATE_DIR = Join-Path $env:TEMP ('ct-checkpoint-' + [guid]::NewGuid().ToString('N'))
$env:CT_STATE_BACKEND = 'sqlite'
$env:CT_AUTH_MODE = 'dev'
$env:CT_SECURITY_MODE = 'range'
python -m cyberthunder demo load
python -m cyberthunder scan
python -m cyberthunder serve --host 127.0.0.1 --port 8001
```

Open `http://127.0.0.1:8001`. This fresh-state, loopback development rehearsal uses unverified names and simulated targets; it does not test verified login or target credentials. Keep the printed/chosen state path to return to this rehearsal later; a new path creates a separate rehearsal. The same backend must be used by every process opening that directory. Do not point `demo reset` at existing operational state or use these development settings for a deployed service. [STATE](STATE.md) describes migration, local-volume SQLite limits and complete state backup.

Native Python changes take effect after restarting the application process. A previously published container or Zarf package does not acquire source changes automatically; build and deploy the intended revision through the existing [deployment procedure](DEPLOYMENT.md).

## Check the operator flow

1. **Findings:** combine machine/type/severity/source filters, sort results, and open an entire row by click or keyboard. Compare the scanner result, evidence confidence and review decision; these describe different things.
2. **STIG Library:** distinguish local downloads from maintained selections and available updates. Browse products outside the inventory, inspect versions and actual sync times, and import a local fixture. Saving maintenance choices alone does not download anything.
3. **Scans:** inspect content preflight, then the stored coverage after a scan. Missing/unconfigured benchmarks and unknown applicability must remain visible. An incomplete run must not clear older unassessed findings.
4. **Decisions:** inspect the preview, explicitly collect an impact assessment if wanted, read unknowns and rollback limits, then make a reasoned decision. Model output is advisory; availability, fallback and actual evidence are shown separately.
5. **Apply and history:** use a simulated executable Linux fix. Confirm its verification result and finding state, open the historical change through its audit link, and inspect rollback checks. After rollback, the earlier pass must not remain a current confirmed pass without fresh evidence. A later same-target change can correctly block an older restore.
6. **Kubernetes:** suspicious configurations should offer investigation/owner-review guidance, not a default deletion. A manual runbook being issued is not an automatically completed fix. Saved manifests cannot recover all runtime or application data.
7. **Assets and scope:** inspect the deployment context and host-setup guidance. Preview addresses, CIDRs, ranges and exclusions; confirm any CIDR normalization explicitly. Saving a search range does not authorize discovered assets, and registering a host does not start a scan.
8. **Link and CVE data:** normal mode must show unknown or observed conditions, not an assumed 56 kbps limit. Demonstration rates require test mode. CVE data status must distinguish missing, stale and available data; database bundles do not contain target images.

Use the [demo runbook](DEMO.md) for the timed sequence and [validation matrix](VALIDATION.md) for actual real-target evidence. Simulated checks do not establish real Windows, Cisco, AD, IPv6 discovery, deployed pod-to-host operation, or application/data recovery.

## Preserve the checkpoint

The source recovery set is a source ZIP, an all-ref Git bundle, validation evidence and a manifest with hashes and restore-check results. See [backup and restore](CONTRIBUTING.md#backups-and-restore). On the development laptop, checkpoint sets are under `C:\dev\backups` and mirrored under `C:\Users\joshu\OneDrive\Desktop\FleetHacker\backups`; the manifest identifies exactly which commit and evidence were saved.

That source set is separate from runtime state, credentials, VM disks/snapshots, scanner databases and cached container images. Preserve those separately when carrying a working range home. Do not copy a running SQLite database by itself: stop all writers and follow [STATE](STATE.md#backups) for the complete directory, including the audit and other file-backed records.

Verified browser/CLI login and per-account target grants and credential selection are implemented and have separate local acceptance evidence; see [account access](ACCOUNT_ACCESS.md), [person/account acceptance](PERSON_ACCOUNT_LIVE.md) and [CLI acceptance](CLI_DEVICE_PKCE.md). Those checks do not establish the intended enclave's claim mappings, actual remote privileges, immediate token revocation or credential issuance. Full dependency analysis, independent lockout recovery, durable registry image updates, workload scheduling and platform validation remain tracked in the backlog. No uncompleted item is claimed production-ready at this checkpoint.
