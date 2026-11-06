# Platform validation

Evidence reviewed 2026-11-06. Generated from `validation.json` by `scripts/validation_status.py`.

- Recorded means the repository contains a dated account of a real run. It does not mean this matrix reran that experiment or verified a production deployment.
- The older range notes did not capture exact tested application commits and some component versions. A write-up commit is not the binary that ran. Later entries identify a tested application commit and its bounded acceptance scope where recorded.
- A seed detection score measures the deliberately planted items, not whole-benchmark compliance. See COVERAGE.md for implemented checks and local content mappings.
- No platform has a complete recorded false-positive review (VAL-02). A successful Linux rollback is evidence for that one fix, not every fix or platform.
- Native and container deployments remain supported directions. The matrix describes recorded experiments; it does not imply every deployment-to-target combination has been tested. Verified per-account application controls and credential selection are implemented, while intended enclave identity mappings and target-side per-person access acceptance remain open.

| Platform / version | Real run recorded | Date | Seeded detections | Fix flow | Evidence |
|---|---|---|---|---|---|
| Rocky Linux 9 | Yes | 2026-11-04 | 12/12 | One /etc/shadow fix: apply, verify, rollback | [Run notes](../range/README.md#results-first-real-host-run-2026-11-04) |
| Podman on Rocky Linux 9 (engine version not recorded) | Yes | 2026-11-04 | 6/6 | Not exercised | [Run notes](../range/README.md#results-first-real-host-run-2026-11-04) |
| k3s on Rocky Linux 9 (k3s version not recorded) | Yes | 2026-11-04 | 10/10 | Not exercised | [Run notes](../range/README.md#results-first-real-host-run-2026-11-04) |
| k3d / UDS Core demo cluster on WSL2 | Yes | 2026-11-05 02:21Z | Not scored; 127 findings, no adapter errors | Not exercised | [Run notes](../docs/DEPLOYMENT.md#scanning-the-cluster-from-windows) |
| Exported UBI 9 nginx-124 image; OpenSCAP 1.3.7 | Yes | 2026-11-06 | Not scored; 393 notapplicable; three RPM database diagnostics | JSON/SQLite import, reports and restart only; no remediation | [Run notes](../docs/CONTAINER_SCAP_LIVE.md) |
| Windows 11 | No | - | Not measured | Not exercised | [Range instructions](../range/windows/README.md) |
| Windows Server 2019 | No | - | Not measured | Not exercised | No real-run evidence |
| Windows Server 2022 | No | - | Not measured | Not exercised | No real-run evidence |
| Windows Server 2025 | No | - | Not measured | Not exercised | No real-run evidence |
| Active Directory domain / Kerberos remoting | No | - | Not measured | Not exercised | No real-run evidence |
| RHEL 8 | No | - | Not measured | Not exercised | No real-run evidence |
| RHEL 9 | No | - | Not measured | Not exercised | No real-run evidence |
| AlmaLinux 8 | No | - | Not measured | Not exercised | No real-run evidence |
| AlmaLinux 9 | No | - | Not measured | Not exercised | No real-run evidence |
| Ubuntu 22.04 | No | - | Not measured | Not exercised | No real-run evidence |
| Ubuntu 24.04 | No | - | Not measured | Not exercised | No real-run evidence |
| Cisco IOS switch | No | - | Not measured | Not exercised | [Range instructions](../range/cisco/README.md) |
| Cisco IOS router | No | - | Not measured | Not exercised | [Range instructions](../range/cisco/README.md) |
| Cisco IOS-XE switch | No | - | Not measured | Not exercised | [Range instructions](../range/cisco/README.md) |
| Cisco IOS-XE router | No | - | Not measured | Not exercised | [Range instructions](../range/cisco/README.md) |
| Conformant Kubernetes distribution beyond the k3s/k3d range | No | - | Not measured | Not exercised | No real-run evidence |
| Docker host through the container adapter | No | - | Not measured | Not exercised | [Range instructions](../range/containers/README.md) |

## Provenance and next evidence

Older runs lack an exact application commit. Do not substitute the current branch or a documentation commit. Recorded application SHAs below apply only to the named acceptance scope.

- Exported UBI 9 nginx-124 image; OpenSCAP 1.3.7: application `0261297db3d1ae1fdbbe7e9595bff8881d9945fd`; Result import, reports, exact-repeat handling and fresh-process persistence.
- Rocky Linux 9: write-up commit `6ce5a22; scoring correction 3557f9a`.
- Podman on Rocky Linux 9 (engine version not recorded): write-up commit `6ce5a22; scoring correction 3557f9a`.
- k3s on Rocky Linux 9 (k3s version not recorded): write-up commit `6ce5a22; scoring correction 3557f9a`.

For the next run, record application SHA, deployment mode, OS/build, scanner and benchmark versions/profile, scan ID, seed scope, collection errors, false-positive dispositions, each fix exercised, and sanitized score/audit evidence. Keep credentials and target secrets out of the evidence files.

To refresh this matrix and the README status:

```sh
python scripts/validation_status.py --write
```

To check both generated sections without changing files:

```sh
python scripts/validation_status.py --check
```
