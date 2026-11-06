# vSphere discovery review

Reviewed implementation `b83adfb4f2455fdc454db2faa0ee2fef6a7cb8dc`,
cherry-picked as `1dffc11899fdf1878b1f0ba63b1815b8ce1750b9` on `24489ca`.
The review and corrections cover discovery source/client/wiring and offline
tests. No live vCenter or ESXi endpoint was contacted.

## Confirmed issues corrected

| ID | Severity | Observation and correction |
| --- | --- | --- |
| VSR01 | High | A successful SOAP response could echo the login password or session cookie in a VM name or host product. Those values reached saved candidate metadata on both backends. `InventoryClient` now checks decoded exported values, including object references, UUIDs and service identity, against the active password and session tokens. A match aborts the snapshot with `vsphere:sensitive_response`; previous candidates remain intact. Secret references are cleared during cleanup. |
| VSR02 | High | First-match XML lookup accepted duplicate SOAP bodies, return values, tokens, object references and property values. An empty token followed by the real continuation token ended collection early; a foreign-namespace object was silently skipped. The client now rejects ambiguous or unknown page/object/property fields before returning any inventory. |
| VSR03 | High | Revoking kill, range or source-target access during observation conversion still allowed publication. A longer later source or reconciliation step extended this gap. The source rechecks after conversion; the service captures source guards before collection and checks them immediately before saving candidates, after reconciliation. These guards retain the original target configuration and exact range grants. Revoked runs terminate without publishing their observations. Candidates from a source introduced mid-run are refused because no original source guard covers them. |
| VSR04 | Medium | An initial property retrieval with no return value was treated as a missing page. It now produces a successful empty snapshot. An absent continuation result still fails and discards earlier pages. |
| VSR05 | Medium | An explicitly null `runtime.host` aborted collection of powered-off, unassigned VMs. Empty `xsi:nil` property values now mean unavailable evidence; they do not create a host association or address. Nil values containing text or children remain invalid. |
| VSR06 | Medium | The existing watchdog test exposed a fired timer whose returned body was accepted when the subsequent clock comparison did not report expiration. The exchange now also checks an explicit fired event. A deterministic regression exercises that event independently of clock timing. |
| VSR07 | High | A configured Windows UNC CA-file path reached `Path.is_file()` before connecting to the approved HTTPS endpoint. Windows may perform an out-of-scope file-share connection and use ambient OS credentials for that filesystem probe. UNC and device paths are now refused before any file probe. Four offline cases intercept the probe; no file-share connection was made during review. |

The [PropertyCollector API](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vmodl.query.PropertyCollector.html)
documents a null initial retrieval when no objects match. The
[VM runtime API](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.vm.RuntimeInfo.html)
allows a null host for a VM that is not running and has no assigned host.

The initial adversarial run reproduced 23 failures out of 24 cases before
corrections. The retained passing case established that an absent continuation
already failed safely. Subsequent coverage adds publication-time revocation and
the deterministic watchdog case.

## Other reviewed boundaries

- Requests use one explicit HTTPS `/sdk` endpoint and a literal, scoped inventory
  IP. The socket does not resolve the endpoint hostname; that hostname is used
  for TLS identity and HTTP Host. Redirects and non-200 responses fail without
  following a new endpoint. Certificate verification stays enabled. CA files
  must use local paths; administrators must also control the files and their
  mounts/reparse points, which are outside HTTP endpoint authorization.
- Credentials come from the explicit vSphere reference. SSH credentials, bare
  environment references, process proxy settings and ambient authentication do
  not supply alternatives. Verified authentication still fails before credential
  lookup or network I/O because delegated vSphere bindings are unavailable.
- Request methods remain limited to session, ephemeral view and property reads.
  DTD/entity declarations, malformed XML, encoded responses and ambiguous HTTP
  framing fail. Body, total-byte, object, page, token and deadline bounds remain.
- Guards run at connection and request boundaries and after responses. Existing
  pagination tests verify that revocation prevents continuation and cleanup I/O.
  A server must expire sessions/views when cleanup cannot run after revocation.
- IDs retain endpoint/service/object identity across rename or address changes.
  Conflicting duplicate objects fail; identical repeats deduplicate. Shared IPs
  remain unresolved and powered-off/addressless VMs retain metadata. Discovery
  does not accept candidates into inventory or imply guest reachability.
- Fault/error bodies never become exception or audit text. Successful property
  values now also reject literal decoded credential/token echoes. This is not a
  claim to detect arbitrary transformations or encodings of secrets by a hostile
  endpoint; an approved endpoint and read-only account remain required.

## Open acceptance and separate observations

The central credential owner must supply requester/action/resource-generation
and exact-endpoint bindings, dedicated credential selection, revocation guards
and credential-use audit evidence before verified-mode access can be enabled.
No fallback was added. Real Read-only role behavior, server compatibility,
certificate-chain/name validation and large-inventory timing/pagination still
need live acceptance. This review does not close those requirements.

A pre-existing run-list issue surfaced while checking two sweeps in the same
second: `DiscoveryService.runs()` sorts equal `started_at` timestamps by the
random suffix in the ID, so `last_run()` can select the older run. The regression
tests identify the failed run by ID rather than elapsed time. That unrelated
ordering behavior was left unchanged.

## Validation

All tests use synthetic SOAP responses and fake sockets. The shared parent
Python interpreter runs with `PYTHONPATH` set to the worker checkout. Stateful
tests use both JSON and SQLite fixtures.

- Initial focused client/source/review tests: **112 passed in 45.67 seconds**.
- Discovery before the final CA-path and source-addition checks:
  **374 passed, 1 dependency deprecation warning in 116.72 seconds**.
- Final discovery: **380 passed, 1 dependency deprecation warning in
  73.13 seconds**. This includes 37 new review regression cases.
- `git diff --check` passed; all five changed files use LF line endings.

```powershell
$env:PYTHONPATH = 'C:/Users/joshu/.codex/worktrees/testing-checkpoint/cyber-thunder'
& 'C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe' -m pytest tests/discovery --tb=short
```
