# vSphere source inventory in Assets

The Assets table offers **View vSphere inventory** for targets with the explicit
`vsphere` transport or `options.hypervisor: vsphere`. Other targets retain
**Read asset facts**, including Workstation targets declared as `vmware`.
Opening the drawer reads saved history for that inventory target. It does not
collect, probe a range, inspect the local machine, accept guests or start a scan.

The drawer is labeled **Your source collections**. It shows up to twenty saved
collections with UTC start/finish dates and completion status. Selecting a row
reads that saved run's observations. **Collect inventory** is a separate explicit
action. Its returned run is selected and added to the displayed history without
an automatic retry, global discovery call or follow-up mutation.

Observation columns are name, VM/ESXi type, reported IP addresses, power state
and evidence. Stable object references distinguish duplicate names. Powered-off
and addressless VMs remain visible; missing data says **Not reported**. Reported
addresses are inventory claims and do not establish guest reachability. Text is
rendered as escaped React content. There is no acceptance, registration or scan
control in this drawer.

## Request and display boundaries

The three typed client methods use the existing authenticated request wrapper:

| Method | Request under `/api/v1` |
| --- | --- |
| `api.vsphereRuns(targetId)` | `GET /discovery/vsphere/{target_id}/runs?limit=20` |
| `api.vsphereRun(targetId, runId)` | `GET /discovery/vsphere/{target_id}/runs/{run_id}` |
| `api.vsphereCollect(targetId)` | `POST /discovery/vsphere/{target_id}/collect` |

Identifiers are URL-encoded. Collection uses the wrapper's empty JSON object and
existing CSRF header; callers cannot supply an endpoint, credential or range.
`VsphereRunSummary` and `VsphereRun` match the source API contract in
`VSPHERE_ACCOUNT_ACCESS.md`. The full run adds `observations`; history summaries
omit them. `Target.authorization_id` is optional for compatibility with older
inventory payloads. When present, the UI checks it against returned ownership,
as well as target ID and environment. Server authorization remains authoritative
when that generation is absent.

Only `status: finished` together with `complete: true` displays a complete
snapshot. A complete empty inventory has its own explanation. Failed, stopped,
running and otherwise incomplete runs display an incomplete notice and do not
render any partial observations as accepted evidence. A collection that was not
invoked says so; `collection_started: true` does not prove connectivity.

An unsuccessful history request is **Source history unavailable**, never **No
saved collections**. Empty history is shown only after a successful empty read,
with no pending request or request error. A failed collection HTTP request says
completion may be unknown and directs the operator to refresh history before
retrying. A successful collection after a history failure preserves the warning
and labels the returned run separately from unavailable saved history.

`PermissionButton` and `usePermissions` provide application read/discover controls
and an accessible permission explanation. Every handler checks permissions again;
a retained callback cannot rely on the earlier enabled button. Reading history
requires `read`; collection requires `read` and `discover`, an in-scope target and
the existing setup/kill guard. Backend target grants and discover credential
selection are additional requirements, not implied by these UI controls.

Every request captures `api/identity.authorityRevision()`. The existing API
wrapper checks it during response and error-body decoding. The component also
checks that authority, the current target configuration and the active request
before publishing data or errors. Target/account changes clear the visible
snapshot before effects run; cleanup, close and unmount invalidate pending
requests. Late completion cannot populate another account's view, restore an old
target generation or release a newer request's busy guard. A ref suppresses
duplicate pending actions, including clicks before React rerenders.

Closing the drawer does not cancel a server collection already in progress.
Reopening performs a fresh history read; it never automatically repeats a POST.

## Backend ownership dependency

This branch starts at parent `77ef33e`, which includes the source API and shared
session-evidence correction. The independent backend review owns issuer/subject
binding of collection history. That binding must be integrated before accepting
the **Your source collections** behavior: separate accounts can have read access
to the same inventory target while their remote vSphere credentials expose
different VM sets. A target-only history filter is insufficient. The label and
frontend authority checks do not replace that backend boundary or introduce
sharing grants.

This UI patch changes no backend routes, policy helpers, credentials, global
discovery behavior or `DiscoveryPanel`. It adds no runtime dependencies and
does not build or commit distribution assets. Live vCenter/ESXi acceptance and
the parent's combined UI build/full gate remain separate checks.

## Focused validation

Run from `cyberthunder/ui`:

```powershell
node --test src/components/VsphereInventory.test.mjs src/components/VsphereInventoryRendering.test.mjs src/components/PermissionControlsRendering.test.mjs src/components/DiscoverySetup.test.mjs src/api/identityAuthority.test.mjs src/state/Identity.test.mjs
npm run typecheck
```

On Windows with Node 26.13.0, the focused command passed **76 tests, zero
failures and zero skips** in **18.78 seconds**, including **43 new source UI
cases**. The final `npm run typecheck` completed successfully. No production
distribution build was run.

The handler tests execute the component's real handlers/effects together with
the actual API wrapper and identity authority module. Only HTTP responses and
widget layout are fixtures. Separate rendering tests use real Mantine buttons,
tables, alerts and permission providers, with drawer layout inlined for server
rendering. They verify disabled controls and their ARIA explanations; they do
not claim an interactive browser keyboard or focus-trap acceptance run.

Coverage includes readonly accounts, explicit collection and duplicate
suppression, history failure versus empty history, complete-empty versus failed
snapshots, offline/addressless inventory, escaped metadata, no acceptance/scan
requests, bounded history, failed requests, late body decoding, account changes,
permission revocation, target generation/address changes, close/reopen and
unmount while requests are pending. All fixtures are local; no service, loopback
probe or vCenter connection is started by these tests.
