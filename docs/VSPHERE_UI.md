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

## Bounded observation rendering

The observation table renders **25 rows by default**, with local page sizes of
25, 50 or 100. Only the selected page creates row, evidence and note elements;
the scroll viewport is also height-limited. Snapshot order is preserved across
pages. Pagination does not request additional data or change the saved run.

Search matches names, object references and reported IPs, with case-insensitive
Unicode normalization. Fixed type and reported-power selectors combine with the
search. Evidence and notes are not searched or summarized from hidden rows.
Changing a filter or page size returns to page one. **Reset filters** clears
search/type/power and returns to page one while retaining the chosen page size.

Counts distinguish the visible range, number of matches and total observations
in the complete saved snapshot. They do not claim that a page, a filtered set
or the saved source snapshot describes all vCenter inventory. No matches has a
separate explanation from a complete empty inventory. Filter options are fixed;
they do not expose hidden names or metadata through generated menus.

The observation subtree is keyed by current account authority, target ownership
and run ID. Selecting another run or changing account/ownership creates fresh
controls with empty filters, page one and 25 rows. Existing parent permission,
request cleanup and authority checks remain in force. The full authorized
snapshot is still held in memory; this is a DOM rendering bound, not server-side
pagination or a new network/body limit.

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
node --test src/components/VsphereInventory.test.mjs src/components/VsphereInventoryRendering.test.mjs src/components/VsphereInventoryPagination.test.mjs src/components/PermissionControlsRendering.test.mjs src/components/DiscoverySetup.test.mjs src/api/identityAuthority.test.mjs src/state/Identity.test.mjs
npm run typecheck
```

On Windows with Node 26.13.0, the focused command passed **83 tests, zero
failures and zero skips** in **19.03 seconds**, including **50 source UI
cases**. The final `npm run typecheck` completed successfully. No production
distribution build was run.

The handler tests execute the component's real handlers/effects together with
the actual API wrapper and identity authority module. Only HTTP responses and
widget layout are fixtures. Separate rendering tests use real Mantine buttons,
tables, alerts and permission providers, with drawer layout inlined for server
rendering. They verify disabled controls, ARIA explanations, exact paged row
content and absence of excluded evidence/notes in the rendered markup.

An explicit native-browser fixture uses the real Mantine drawer, identity
provider and client. It serves only its UI through a temporary loopback Vite
server. All API responses are intercepted; non-fixture HTTP requests are blocked.
It does not contact an identity provider, backend discovery service or vCenter.
Run it with an already available Playwright module and native Chromium browser:

```powershell
$env:CT_PLAYWRIGHT_MODULE='file:///C:/Users/joshu/.codex/worktrees/scope-recipes/cyber-thunder/.build/scope-recipes-browser/node_modules/playwright-core/index.mjs'
$env:CT_VSPHERE_BROWSER='C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'
node src/components/VsphereInventory.browser.mjs
```

The native Windows Edge run passed: readonly controls, Enter/Space paging,
25/50/100 row bounds, local search/type/power filters, absence of hidden row
metadata, run/account control resets and close/reopen. Paging/filtering made
no API requests; every intercepted API request was a source-specific GET.
Playwright is a fixture tool, not an added production dependency.

Coverage includes readonly accounts, explicit collection and duplicate
suppression, history failure versus empty history, complete-empty versus failed
snapshots, offline/addressless inventory, escaped metadata, no acceptance/scan
requests, bounded history, failed requests, late body decoding, account changes,
permission revocation, target generation/address changes, close/reopen and
unmount while requests are pending. All fixtures are local; no inventory scan,
loopback discovery probe or vCenter connection is started by these tests.

## Independent review of the integrated UI candidate

The independent review of `de7282e` found no concrete production UI defect in
retained read/collect callbacks, account changes, source deletion/reassignment,
local paging, incomplete results or reported power/address presentation. Eight
additional regressions cover already-loaded snapshots across issuer, subject and
read-permission changes; source ownership, environment and address changes;
deletion followed by reuse; and the Assets page resolving its selected ID against
the current inventory. Old callbacks cannot restore the former target or invoke
collection against its replacement. An ID retained across inventory refreshes
may select the replacement source, but its current configuration is passed to the
drawer and triggers a fresh authorized history read.

The three vSphere test files below passed **58 tests, zero failures and zero
skips**, using Windows Node 26.13.0 in **9.30 seconds**:

```powershell
node --test cyberthunder/ui/src/components/VsphereInventory.test.mjs cyberthunder/ui/src/components/VsphereInventoryRendering.test.mjs cyberthunder/ui/src/components/VsphereInventoryPagination.test.mjs
```

Run this command from the repository root. These checks exercise actual handlers,
the authenticated client and real Mantine static rendering; they do not constitute
a fresh browser acceptance run. The existing intercepted Edge fixture was read,
not repeated. No production code changed, and the full UI suite, typecheck,
distribution build and live vCenter acceptance were not repeated for this review.

The integrated candidate includes the backend collector and credential-binding
history checks reviewed in `8f9875f`. Its earlier `de7282e` UI source passed all
405 UI tests and the production TypeScript/Vite build; this later review adds
tests and documentation without changing that production source or bundle.
Frontend account resets do not establish
per-collector authorization. A saved snapshot may remain displayed until a local
authority/target change or a subsequent request invalidates it: this UI has no
push invalidation for server policy, credential mapping or remote vCenter role
changes. Remote role changes cannot be detected from saved inventory alone.
Previously delivered data cannot be withdrawn from browser memory by a later
server refusal. Live provider sessions and actual vCenter visibility remain
separate acceptance work.
