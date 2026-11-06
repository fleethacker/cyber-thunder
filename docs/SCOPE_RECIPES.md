# Editable discovery scope recipes

The discovery editor saves each recipe's original include/exclude expressions, name, public-address decision, scanner target and normalization acknowledgement. Select a recipe to edit it independently. Other recipes retain their expressions, policies and effective grants. Saving does not start discovery, scan a target, accept a candidate, change inventory authorization or verify scanner connectivity.

## Operator workflow

1. Open **Edit discovery search ranges**. Saved recipes load from the service, including exclusions and scanner choices.
2. Select **Recipe to edit**, or use **Add recipe**. Expressions accept IPv4/IPv6 addresses, CIDRs and inclusive start-end ranges, one per line or separated by commas. A recipe can have several expressions under one policy.
3. **Preview exact search ranges** shows effective networks, exact decimal address counts, exclusions, per-recipe scanners and public policies. Review any host-bit CIDR expansion. A changed acknowledgement requires another preview.
4. Enter a decision reason and confirm the exact ranges. Additional warnings require their own acknowledgement.

**Reset unsaved edits** restores the last loaded snapshot and discards the current preview and confirmation. **Reload saved recipes** fetches the current server revision and discards local edits. A server conflict requires reload and a fresh review; local reset cannot clear a conflict. Removing a recipe changes only the draft until preview and confirmation. Removing all recipes explicitly clears discovery scope. Excluding every address from a nonempty include list is refused to avoid accidental clearing.

Controls support keyboard focus, arrow-key recipe selection, Enter/Space buttons and checkboxes, and Escape to close an idle modal. Escape and dismissal are disabled during save. Closing and reopening restores persisted recipes; unfinished edits are not written. Labels, errors and source expressions render as text.

## Legacy records and upgrades

Older `discovery/scopes.json` documents contain only effective CIDRs and policy fields. Read-only loading does not rewrite them. Each effective record appears as a legacy recipe with `include: null`, `exclude: null` and `original_expressions_known: false`. An absent historical timestamp stays empty. No original expression or exclusion is inferred from a CIDR.

**Use effective ranges as new expressions** explicitly starts a new declaration using the displayed effective CIDRs and an empty exclusion list. It preserves that record's scanner/public choice, invalidates the preview, and still requires review before saving. Until conversion, expressions and policy cannot be edited; other legacy records remain effective-only.

A successful write upgrades the document to an envelope:

```json
{
  "version": 1,
  "revision": "opaque revision",
  "recipes": [{
    "id": "range-a",
    "name": "Enclave A",
    "include": ["10.20.30.1-10.20.30.9"],
    "exclude": ["10.20.30.4"],
    "allow_public": false,
    "scanner_target": null,
    "acknowledge_normalization": false,
    "scopes": []
  }]
}
```

Here `scopes` is abbreviated; actual saved entries contain the derived CIDRs and existing grant metadata. Expressions and effective grants reside in the same document: atomic replacement for JSON and one document transaction for SQLite. All new writers share the `discovery-scopes` backend lock. Restart all API/CLI processes when deploying this format: older binaries expecting a plain list cannot read the envelope. State backup/migration already includes the discovery document area.

The compatibility `PUT /discovery/scopes` and `PUT /discovery/scopes/ranges` routes retain whole-set replacement semantics. The latter now retains its submitted expressions; a CIDR-only replacement creates effective-only records. Both advance the revision and make outstanding recipe previews stale. They do not implement optimistic editing themselves; use the recipe endpoints for edits that must refuse stale state.

## API and review binding

All paths below are relative to `/api/v1` and use the existing discovery router and shared actor dependency.

| Method and path | Contract |
| --- | --- |
| `GET /discovery/scopes/recipes` | Returns `revision`, editable `recipes`, their effective `networks` and `original_expressions_known`, plus existing `scopes`. |
| `POST /discovery/scopes/recipes/preview` | Takes `revision` and the complete recipe list. Returns the same revision, per-recipe previews, an aggregate preview and a `fingerprint`. Does not write scope state or audit a decision. |
| `PUT /discovery/scopes/recipes` | Takes the same revision and recipe inputs, `preview_fingerprint`, and a nonempty reason of at most 1,000 characters. Revalidates and saves under the backend lock. |

Recipe inputs contain exactly `id`, `name`, `include`, `exclude`, `allow_public`, `scanner_target`, and `acknowledge_normalization`. Do not submit response-only `networks`, `scopes`, or `original_expressions_known`. IDs are unique ASCII identifiers, at most 64 characters. Names allow Unicode, at most 80 characters, without control characters or invalid surrogate code points. Booleans are strict. Unknown fields are rejected.

The fingerprint binds the exact expressions, their order, policies, names, acknowledgements, revision and computed preview. Save recomputes that fingerprint and all bounds from submitted expressions; it never trusts client-supplied effective networks. The UI saves its retained preview request, not a newly assembled declaration. A changed expression or policy invalidates the review. The fingerprint is a consistency check, not a secret authorization token or evidence that a human read the preview. Actor authorization remains the application's existing responsibility.

Stale revisions return HTTP 409 without changing state. Invalid inputs, missing acknowledgements and mismatched previews return 400 (request-schema errors return 422). An unknown scanner returns 404; an out-of-scope scanner prevents save. The kill switch blocks a recipe save with 423. Competing operators cannot silently overwrite each other: one revision wins, the other must reload and reapply its change. There is no automatic merge of stale drafts.

Every successful write appends `discovery.scopes` with the actor, reason, old/new revisions, old/new recipe declarations, effective CIDRs and public-address decisions. Recipe saves also record the preview fingerprint. Existing compatibility `range_input` audit details remain available. The audit chain remains a separate append from document persistence; this feature does not add a cross-file transaction between state and audit.

## Bounds and active discovery

- Across the complete set: at most 128 recipes, 128 combined include/exclude entries, 256 normalized networks, and 65,536 unique effective addresses. Each expression is at most 256 characters. Each effective CIDR is at least `/16` for IPv4 or `/112` for IPv6.
- Counts use bounded interval arithmetic, include network/broadcast addresses, and travel as decimal strings. IPv6 counts remain exact even when displayed network output is truncated; truncated or oversized output cannot be saved. No host enumeration or DNS lookup is used for preview.
- IP expressions use ASCII syntax. Unicode lookalike digits, dashes, whitespace, invisible characters, controls and IPv6 zone IDs are rejected. Edited text splits at commas/newlines and trims surrounding ASCII whitespace. Unchanged reloaded expressions preserve their original formatting.
- Exclusions belong to their recipe. Another recipe may explicitly include the same address; the aggregate effective count reflects that union. Overlapping effective ranges with different scanner/public policies are refused. Identical effective CIDRs with the same policy produce one grant.
- Public addresses still require an explicit public-space decision and save reason. Host-bit expansion of an include or exclusion still requires acknowledgement for those exact inputs. A recipe grants discovery search scope only; it cannot authorize an inventory target.
- A running sweep retains its selected ranges and exact original grants. New grants have unique `grant_id` values, so removal and regrant cannot revive a running sweep even with identical CIDRs, policy and timestamps. Legacy records retain an empty grant identifier until replaced. Removing or replacing a grant, including replacing it with a wider CIDR, prevents its next discovery command. An edit to another recipe preserves unchanged grants. A sweep request cannot override a saved scanner policy.
- Scope and scanner authorization are rechecked before the ping and port phases and passive reads. The kill switch is also checked. These checks do not terminate a command already executing when a decision changes; that command remains subject to existing tool/transport timeouts. This is not a claim of instantaneous network cancellation.

## Verification and integration handoff

Observed on Windows: the Python command below passed **342 tests** across JSON/SQLite; the focused UI command passed **31 tests**; TypeScript checking passed; the explicit browser fixture passed with React StrictMode enabled. The final context/audit-provenance assertions also passed the **10-test** principal-context module rerun. Python emitted existing framework deprecation warnings. These are focused checks, not the combined release gate.

The focused service/API tests run on both configured state backends. They cover original-expression round trips, mixed scanner/public choices, exclusions, legacy migration/conversion, stale/replayed previews, concurrent independent contexts, immutable bindings, input bounds, invalid Unicode/types, host-bit/public broadening refusal, scanner revocation, kill/actor refusal, exact active-grant revocation, and unchanged inventory/run state. Recorded nmap output verifies that revocation between ping and ports prevents the second command; no target network is contacted.

Run from the repository root with the agreed Python environment and this checkout on `PYTHONPATH`:

```powershell
$env:PYTHONPATH = (Get-Location).Path
& $env:CT_TEST_PYTHON -m pytest -o addopts='' -q tests/discovery/test_scope_recipes.py tests/discovery/test_scope_recipes_api.py tests/discovery/test_scope_principal_context.py tests/discovery/test_ranges.py tests/discovery/test_service.py tests/discovery/test_robustness.py tests/discovery/test_api_cli.py tests/api/test_host_scope.py tests/api/test_host_scope_review.py
```

From `cyberthunder/ui`, the focused UI/client/rendering suite and typecheck are:

```powershell
node --test src/api/scopeRecipes.test.mjs src/api/hostScope.test.mjs src/components/ScopeEditor.test.mjs src/components/HostScopeRendering.test.mjs src/components/DiscoverySetup.test.mjs
npm run typecheck
```

The browser fixture uses the real editor, React StrictMode and Mantine controls in a loopback Vite page. API replies are intercepted; the access-status hook is replaced only inside this fixture (actor/kill behavior is tested separately by component/API tests). It exercises keyboard selection, mixed policies, reset, add/remove, explicit save, reopen, Escape cancellation, HTTP 409 recovery and legacy conversion/reset. Run explicitly; it is not part of default `node --test`:

```powershell
# Repository root: isolated test-only installation; no product manifest changes.
npm install --prefix .build/scope-recipes-browser --no-package-lock --no-audit --no-fund playwright-core@1.56.1
# From cyberthunder/ui, set the module URL and an installed Chromium executable.
$env:CT_PLAYWRIGHT_MODULE = ([System.Uri](Resolve-Path '../../.build/scope-recipes-browser/node_modules/playwright-core/index.mjs').Path).AbsoluteUri
$env:CT_SCOPE_BROWSER = 'C:/Program Files/Google/Chrome/Application/chrome.exe'
node src/components/ScopeEditor.browser.mjs
```

No new production dependency or app-router registration is needed. The dedicated `scopeRecipes.ts` module uses the existing shared `request` function, so parent-owned authentication headers and error handling continue to apply. Existing scope-mutation permission mapping is retained; the parent handles resource-scope and read API authorization globally.

Background discovery starts `_execute` through `contextvars.copy_context().run`, retaining the authenticated requester and operation context. When `settings.auth_mode != 'dev'`, sweep entry, each next range, ping/port/passive scope checks, and each next inventory source call `ctx.authorize('discover', actor=actor)`. Development contexts (including contexts without `auth_mode`) skip this hook. Authenticated contexts without a callable hook fail closed. No principal-module import is required here. The parent supplies `ctx.authorize`, current principal/operation context and its actual authorization policy; `auth/access.py` and `context.py` are untouched. Focused tests exercise two ContextVars across the thread boundary, entry refusal, and revocation before a subsequent range/source. They do not validate the parent's identity provider or token handling.

The parent must run the combined Windows/Linux gates and build the combined UI bundle. No `dist` output is part of this change. Real network connectivity, remote scanner behavior, deployment identity enforcement, screen-reader behavior and additional browser/platform testing remain external acceptance work; unit and browser fixtures do not establish those results.

Scoped paths for integration:

- `cyberthunder/discovery/recipes.py`, `ranges.py`, `models.py` (grant identity), and scope/background-authorization portions of `service.py`.
- `cyberthunder/api/routes/discovery.py` (recipe schemas and endpoints).
- `cyberthunder/ui/src/api/scopeRecipes.ts`, its focused test, and the optional recipe identifiers on normalization entries in `types.ts`.
- `cyberthunder/ui/src/components/ScopeEditor.tsx`, `ScopeEditor.test.mjs`, and `ScopeEditor.browser.mjs`.
- `tests/discovery/test_scope_recipes.py`, `tests/discovery/test_scope_recipes_api.py`, `tests/discovery/test_scope_principal_context.py`, and this document.
