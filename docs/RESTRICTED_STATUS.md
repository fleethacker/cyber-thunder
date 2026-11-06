# Restricted node status in the UI

An authenticated reader can have access to selected targets without access to
node-wide operational details. The sanitized `/status` response marks
`global_details: false`, returns the visible target count and kill-switch state,
and sets audit counts, audit head and verification, standing-policy fields,
model, link and outbox count to `null`.

Header badges, Commander and Settings display restricted details explicitly.
Commander labels counts as belonging to assets visible to the account and keeps
the kill-switch state visible. A restricted response also suppresses cached
audit verification and any stale global values. Settings keeps the signed-in
account, sign-out and library navigation available, while global policy, link
and demonstration controls are not mounted. They also wait for initial node
status before mounting, avoiding premature global configuration requests.

Null details without the restriction flag display as unknown. They never imply
a zero queue, a disabled policy, an offline node or a failed model. Explicit
full-status zero values, operator-offline states and verification failures keep
their existing meanings. Older full-status fixtures may omit the flag.

Content, content downloads and vulnerability database updates tolerate a null
link. Cached library connectivity does not override an explicitly unknown or
restricted link. Online actions remain disabled, including direct invocation
of their handlers; local browsing and refresh remain available.

These displays are hints based on the server response, not authorization checks.
The backend remains responsible for target visibility and every operation.
They do not establish an account's right to modify node configuration.

## Validation

`RestrictedStatusRendering.test.mjs` renders the real header, Commander and
Settings components with real Mantine controls and an explicit IdentityProvider.
It checks restricted and unknown responses, stale global data, legitimate zeros,
kill-switch visibility, full and legacy fixtures, and known negative states.
Network-backed child controls are instrumented to fail if mounted for a
restricted account. The page tests also invoke disabled online-action handlers
and check that no request is issued.

From `cyberthunder/ui`:

```powershell
node --test src/components/RestrictedStatusRendering.test.mjs src/components/ContentUpdates.test.mjs src/pages/ContentTasks.test.mjs src/pages/Vulnerabilities.test.mjs src/components/VulnerabilityRendering.test.mjs src/lib/linkPresentation.test.mjs src/components/PermissionControlsRendering.test.mjs src/components/IdentityProvenance.test.mjs src/state/Identity.test.mjs
npm run typecheck -- --force
```

`IdentityProvider` supplies the same `can(action)` function to the identity
context and its nested `PermissionProvider`, connecting account permissions to
the action controls.

These are local fixture checks. End-to-end acceptance still requires a limited
account exercised against its actual target grants.
