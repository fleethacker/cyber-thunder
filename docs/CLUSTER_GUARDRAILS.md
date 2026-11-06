# Cluster baseline authorization

The active cluster survey and image baseline use the existing inventory scope,
operator actor, kill switch and hash-chained audit log. Only isolated range or
local test clusters may be authorized.

## Packaged startup

`CT_BOOTSTRAP_CLUSTER_TARGET` remains opt-in. When enabled, startup registers a
missing target with `in_scope: false`. Its ID comes from
`CT_BOOTSTRAP_CLUSTER_TARGET_ID` (default `test-cluster`); the proposed connection
uses `CT_BOOTSTRAP_CLUSTER_KUBECONFIG`, context `in-cluster`, and `kubectl`.
This context matches the packaged kubeconfig. A different kubeconfig requires
operator review of the inventory connection before authorization.

The supplied Kubernetes manifests enable this registration and name the target
`local-cluster` (Local Kubernetes cluster). It appears in Assets automatically,
with `sudo: false`, but discovery and scans remain blocked until an operator
authorizes it through the existing scope control. Existing operator targets keep
their own connection, scope and privilege settings.

Registration is audited as `inventory.bootstrap` under `CT_SCHEDULER_ACTOR`.
The record explicitly says authorization is required. A scheduler actor may
register this out-of-scope candidate; that registration grants no scan authority.
An engaged kill switch blocks registration and records `action.blocked`, while
allowing API startup so an operator can inspect state and release the switch.
Startup does not retry registration automatically after release; restart the
service or register the target through the existing inventory workflow.

Existing targets are left unchanged, including their connection options and
scope. Restarting never re-enables a revoked target. Targets authorized by an
older installation also retain their scope: review those authorizations when
upgrading. The existing periodic inventory scanner selects only in-scope targets.

## Operator workflow

1. Review the target in Inventory (`GET /api/v1/targets`). Confirm the ID,
   `asset_type: kubernetes`, `transport: kubeconfig`, and the intended isolated
   range. Simulated targets cannot use this active cluster path.
2. For development, set `options.kubeconfig` to the intended file and `options.context` to its
   explicit named context. `options.kubectl` may select the executable; it defaults
   to `kubectl`. Missing or blank connection values are refused. There is no
   fallback to the process's default kubeconfig or current context.
   Verified operation instead selects the authenticated account's protected
   kubeconfig/context binding for that action; inventory defaults do not supply
   a shared administrative account. See [account access](ACCOUNT_ACCESS.md).
3. Authorize using the existing scope control, or
   `PUT /api/v1/targets/{target_id}` with `{"in_scope": true}` and the operator's
   verified identity and administrative grants. This records `scope.change`.
4. Send authenticated `POST /api/v1/cluster/baseline` with optionally
   `{"target_id": "test-cluster"}`. The active survey uses
   `GET /api/v1/cluster/survey?target_id=test-cluster` and also requires current
   scan authority and the corresponding account connection binding.
   Omitting `target_id` selects `CT_BOOTSTRAP_CLUSTER_TARGET_ID`; the selected
   target must already exist and be authorized.

In loopback development mode only, `X-Actor` supplies a typed, unverified
attribution label. Verified mode uses signed OIDC/mesh identity or its browser
session and role/resource grants; `X-Actor` cannot replace that principal.
The existing human checks also reject unnamed and reserved machine/policy actors.

## Execution and audit

Service callers must pass `actor` explicitly to `survey()` or `scan()`; each
accepts an optional `target_id`. Every kubectl call uses the kubeconfig, context
and executable resolved for that target and, in verified mode, the acting account's
explicit binding. Bootstrap connection settings
are only candidate defaults, never an alternate execution connection.

The service pins that connection for the run and rechecks the current inventory
and kill switch before and after every external call, including image scans and
optional generated descriptions, and before publishing the baseline. A removed,
revoked or changed target stops the run. Guard failures propagate instead of
becoming ordinary per-resource errors. Tool failures without a guard violation
retain the existing partial-baseline behavior.

Every check rereads the persisted inventory authorization source using its
existing parser, even if the inventory's cached file signature has not changed.
Missing, unreadable or malformed inventory stops access; cached targets cannot
authorize continued work. Both the current target and its persisted connection
must be explicitly in scope and agree. Save inventory changes before scanning.
Unexpected authorization or kill-check exceptions are fatal, including transient
IO failures; they cannot become recoverable scanner errors. Their audit/API
messages include the exception type, without copying raw parser diagnostics or
inventory contents. The prior cached baseline remains readable after these stops.

The audit records `cluster.survey.start` / `cluster.baseline.start` and a terminal
`cluster.survey` / `cluster.baseline` event. Events include the requesting actor,
run ID, target ID, kubeconfig path, named context and executable when resolved.
Terminal outcomes distinguish success, partial results, rejection, interruption
and errors. No kubeconfig contents are copied into the audit log. Returned and
stored results also carry `requested_by` and `target` provenance.

`GET /api/v1/cluster/risk` reads the last cached baseline without starting tools,
requiring an actor or bypassing a stop. It remains readable during a kill or after
scope revocation. Inspect its timestamp and target provenance: it is a single
last-completed cache, not a fresh survey or a cache per cluster. Older cached
results may lack provenance.

HTTP responses follow the existing API mapping: 400 for missing/reserved actor,
403 for missing/out-of-scope/wrong-kind targets, connection changes or an
authorization check that cannot be completed, and 423
for an engaged kill switch.

## Limits and integration

Checks occur at call boundaries. A command already running finishes or reaches
its existing timeout before the stop takes effect; this is not process
preemption. Completed raw tool reports can remain in the run directory after an
interruption, but an interrupted collection does not replace the cached baseline.
Inventory checks and external calls are not one atomic transaction. Operators
must protect the referenced kubeconfig and executable. Verified account-bound
kubeconfigs also undergo protected-file and content rechecks; these checks do
not attest the target cluster's actual RBAC or service identity.

Direct service callers must supply the acting identity and remain subject to
current-principal checks. HTTP clients use configured verified authentication;
`X-Actor` applies only in development. Clients selecting a
non-default target can use the new optional `target_id`. Custom packages must
register the correct context through inventory because bootstrap currently uses
the packaged `in-cluster` context.
