# Static remediation preview

`apply <proposal-id> --plan` inspects the vetted fix bound to an existing proposal.
It returns static metadata and records one `remediation.plan` audit event for each
returned preview. It does not authorize a change or prove that a fix is safe.
This is the bounded first part of COV-03; host validation and maintenance-window
enforcement remain outside this change.

```sh
cyberthunder --actor "ITC Rivera" apply <proposal-id> --plan
```

The CLI prints only the JSON preview on success, including when a metadata check
is blocked or unknown. Exit status 0 means a preview was produced, not that a
proposal is ready to execute. Refusals return 2 on stderr. Combining `--plan` and
`--simulate-verify-fail` is refused before opening application state. The plan
branch never falls through to execution.

The equivalent HTTP request is `POST /api/v1/proposals/{pid}/plan` with a named
human `X-Actor` header. It returns 200 with the same JSON object. Missing or
reserved machine/policy identities are rejected by `ActorDep` with 400. An
unknown proposal returns 404, invalid fix binding returns 409, and an engaged
kill switch returns 423. A missing or unavailable planner returns 501. The engine also requires a named human actor and checks
the kill switch when called directly.

## Version 1 response

| Field | Meaning |
| --- | --- |
| `version`, `mode` | `1`, `"static"` |
| `generated_at` | UTC timestamp of this preview |
| `proposal_id`, `proposal_state` | Stored proposal identity and state |
| `target` | Explicit allowlist: `id`, `name`, `asset_type`, `simulated`, `in_scope` |
| `fix` | Complete `FixEntry.to_dict()`: vetted payload or runbook steps, capture and verification declarations, service/reboot impact, rollback and citations |
| `fix_sha256` | Existing engine digest over all declared fix fields |
| `approved_fix_sha256` | Digest recorded with the proposal, or `null` for a legacy proposal; despite its name, its presence does not mean the proposal was approved |
| `checks` | Objects containing `code`, `status` (`pass`, `blocked`, `unknown`) and explanatory `detail` |
| `limitations` | Explicit limits of the static preview |

For a missing inventory target, `target.id` is the proposal's host and the other
four fields are `null`. Target addresses, usernames, credential references and
raw target options are not returned.

## Metadata checks

| Code | What it reports |
| --- | --- |
| `scope` | Current inventory scope flag; missing inventory is unknown |
| `approval` | Whether the stored proposal is currently approved; other states are blocked |
| `fix_binding` | Preview and full-entry digest match; a legacy preview-only binding is unknown |
| `current_finding` | Whether the finding exists in the current stored view, matches `proposal.host`, and is open |
| `suppression` | Active review suppression for the matching current finding; missing/mismatched current finding is unknown |
| `policy_evidence` | Existing evidence/review eligibility for a proposal approved under standing policy; missing/mismatched/non-open current evidence is blocked. Without standing-policy approval, this check is unassessed (`unknown`) |

A pass describes only the stated metadata check. Even if every check passes,
the result is not an execution-readiness or safety assessment. Current findings
can themselves be stale; the policy evidence check uses the existing confidence
and review rules, including freshness. Individual human approval is not granted
or revoked by this preview.

## Content binding and side effects

The preview checks the current library entry first. If absent, it reads the
already-saved proposal fix without creating a snapshot directory. If neither
exists, a dynamic SSG entry may be reconstructed from stored scanner fix content
for a known nonsimulated target, without adding anything to the library. Missing,
malformed or mismatched entries are refused with `EngineError`. An altered
library entry is refused even when an older matching saved entry exists. Preview
text and the recorded digest use the engine's existing binding semantics; legacy
proposals without a digest cannot establish full metadata binding.

Historical stored scanner content may reconstruct a bound SSG entry, but only
the current findings view is used for review and policy readiness. It must match
both the proposal's finding ID and host. Historical observations and the engine's
in-memory finding cache never fill a gap in those readiness checks.

The planner never connects to a target, creates a transport, captures before-state,
runs payloads or verification, generates explanation text, changes a proposal,
writes snapshots, updates the fix library, or consumes demo flags. The only
intentional write for a returned preview is its audit event. That event contains
the actor, proposal/finding/target/fix IDs, digests and check statuses; it excludes
fix payloads, review text, target options and credentials. The existing kill
guard retains its usual blocked-action audit behavior.

Current host contents, access, applicability and lockout safety have **not** been
tested. `before_state.files` lists declared capture paths, **not** every file a
payload might touch. Maintenance windows are **not enforced** by this change.
Runbook steps are displayed without issuing or performing them. Apply, approval,
verification and rollback retain their existing guards and behavior; previews
are informational and may become stale immediately.
