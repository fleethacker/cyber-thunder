# Assessing what a fix could disrupt

Use **Assess impact** before approving a proposed change. This is an advisory
assessment of a specific fix and target. It combines bounded dependency evidence
with the configured model's interpretation and keeps unresolved questions visible.
It is not a probability of success or proof that applying the change is safe.

The assessment shows affected services or workloads, observed relationships,
possible management-access loss, disruption, recommended checks and rollback
limitations. A model cannot remove a collected risk, lower its severity, approve
a proposal or supply executable commands. Each model claim must reference
available evidence. Invalid or unavailable model output produces a clearly
labelled deterministic assessment, preserving the evidence and unknowns.

Validation checks the response structure and references against the supplied
evidence. It does not prove the model's causal conclusions or predict every
failure. Review the cited facts and application-specific checks before deciding.

## Evidence coverage

| Target | Bounded read-only evidence | Limits |
|---|---|---|
| Linux | Declared affected systemd services, required/wanted units, reverse dependencies and state | Direct relationships only; application and network dependencies may be missing |
| Windows | Declared service state, required services and dependent services | No full application, AD or network dependency graph |
| Kubernetes | Scoped workload/pod, service, replica, disruption-budget, volume and service-account relationships | Collection limits and permissions can leave gaps; referenced names are not secret values |
| Other platforms | Declared fix metadata and explicitly unknown dependencies | No claim of live topology validation |

The collector chooses fixed read operations; it does not run the proposed fix.
It checks the actor, target scope and kill switch, bounds calls and output, and
omits secret values, environment dumps and full configuration files. Simulated
and recorded evidence is labelled accordingly. Declared capture files are not
necessarily the complete set of resources a script can change.

## Review and freshness

Each assessment is an immutable receipt bound to the proposal, full fix digest,
nonsecret target connection declarations, current finding and collected evidence. Receipts
are stored through StateStore under `change_assessments/` with either JSON or
SQLite. Audit events record receipt identifiers, hashes and model status.

Required key/configuration files must be readable and their file identity and
metadata are included in the binding. Credential values and file contents are
not hashed into public receipts. Credential rotation, privileges, external
credential plugins and remote-host identity are not attested by this comparison.
Missing or invalid persisted scope makes the assessment unavailable or stale.

The receipt's maximum lifetime is 15 minutes from its evidence time. Before
approval and again before execution, the service checks its bindings and age.
These are local checks: a target can change between collection and execution.
Unknown dependencies require an explicit review note when attaching a receipt.
If a reviewed receipt expires, assess again and review the new receipt on the
still-approved proposal before applying it. Assessment does not apply the fix.

Existing direct API/CLI and standing-policy workflows can still approve without
a receipt. Such a decision is **not assessed**, never implicitly cleared by the
model. The GUI requires either review of an assessment or a deliberate reason
for proceeding without one. Assessment availability is not a new source of
approval authority, and the existing approval, scope and kill-switch guards apply.

## Command line

Global `--state-dir` and `--actor` options precede the command:

```text
cyberthunder --actor "operator name" assess PROPOSAL_ID
cyberthunder --actor "operator name" assess PROPOSAL_ID --stored-only
cyberthunder assess PROPOSAL_ID --latest
cyberthunder --actor "operator name" proposals approve PROPOSAL_ID --assessment-id RECEIPT_ID --assessment-note "Reviewed the missing application dependencies and planned a maintenance window."
cyberthunder --actor "operator name" proposals review-impact PROPOSAL_ID --assessment-id NEW_RECEIPT_ID --assessment-note "Reviewed the refreshed evidence and outstanding checks."
```

`--latest` only reads saved state. `--stored-only` omits target access and keeps
live dependencies unknown. An explicit assessment request may take as long as
the configured model timeout; ordinary GET requests do not trigger inference.

Independent recovery after connection loss, maintenance-window enforcement,
canaries and broader dependency coverage remain tracked under COV-02 and COV-03
in [BACKLOG](BACKLOG.md). This assessment does not implement those protections.
