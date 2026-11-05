# Change history, finding status and rollback

The **History** view on Decisions loads saved proposals, including completed
changes from earlier sessions. Filter by state, target, actor or date and search
for a proposal or finding. Proposal links in Audit open the corresponding change;
the original decision actor is separate from the actor recorded for a later
rollback. History persists in the selected JSON or SQLite state backend.

## What happens to a finding

A verified fix can close an older open observation in the current findings view.
The scanner's original result, evidence and saved scan/report artifacts remain
unchanged. An actual rollback attempt withdraws an earlier clean result because
the target may have changed, even when restoration fails partway through. The
current view shows the open finding or **needs rescan** rather than silently
retaining a pass. A strictly later observation establishes the target's current
condition; equal or unknown timestamps are treated conservatively.

An unsuccessful preflight is different from a restoration attempt: it does not
write to the target, mark the proposal rolled back or invalidate observations.
A failed restoration never receives a successful rollback state. The audit chain
retains attempts and outcomes; saved before-state and apply-time after-state are
kept for investigation. A retry replaces the latest result file, not prior audit
events.

## Restoring an older change

Open an applied or verified proposal in History, inspect its **Diff**, then choose
**Rollback**. The confirmation shows the saved plan and the available guard
coverage. Viewing this information makes no target connection. The engine repeats
its checks when the restore is requested, so a displayed result is not a durable
authorization. The CLI/API also support the existing failed-proposal recovery
path. A named actor, current target scope and a disengaged kill switch are still
required.

A week-old change can be restored only while its necessary state and access remain
available and its guards pass. There is no automatic one-week expiration. Keep
the complete state volume, including audit records and rollback snapshots, in the
node backup; a source-code backup alone cannot restore this history.

The engine serializes cooperating apply, verify and rollback operations by target
id. Later recorded change attempts on the same target block an older restore,
including failed attempts and changes to other findings. This conservative check
does not assume that two fixes touch independent resources. A changed recorded
endpoint or fix also blocks restoration.

For supported Linux `restore_files` fixes, a retained post-apply manifest binds
the captured file bytes, type, mode and ownership. Before a manual restore, the
adapter compares the current files with that manifest. Drift, missing or
unreadable resources, changed snapshot material and missing required baselines
block the restore. A Linux file snapshot from before this manifest existed is
not silently treated as current.

## Coverage limits

**Files** means that the listed restoration files are compared. **Partial** means
that file checks cannot cover all script, service or other effects. **Unsupported**
means that no live platform drift comparison exists. None means the whole restore
is safe. Windows, Cisco, Kubernetes and non-file rollback kinds do not gain a
general drift guarantee from the Linux checks. Existing unsupported restore paths
retain their compatibility behavior and may overwrite external changes.

Locks coordinate workers using this state directory and target id. They do not
lock other administrators, other nodes or aliases for the same host. A remote
write can race the final file comparison; ACLs, extended attributes, application
state and interrupted sessions are outside these file checks. The endpoint
binding is an inventory comparison, not cryptographic host authentication or
credential/privilege attestation.

Immediate recovery after apply/verification failure retains its existing
semantics inside the target operation lock. It still depends on a usable control
connection and the adapter's rollback capabilities. Independent recovery after
management access is lost remains in [BACKLOG](BACKLOG.md), COV-02. After any
restoration, inspect service health and run a fresh scan.
