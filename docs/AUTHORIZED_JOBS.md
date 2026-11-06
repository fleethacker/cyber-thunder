# Authorization for jobs and passive imports

Verified mode carries the submitting principal and its session-validity callback
into vulnerability-update and impact-model threads. A worker label or stored
actor string is not authority to continue a job. Each service rechecks the
current account, role, policy and relevant resource before its bounded IO and
publication boundaries. Development mode retains its existing behavior.

## Required authority

| Operation | Required permission |
| --- | --- |
| Vulnerability database settings and downloads | Node `admin` |
| Import an offline vulnerability database | Node `import` |
| Build and release a vulnerability database export bundle | Node `export` |
| Read an existing database generation during a target scan | The caller's target scan authority; no new database-management grant |
| Impact assessment, including model probe/generation and receipt publication | `plan` on the proposal's target |
| Import scanner results | Node `import` and `import` on every host-map destination |
| Accept a new bulletin and publish its matching findings | Node `import`, `read` on checked source observations, and `import` on every matched host |
| Rematch already accepted bulletins after a full scan | `scan` on the collected targets and published matches; no `import` requirement |

Application roles and the server-managed access policy must both permit the
operation. A target grant does not substitute for a node grant, and node import
does not substitute for target import. Explicit import checks also apply to
repeated scanner uploads before their existing result is returned.

## Queued work and interrupted jobs

Vulnerability updates copy context separately for each job. The worker checks
authorization before preparing its staging directory, before downloader work,
during bounded processing, and before selecting a published generation. A job
whose principal expires or whose session/policy is revoked becomes `stopped`
with a fixed error message and a completion timestamp. Thread construction or
start failure becomes `failed`. Cleanup releases the operation lease and removes
that job's staging files even when authority has been revoked.

Terminal bookkeeping is allowed after denial: recording that work stopped does
not grant permission to resume downloads or select a new database. Existing
interrupted-job recovery remains under the operation lease. It records an
already selected generation as completed, otherwise stops the interrupted job;
it does not recreate the old principal or resume the job as a scheduler.

The previously selected database remains selected when a new update is denied
before its publication commit. A denial after a generation directory is moved
but before selection can leave an unselected generation for normal retention.
It must never be reported as the active database merely because the files exist.

Offline import and export use their own actions throughout processing. Neither
requires admin as an incidental privilege. Existing-generation scan reads do not
download or publish a database; their caller remains responsible for target scan
authorization.

## Impact model work

The existing proposal, target, fix, model-configuration and publication guards
remain in place. Both the proposal and its current finding must pass the shared
`check_record` ownership check for `plan`. A grant on today's target cannot
authorize evidence from a deleted, moved or replaced target. Legacy records with
no captured ownership fail closed in verified mode. Local freshness evaluation
also checks ownership with `read`; unavailable authority cannot imply readiness.
Each bounded model probe/generation thread gets a fresh copy of
the current context and rechecks the assessment guard before calling the backend.
An authorization failure propagates as a denial, rather than becoming a model
error eligible for deterministic fallback. Receipt publication checks authority
again immediately before the store write.

The existing concurrency/time limits still apply. A callback that has not started
before its bounded-call deadline is not invoked. An already dispatched backend
request cannot necessarily be cancelled; late results have no receipt-publication
callback and are discarded. This change does not claim to retract data already
sent before revocation.

## Scanner results and bulletin publication

Scanner imports authorize every explicit destination before temporary parsing and
again at publication boundaries. On nodes with no full baseline, the existing
carry-forward behavior requires `import` on every retained finding's immutable
owner as well. Unauthorized or legacy retained evidence blocks the import; it is
not silently dropped or relabeled. Repeated imports authorize the recorded run
before returning its historical metadata or counts.
They preserve `PermissionError` so callers can
distinguish an authorization denial from an unavailable storage device. They do
not start a scanner, open a target transport or grant remediation permission.

New bulletins check node import before acceptance, then target import for every
matched finding before persistence. Publication is all-or-denied for the matched
host set; the service does not silently publish a subset of unauthorized matches.
Reading the source observations requires `read` on their recorded ownership, so
even checked-host metadata cannot disclose an unreadable environment. The disk
reader accepts a service guard before each raw observation; the pure parser and
matcher remain independent of identity.

Full-scan rematching is a separate path. It reads already accepted bulletins and
uses target scan authority, without rewriting those bulletin documents or
requiring import privilege. When the scanner supplies no actor argument,
verified mode derives it from the current principal. Explicit actor arguments
must still match the principal. This preserves the existing scanner callback
without weakening its permission checks.

Both bulletin paths validate source scan ownership before reading raw evidence
and retain that ownership on derived findings. Missing source ownership and
changed target identities require a new authorized observation; rematching cannot
convert historical data into evidence for today's target. These checks use `scan`
for a full-scan rematch, preserving scan-only authorization.

Both import paths write findings before registering the completed scan run and
recheck authority before that registration. A denial between those writes may
leave staged findings, but no new completed-run marker or current findings view.
These are boundary checks, not an atomic transaction combining policy changes
with all filesystem/database writes. Previously committed evidence is retained.

## Integration boundaries

The API owner must preserve service authorization errors. In particular,
`api/routes/ingest.py` must let `PermissionError` pass through before its scanner
upload handler's `OSError` storage fallback, because `PermissionError` is also an
`OSError`. The normal API error mapping can then return 403 rather than reporting
an authorization denial as storage unavailability.

Export-bundle construction and release are authorized here. Authorization during
later HTTP response-byte streaming belongs to the response/session owner. The
service's retained export lease protects file lifetime; it is not an authorization
token. No browser, session, route, context, gate, scanner-queue or report ownership
logic is changed by this feature.

## Focused validation

The new tests use real principal/policy checks and inert IO on both JSON and
SQLite stores. They cover:

- Worker identity and session-context propagation, with no cross-job identity reuse.
- Policy/session revocation and expiry before a queued downloader starts.
- Terminal job state and released leases after authorization or thread-start failure.
- Revocation before database selection, import publication, or export release.
- Independent admin/import/export permissions and ordinary database scan reads.
- Model authorization before probe/generation and refusal to publish a denied receipt.
- Missing or changed proposal/finding ownership, including deletion and identifier reuse.
- Scanner destination checks, repeat checks, and revocation after parsing/staging.
- Authorization of carry-forward findings and historical repeat metadata.
- Bulletin host checks and the actual full-scan callback using scan-only authority.
- Rejection of old raw observations after target moves, identifier reuse or missing ownership.

These checks establish service behavior, not external identity-provider, live
transport, browser-session or fleet deployment acceptance.
