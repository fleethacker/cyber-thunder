# Security control contribution and evidence map

Cyber Thunder supplies some technical mechanisms and assessment evidence for a
larger system. This document identifies those contributions and their limits.
It does not select the system's control baseline, declare a control satisfied,
or establish authorization to operate.

The intended readers are the system owner, ISSO, control assessor and authorizing
official's staff. Every claim below refers to the source delivered with this
document; record the exact commit and deployed image digest when using it in an
assessment. An unmerged branch or fixture receipt is not evidence of deployed
behavior. Features under development on other branches are excluded.

The family references use [NIST SP 800-53 Revision 5 and its published updates](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final).
NIST's publication page identifies Release 5.2.0. The organization must tailor
its selected controls and parameters and determine the applicable assessment
procedures using [SP 800-53A](https://csrc.nist.gov/pubs/sp/800/53/a/r5/final).
The [NIST Risk Management Framework](https://csrc.nist.gov/projects/risk-management)
separates implementation, assessment and the official's authorization decision.
The relationships below are project interpretations, not a NIST endorsement or
a claim that this software covers an entire family.

## Boundary and operating assumptions

The application node holds inventory, findings, approvals, rollback snapshots,
reports and an audit chain. It may contact explicitly configured identity and
model services, scoped targets, and approved content sources. Native and
container deployments remain supported. A container-local scan observes the
container; an authorized remote connection is required to inspect its host.
See [architecture](ARCHITECTURE.md), [account access](ACCOUNT_ACCESS.md) and
[host registration](HOST_SCOPE.md).

Configured OIDC/mesh mode verifies account identity. Application roles intersect
target, environment and operation grants. A node administrator does not thereby
gain target access or approval authority. A selected target credential must
also be permitted by the remote system. Its existence does not prove that the
remote account has only the intended privileges. Local development mode uses
explicitly unverified names and cannot supply verified-person evidence.

Protected configuration, the node OS/service account and the identity provider
are trusted boundaries. Compromise of a trusted node administrator is not
contained by an ordinary application role. Current browser sessions require one
application process. Token/session expiry is enforced, but immediate revocation
of an already issued standalone bearer token is not established. Record the
chosen token lifetimes, role mappings and disconnected-operation policy.

## Contributions and remaining responsibilities

| Family / assessment concern | What the application contributes | What the deployment or organization must provide | Evidence and open work |
|---|---|---|---|
| AC / permitted actions and data access | Role checks intersect explicit account/group grants by target, environment and operation. Historical artifacts retain original target ownership; replacing an ID does not grant access to its old evidence. | Approve the account/group mappings, enroll and remove users, test actual remote privileges, and restrict node administration. | [Roles and resource enforcement](../cyberthunder/control/access.py), [artifact ownership](../cyberthunder/security/resources.py), [account-isolation regressions](../tests/security/test_account_isolation_review.py). ZT-08/10/12/13/14. |
| AC / independent approval and least privilege | Verified proposers cannot approve their own change. High or unknown severity requires two distinct approvers; other severities require one. Scan and change operations select their own explicit target bindings. Partial approval does not permit execution. | Establish role assignments and remote read/change accounts; decide whether additional first-device restrictions apply; validate permissions at each target. | [Approval checks](../cyberthunder/control/separation.py), [transport binding](../cyberthunder/context.py), [approval reports](APPROVAL_REPORT_EVIDENCE.md), [separation tests](../tests/security/test_separation_of_duties.py). ZT-09/16/18. |
| IA / identity and sessions | Signed OIDC/mesh tokens, bounded cached signing keys, browser PKCE, server-held tokens, CSRF checks, session expiry and local logout. Sensitive actions require signed authentication age and an explicitly configured assurance value. | Operate the IdP and trust roots, map trustworthy claims, configure authenticators, provision CAC/PIV where required, and approve outage/revocation behavior. A password fixture does not establish CAC assurance. | [OIDC validation](../cyberthunder/security/oidc.py), [browser sessions](BROWSER_IDENTITY.md), [step-up](STEP_UP.md), [local provider evidence](OIDC_REVIEW.md). ZT-01/03/04/05/06/07/26. |
| IA / target authenticators | Account/action-bound SSH, WinRM and protected static Kubernetes configurations; verified paths refuse ambient shared-account fallback. Fleet transport trust checks apply separately. | Issue, protect, rotate and revoke the actual authenticators; configure remote authorization, broker policy, delegation and service-account custody. Environment references alone are not a production vault. | [Credential binding](../cyberthunder/security/credentials.py), [Kubernetes credentials](../cyberthunder/security/kube_credentials.py), [transport policy](TRANSPORT_SECURITY.md), [secret boundaries](SECRET_BOUNDARIES.md). ZT-12 through ZT-22. |
| AU / attributable events | Audit records include actor and recorded principal evidence; reports preserve independent approval receipts and their audit association. Older unverified records remain unverified. | Define the required event set, monitor collection failures, protect time sources, assign reviewers and handle the personal/security information in records. | [Audit chain](../cyberthunder/audit/chain.py), [report evidence](../cyberthunder/report/approvals.py), [report review tests](../tests/report/test_approval_report_review.py). ZT-23/25. |
| AU / integrity and retention | Hash chaining and a local head checkpoint detect many edits and truncation. Native Windows or POSIX checks protect selected runtime files; the node assessment reports observed state permission metadata. | Restrict writers, keep independent anchors, determine retention, and operate acknowledged off-node forwarding. A writer able to replace both chain and checkpoint can defeat local hash-only evidence. | [Chain verification](../cyberthunder/audit/chain.py), [node assessment](NODE_HARDENING.md). Signed anchors, rotation and SIEM delivery remain ZT-24/25; runtime backup is separate from source backup. |
| CM / reviewed changes | The engine executes vetted library payloads bound to approval evidence, captures declared before-state, verifies supported checks and attempts recovery after failed verification. The model cannot supply executable replacement payloads. | Approve maintenance windows, service ownership, lockout recovery and application/data backup. Review change dependencies beyond the evidence the tool can collect. | [Engine](../cyberthunder/remediation/engine.py), [payload library](../cyberthunder/remediation/library.py), [rollback guards](../cyberthunder/remediation/rollback_guard.py), [change history](CHANGE_HISTORY.md), [browser rehearsal](BROWSER_REHEARSAL.md). COV-02/03, REM-01/03, MVP-07/09. |
| CM / authorized content | Versioned library records, selected publication maintenance, download provenance and operator-signed transfer envelopes support controlled content ingestion. Known-invalid signatures cannot be excused as unsigned content. | Approve signing-key custody and trusted publishers, validate applicability and scanner readiness, and protect the release process. Operator signatures are not DISA publisher signatures. | [Content authenticity](CONTENT_AUTHENTICITY.md), [publication accounting](CATALOG_ACCOUNTING.md), [scan content](SCAN_CONTENT.md). CON-01, DOC-05, VAL-03; downgrade prevention and interrupted publication recovery remain open here. |
| SI / detection and correction evidence | Deterministic native/SCAP checks, imported scanner results, bulletin matching and managed Trivy data produce normalized findings. Supported remediation verification changes the current finding view while preserving original observations. | Provision suitable benchmark/database/image content, validate coverage on each actual platform, review false positives and missing evidence, and respond to detected conditions. Finding absence does not establish a clean system. | [Scanner](../cyberthunder/scan.py), [vulnerability data](VULNERABILITY_DATA.md), [current finding semantics](../cyberthunder/findings/current.py), [coverage](COVERAGE.md). SCAN-01/02/03/04, VAL-01/02, MVP-03/04/06. |
| SC / connection boundaries | Fleet SSH host trust, WinRM HTTPS validation, explicit target scope and credentialed-request protections reduce unintended connections. Deployment templates describe authenticated ingress. | Provision TLS/mTLS, network egress policy, service identities, trusted names/roots and approved model/content endpoints. Test the actual native or UDS deployment. | [Transport security](TRANSPORT_SECURITY.md), [deployment identity](../packages/cyberthunder/docs/IDENTITY_REVIEW.md), [scope guard](../cyberthunder/inventory/targets.py). ZT-27/28/29/30, MVP-01/10. |
| CP / restoration evidence | Per-change before-state and supported rollback checks can restore selected configuration. Source checkpoints retain Git history and tested source. | Provide consistent runtime/database and application-data backup, retention, off-node storage and tested recovery objectives. Source ZIPs and Git bundles do not contain runtime credentials, VM disks or every scanner cache. | [Change history](CHANGE_HISTORY.md), [backup instructions](CONTRIBUTING.md), [state storage](STATE.md). SCL-04, COV-02, MVP-09. |

These rows identify contributions to selected concerns within each family.
They do not cover all controls or enhancements. The control assessor must assign
specific control identifiers, organization-defined parameters, inheritance and
assessment objectives for the actual system boundary.

## Evidence packet for a deployment review

1. **Identify the tested system.** Record source commit, application/image digest,
   package version, operating system, state backend, identity mode and review
   date. Retain the matching test/skip-policy receipts. A successful test against
   a different commit is supporting history, not the deployment result.
2. **Record the intended authority model.** Supply a redacted approved role/grant
   matrix and remote account privilege descriptions. Include two unequal-access
   users, an administrator without target grants, an unauthorized account and
   the proposed approval separation. Do not export passwords, tokens, private
   keys, credential paths or full environment dumps.
3. **Collect identity acceptance evidence.** Demonstrate the intended realm and
   authenticator, denied/expired access, permission changes, sign-out and the
   chosen disconnected behavior. Keep signed claim metadata and categorical
   results; do not retain bearer tokens. The local Keycloak receipt remains
   separate from enclave/CAC acceptance.
4. **Retain a scoped change record.** From Decisions / Changes, select a proposal
   and retain its original finding, exact payload, dependency assessment,
   distinct approvals, apply and verification outcomes, and any rollback result.
   Preserve uncertain/failed outcomes. [Report exports](../cyberthunder/report/service.py)
   and [their access checks](../cyberthunder/report/access.py) require the current
   account's node export permission and export grants for the included artifacts'
   original ownership. Report generation also requires the separate node-wide
   audit permission because reports consume audit evidence or its verified head.
5. **Verify audit evidence under its own permission.** Audit access is a separate
   node-wide grant; permission to read one target is not permission to read the
   whole chain. An authorized operator can use the Audit view and
   [`/api/v1/audit/verify`](../cyberthunder/api/routes/audit.py). Retain the matching
   complete chain/checkpoint under the records policy when whole-chain review is
   authorized. A filtered event list is not a complete verifiable chain.
6. **Attach coverage and unresolved findings.** Keep the coverage report,
   unavailable/unsupported checks, benchmark/database versions, scanner errors
   and POA&M. A simulated answer-key score measures that seeded fixture only.
7. **Record deployment controls and gaps.** Add actual service ACLs, network
   policy, backup/restore evidence, supply-chain/SBOM review and the assigned
   owners/dates for open backlog items. A local outbox move is not acknowledged
   delivery to another system.

Assessment artifacts can contain sensitive hostnames, accounts, software
versions and operational details. Store and share them within the authorized
boundary and records policy. This document does not assign a classification or
retention period.

## Review record and unresolved decisions

| Field | Current record |
|---|---|
| Implementation source reviewed | `a5d031acbb50f44ab3d5acf7723beacf2a4bccb6`; source review only, no deployed image assessed |
| System boundary and baseline | Not assigned by this project document |
| ISSO / control assessor | Not assigned; no external review has been recorded |
| Authorizing official / sponsor | Not confirmed |
| Authorization decision | None recorded |

Before closing ATO-03, record the actual reviewer, review date and source/deployed
revision here or link the approved assessment record. For each question, retain
the answer, evidence reference, owner and unresolved disposition. Open decisions
include applicable control IDs and enhancements; account/credential ownership;
acceptable assurance and outage limits; audit/time/retention/anchor custody;
backup and lockout recovery; supported platforms; and maintenance/supply-chain
responsibilities. The [backlog](BACKLOG.md) remains the work record until those
criteria are met.
