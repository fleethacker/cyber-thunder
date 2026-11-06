# Approval evidence in exported reports

Commander, POA&M and CKLB exports retain every independent approval receipt for
each included proposal. A second approval no longer hides the first behind the
legacy `decided_by` field. Evidence includes the proposer, required quorum,
requirements/source association, canonical actors, full recorded principals,
receipt IDs, approval times, notes, and payload/assessment associations.

The export distinguishes recorded identity, recorded proposal state, evidence
validation at export, and current permission to apply. They are separate facts.

## Formats and compatibility

Commander HTML and Markdown show all proposals, including partial, denied,
cancelled and completed proposals, with each recorded reviewer and proposer.
Full recorded JSON accompanies the readable rows. HTML details are open by
default, and long evidence wraps for printing. These reports may span multiple
pages when complete approval evidence requires it.

Commander JSON is available through `ReportService.commander(scan_id, "json")`,
`GET /api/v1/reports/commander?format=json`, and the report CLI:

```text
python -m cyberthunder --state-dir <state> report commander --format json --out commander.json
```

Existing commander keys and the legacy `decided_by` / `decision_identity` fields
remain. The additive `proposal_approvals` list contains complete evidence for
every included proposal; `verified` and `reverted` entries also carry
`approval_evidence`. Saved JSON reports use the existing history ownership checks.
Previously saved snapshots remain unchanged; generate a new report to include
the additional evidence rather than rewriting historical exports.
The API returns the service's exact JSON text with `application/json`, preserving
the saved report bytes. It enforces the same export permission and original
target ownership as other report formats. Other page formats and queued-report
defaults are unchanged.

POA&M keeps every existing column in its existing order and appends:

* `Proposed By` and `Proposer Identity`: the latest proposal's proposer.
* `Approval Quorum` and `Approval Validation`: each associated proposal's recorded
  count/state and the export-time evidence-check result.
* `Approval Evidence`: a JSON array with the complete records, including earlier
  cancelled or superseded proposals for the same finding and host.

The existing comments also retain all associated reviewers. Partial quorum asks
for the remaining independent approvals. Cancelled proposals ask for a new
proposal; an approved record asks for revalidation before apply. CSV writer
quoting preserves multiline notes as one row. Formula-like cells, including
leading whitespace/control characters or a BOM, receive a leading apostrophe
for spreadsheet safety. This escaping applies to the CSV representation, not the
structured row data. Audit row counts parse the CSV instead of counting newlines.

CKLB keeps the STIG Viewer schema and scanner/verification closure rules. Approval
evidence is appended to rule comments, preserving existing reviewer comments and
the original input file. Both synthetic and updated checklists retain prior
associated proposals. Approval alone never marks a finding remediated.

## Meaning of validation

The report uses `control.separation.validate` to check the creation record,
audited receipt/lifecycle associations, distinct identities, payload, and current
finding/fix requirements. Ownership and audit permission are checked before
reading this evidence. Ownership failures abort export; they are never converted
to an unverified but readable report. Existing final ownership checks still run
before saving or returning an export.

Validation statuses are `checked`, `not_established`, `legacy_unavailable`, and
`not_checked` (local comment formatting without application context). A failed
check retains the disputed historical receipts and reports the failure without
including raw exception messages. `quorum_evidence_checked` describes that
specific evidence check; it is not approval to act, including after cancellation
or completion. `current_apply_authorization` is always
`not_established_by_report`. The gate must separately recheck current account
authorization and dependency assessments before application.

Recorded principal attribution remains meaningful after a reviewer's login
expires. Issuer, subject and canonical actor distinguish people sharing the same
display name, including equal subject names from different issuers. Development
identities remain explicitly unverified. Legacy proposals without separation
fields retain the final recorded decision; no missing vote or quorum is invented.
Reports are historical snapshots, not signed attestations or fresh authentication.
The protected local state and audit checkpoint remain trust dependencies.

## Verification

`tests/report/test_approval_evidence.py` exercises the real separated approval gate
and access policy on both JSON and SQLite. It covers complete and partial quorum,
denial/cancellation, verified/rolled-back states, prior proposals, same-name
reviewers, distinct issuers, changed findings/fixes/receipts/audit, unavailable
sources, expired logins, revoked application rights, original target ownership,
HTML/Markdown escaping, CSV formulas/multiline rows, legacy records, unverified
development mode, and preserved CKLB inputs.

Run the new regressions and all existing report tests with:

```text
CT_STATE_BACKENDS=json,sqlite
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
python -m pytest tests/report -o addopts= -q --tb=short -p no:cacheprovider
```

Windows Python 3.12 verification completed with 363 passed, zero failures and zero
skips for the report suite (523.17 seconds). The CLI JSON regression was added
after that run collected tests and passed separately on both stores:

```text
python -m pytest tests/report/test_approval_evidence.py -k commander_cli -o addopts= -q --tb=short -p no:cacheprovider
```

That focused check passed 2 cases with 74 deselected in 14.97 seconds. Together
these runs cover 365 distinct cases, including all 76 new regressions. The suite
reported 17 existing Starlette/FastAPI deprecation warnings; the CLI check reported
one existing Starlette warning. Neither run reported a thread warning.
Local JUnit receipts are `.build/approval-report-tests.xml` and
`.build/approval-report-cli-tests.xml`.

The new regressions use isolated state and deny target/network access. No external
dependency was added. Parent integration owns the complete cross-platform gate
and API integration; Linux was not rerun for this scoped patch.
