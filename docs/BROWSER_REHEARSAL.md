# Repeatable browser rehearsal

`scripts/rehearse_browser.py` runs the built application through a real Chromium
browser against new simulated Linux state. It exercises the UI, API, engine,
state store and audit log together. It never reuses the operator's inventory or
state directory, and rejects any transport except a simulated one. The fixture
blocks external connections, DNS and datagrams. Browser page requests are
restricted to the fixture origin; service workers and WebSockets are blocked.

Use an existing Python environment with the project's dependencies and a
prepared, committed UI build. Supply an installed Playwright module and a
Chromium executable; this script does not build the UI or install browsers or
packages. With Node, Playwright and its Chromium browser already available:

```sh
python scripts/rehearse_browser.py
```

Explicit paths are supported, including on Windows:

```powershell
python scripts/rehearse_browser.py `
  --node 'C:/Program Files/nodejs/node.exe' `
  --playwright-module 'C:/tools/node_modules/playwright/index.mjs' `
  --browser 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'
```

`--playwright-module` also accepts a local module URL. `CT_PLAYWRIGHT_MODULE` and
`CT_PERMISSION_BROWSER` provide defaults. `--backend json` or `--backend sqlite`
selects one backend; the default exercises both.

Each backend receives two fresh scenarios:

1. Review a stored dependency assessment and approve. In the **Findings** drawer,
   open **Review and history**, choose **Risk accepted**, enter a reason,
   supporting evidence and a future expiry, then press **Accept risk**. Confirm
   the visible hold and retained scanner result, severity and totals. Return to
   the existing approved proposal: **Apply** must be disabled, and a supplemental
   direct apply request must return HTTP 409 specifically for the risk hold.
   Return to the drawer, choose **Prepare risk revocation**, enter its own reason,
   and press **Revoke risk acceptance**. Check both saved decisions, released hold,
   unchanged approval records and unchanged current/historical scanner evidence.
   Engage the kill switch, confirm UI/API refusal (HTTP 423), release with a
   reason, apply, verify, and manually roll back through the saved decision.
2. Repeat the same UI risk and kill-switch sequence with the fixture's explicit
   verification failure armed. Applying must fail verification and recover by
   rollback; it must never record a verified result.

Both risk mutations come from browser form submissions. The runner observes
their responses; it never substitutes direct risk API writes for those clicks.
Read-only API comparisons supplement the visible state. The approved proposal
retains its existing decision and assessment; other unapproved proposals serve
as controls against accidentally granting approval. Risk acceptance leaves the
finding open and unsuppressed. Revocation returns its review to Unreviewed; it
does not approve or execute a fix. The browser uses UTC for reproducible expiry
entry and verifies the saved timestamp and the drawer's displayed expiry.

The normal scenario asserts that the current finding becomes `not_a_finding`
after verification while the original scanner observation stays `open`.
Rollback restores the current finding to `open` with a rescan requirement.
Both scenarios reload the page, find the saved rollback history and verify the
audit chain. The two risk history events and the original historical scanner
observation must also survive remediation and recovery. Browser runtime errors
and attempted off-origin page requests fail the rehearsal.

The runner creates a unique `.build/browser-rehearsals/<run>/` directory:

- `receipts/summary.json`: tested source commit, runtime configuration, source/UI
  SHA-256 hashes, source/build stability and all four case outcomes.
- `receipts/<backend>-<scenario>/result.json`: fixture identifiers, completed
  checks, risk observation hashes, audit result, failure stage and diagnosis.
- The same case directory contains viewport screenshots of the accepted-risk
  drawer, disabled Apply, revoked history and restored decision. A failed UI
  check adds `failure.png` when the browser is available.
- `receipts/SHA256SUMS.json`: hashes of every summary, result and screenshot.
- `private/<backend>-<scenario>/`: disposable fixture manifest, application state
  and server log. Keep this tree separate from the receipts shared for review.

Receipts contain only the synthetic fixture's selected data, not copies of
state, credentials or server logs. Runtime paths are recorded for reproducibility.
All four cases are attempted even after a case fails. Startup or browser-launch
failures receive a failure receipt and private diagnostic log; a screenshot is
possible only after a browser page exists. The summary names the source commit;
run from a clean checkout with its matching UI build when recording release
evidence. The runner refuses uncommitted tracked changes and fails the receipt
if the commit, tracked tree or hashed build artifacts change during the run.
Local untracked notes do not prevent the rehearsal. All fixture processes started
by the runner are stopped on completion or failure. It leaves the evidence files
available for inspection.

This is simulated Linux transport, template explanation output and unverified
loopback development identity. It is **not verified-realm acceptance, official
risk authorization, or target privilege proof**. It is also not live OIDC/CAC
acceptance, a real model evaluation, platform certification, or a scan/remediation
test against a physical host, VM or cluster. Backend security fixtures and live
platform validation remain separate. The ordinary unit-test gate does not
silently skip or substitute this explicit browser rehearsal.

## Integrated risk rehearsal: 2026-11-06 UTC

The prepared application source was `160d2645abc34afcef55e99d553b674fdcca1c40`.
The final four-case run tested clean committed runner source
`dce05223bd815f14bbb98c2006044e24136a2f65` against the supplied
`index-D-kX3hqn.js`, without rebuilding or installing dependencies. Its SHA-256 is
`66fa6337998de6b1bc690db316873c443fb46b8246d9d2475e860d03f3b61c3e`.
The runtime was Windows, Python 3.12.10, installed Playwright and Chromium
156.0.4314.58. Exact runtime paths are in the summary.

| Backend | Scenario | Actual outcome |
| --- | --- | --- |
| JSON | Normal | PASS: UI accept/hold/revoke, kill guard, verified fix, manual rollback |
| JSON | Forced verification failure | PASS: UI accept/hold/revoke, kill guard, failed verification, automatic rollback; no verified transition |
| SQLite | Normal | PASS: UI accept/hold/revoke, kill guard, verified fix, manual rollback |
| SQLite | Forced verification failure | PASS: UI accept/hold/revoke, kill guard, failed verification, automatic rollback; no verified transition |

Every case retained 36 total results, 20 open failures, 16 scanner passes and the
same severity facets throughout acceptance and revocation. The selected finding
remained Medium / CAT II and open. The existing reviewed approval and 16 other
unapproved proposals were unchanged. Acceptance and revocation each returned
HTTP 200 from the actual UI submissions; held Apply returned HTTP 409. Revocation
released Apply without adding approval or altering scanner evidence. Final
rollback restored an open finding with `needs_rescan=true`. All four audit chains
verified with 47 records each; no browser runtime errors or off-origin requests
were recorded. Source/build hashes stayed unchanged and all four fixtures stopped.

The complete passing evidence is retained at
`.build/browser-rehearsals/20261106T072034Z-uglx5fbl/receipts/` (one summary,
four results, sixteen screenshots and their hash manifest). Private state is in
the sibling `private/` directory. This document is a later documentation-only
change; it does not change which source commit was tested.

Two earlier four-case calibration runs are preserved with failure screenshots,
results and hashes, rather than overwritten:

- `20261106T071639Z-rp7x8c95/receipts/`, source `6cdfc00`: all four stopped before
  acceptance because exact expiry-label matching omitted the required marker.
  Runner correction `759662f` matches the required label prefix.
- `20261106T071902Z-c2f1yy0g/receipts/`, source `759662f`: all four completed
  acceptance, the hold and revocation, then stopped because the reason assertion
  matched both the retained input and saved history. Runner correction `dce0522`
  scopes the assertion to saved paragraph text. Neither failure required an
  application change. Both runs kept source/build unchanged and stopped all fixtures.

The earlier run exposed a usability issue: after successful
revocation, the open form retains its draft and still displays **Revoke risk
acceptance**, while the saved history and current review correctly show the
revoked state. See `json-normal/risk-revoked-history.png` in the passing receipts.
Repeat submission of that retained draft was not covered by that run.

### Completed revocation form correction

Source `bee62167d40027a2edda5af76d4bbf51c894e6d0` resets a successfully revoked
risk decision to an empty Unreviewed draft. Failed submissions retain their input.
The component regression failed on the previous behavior, then all 452 UI tests
passed with the correction. A repeated submission of the empty completed form
cannot repeat revocation or silently create another review.

The four-case rehearsal was repeated against the rebuilt `index-fqp8F2eU.js`
(SHA-256 `b01d3e3edfddee70b0216f037bd09e55b1c1190ca56a8995dfddd2dc146b846b`).
All four cases passed at the same source commit, including the new assertions
that the completed Revoke button disappears and the reason field is empty.
The previous risk hold, original scanner evidence, approval, kill-switch,
verification, manual/automatic rollback and audit checks remain in the runner.
Source and build remained unchanged, all fixtures stopped, and no browser runtime
errors were recorded. Receipts are retained at
`.build/browser-rehearsals/20261106T073135Z-l7m2svom/receipts/` and copied with
verified hashes under `.build/owner-evidence/`. The same simulated, template and
unverified-identity limits apply; this is not live account or target acceptance.

## Earlier lifecycle evidence

Validation on 2026-11-06 UTC: source commit
`e15e34bdf101463453c3a8eaa83382d33b277e74` passed all four scenarios on Windows
with Chromium using the committed `index-CN4LjAMg.js` bundle. Normal and
forced-verification-failure recovery passed for both JSON and SQLite. The runner
started and stopped each fixture; every receipt confirmed the finding lifecycle
and audit chain, and the source commit stayed unchanged. The five summary/result
receipts are retained separately from private temporary state. This supersedes
the earlier `a61fff8` rehearsal for this application state, without claiming that
later source changes or verified identity were exercised.
