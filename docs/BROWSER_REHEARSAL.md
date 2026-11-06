# Repeatable browser rehearsal

`scripts/rehearse_browser.py` runs the built application through a real Chromium
browser against new simulated Linux state. It exercises the UI, API, engine,
state store and audit log together. It never reuses the operator's inventory or
state directory, and rejects any transport except a simulated one.

Install the project's Python dependencies and build the UI first. Supply an
installed Playwright module and a Chromium executable; this script does not
install browsers or packages. With Node, Playwright and its Chromium browser
already available to the repository:

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

1. Review a stored dependency assessment, approve, engage the kill switch,
   confirm the UI and API refuse apply, release with a reason, apply, verify,
   and manually roll back through the saved decision.
2. Repeat approval and the kill check with the fixture's explicit verification
   failure armed. Applying must fail verification and recover by rollback;
   it must never record a verified result.

The normal scenario asserts that the current finding becomes `not_a_finding`
after verification while the original scanner observation stays `open`.
Rollback restores the current finding to `open` with a rescan requirement.
Both scenarios reload the page, find the saved rollback history and verify the
audit chain. Browser runtime errors fail the rehearsal.

The runner creates `.build/browser-rehearsals/<run>/summary.json`, individual
`result.json` receipts, the temporary application state and server logs. Failed
UI checks also save a viewport screenshot. The summary names the source commit;
run from a clean checkout with its matching UI build when recording release
evidence. All fixture processes started by the runner are stopped on completion
or failure. It leaves the evidence files available for inspection.

This is loopback development identity and template explanation output. It is
not live OIDC/CAC acceptance, a real model evaluation, a platform certification,
or a scan/remediation test against a physical host, VM or cluster. Those tests
remain separate. The ordinary unit-test gate does not silently skip or substitute
this explicit browser rehearsal.
