# Contributing

## Set up

Clone outside any synced folder (OneDrive and similar corrupt `.git`), for example `C:\dev\cyber-thunder`.

```bash
python -m pip install -r requirements-dev.txt
```

Without internet, install from the wheels in `vendor/`:

```bash
python -m pip install --no-index --find-links vendor -r requirements-dev.txt
```

Run the tests for your area, then the whole suite before you push:

```bash
python -m pytest tests/<area> -q
```

```bash
python -m pytest -q
```

Set the commit hook once per clone:

```bash
git config core.hooksPath .githooks
```

## Rules

- Own branch named `<name>/<topic>`, your own git identity, changes land by pull request.
- One logical change per commit. Message: one plain-English sentence saying what it adds or fixes and why.
- Run the gate script in `scripts/` before pushing (as designed: tests plus an import check of every package).
  If it is not present on your branch, run the full suite and `python -c "import cyberthunder"` by hand.
- Fixture-first testing. No network and no live hosts in tests. Fake transports with `FixtureTransport` or a
  simulated transport; capture real sessions with `RecordingTransport` on the range and commit the fixture.
- Standard library first. Runtime dependencies are exactly those in `requirements.txt`; do not add any.
  Test dependencies are in `requirements-dev.txt`.
- Paths work on Windows and Linux: `pathlib`, `tempfile` in tests, `encoding="utf-8"`, `newline=""` for CSV.
- Point `CT_STATE_DIR` at a temp directory before running anything that writes state.
- Every finding is built with `make_finding()` and cites a STIG id, CCI, CVE, IAVM id or ATT&CK technique.
  Do not invent identifiers.
- Executable payloads live only in `FixEntry` objects. Never run text that came from a model, a finding or
  any free-text field.
- Keep to your area's directory and tests. Shared files (schema, adapter base, context, CLI, app factory,
  requirements, `.gitignore`) change only by agreement; add CLI commands through your module's
  `register_cli(subparsers)` and API routes in `cyberthunder/api/routes/<name>.py`.
- Comments and docs are written for the Sailor or engineer who maintains this later. Do not name tools,
  assistants or generators anywhere in the repository, including commit messages.
- Never test against live Navy networks. Use the local range ([range/README.md](../range/README.md)).
- Do not copy code from access-controlled government tools into this repository. Call them externally and
  parse their output.

## Adding an adapter

Follow [ARCHITECTURE.md](ARCHITECTURE.md) section 6: adapter package, asset type, collect plus pure detection
methods, fix entries with before-state, verify and rollback, optional simulated transport, tests, fixtures,
seeds and an answer-key file under `range/answer_key/<type>.json`.
