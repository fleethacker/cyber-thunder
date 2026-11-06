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
- Every test that takes a state directory runs twice, once per document backend (json files and SQLite, see
  [STATE.md](STATE.md)); `CT_STATE_BACKENDS=json python -m pytest -q` runs one backend while iterating.
- Fixture-first testing. No network and no live hosts in tests. Fake transports with `FixtureTransport` or a
  simulated transport; capture real sessions with `RecordingTransport` on the range and commit the fixture.
- Standard library first. Runtime dependencies are declared in both `requirements.txt` and `pyproject.toml`.
  Add a dependency only for a concrete requirement, with review, offline wheel support and tests.
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

## Backups and restore

Keep a complete copy of the repository somewhere other than GitHub (an external drive, the team share, a second
cloud). Two files cover the committed source: a git bundle holds every branch and
commit, and a source ZIP can be opened without Git. Check `git status --short` and
commit intended source changes first; neither archive includes uncommitted work.
Run from the repository root with a new dated output name for each checkpoint.

```bash
git bundle create ../cyber-thunder-$(date +%F)-full-history.bundle --all
```

```bash
git bundle verify ../cyber-thunder-$(date +%F)-full-history.bundle
```

Create the ZIP from tracked committed source rather than archiving the entire
checkout, which may also contain ignored state, credential fixtures and `.build`
diagnostics. This command works in PowerShell and Bash:

```text
git archive --format=zip --output=../cyber-thunder-source.zip HEAD
```

Replace the output filename with a dated checkpoint name. Keep the bundle beside
it for the other branches and full history. Runtime state and selected evidence
need their own deliberately scoped backup; see [STATE.md](STATE.md#backups).
Do not add private keys, client token caches or raw credential fixtures to a
source/evidence archive. Preserve those through the deployment's credential
custody process.

To rebuild a working repository from the bundle on any machine with git:

```bash
git clone cyber-thunder-YYYY-MM-DD-full-history.bundle cyber-thunder
```

Then point it back at the shared remote when one exists:

```bash
git remote set-url origin https://github.com/fleethacker/cyber-thunder.git
```

Untracked material is not in the bundle: the STIG downloads under `range/downloads/` (public, re-downloadable
from public.cyber.mil), local model files, and anything under `state/`.

Taking the tool to a new environment (inventory, transports, benchmarks, new adapters): see [ADAPTING.md](ADAPTING.md).
