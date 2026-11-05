# Regression CI (TST-01)

`.github/workflows/regression.yml` runs on pull requests and pushes to `main`.
Each matrix job uses Python 3.12 and Node 22 on a hosted runner:

| Runner | Pytest state backends | Collection |
| --- | --- | --- |
| `ubuntu-24.04` | JSON and SQLite in the same run | Every test module, including the three deployment modules |
| `windows-2022` | JSON and SQLite in the same run | All except the three existing omissions listed below |

The workflow installs the existing `.[dev]` Python dependencies and runs `npm ci`
against `cyberthunder/ui/package-lock.json`. `npm run build` runs TypeScript and
Vite before pytest, so the existing UI asset test inspects the fresh build.
Node 22 satisfies the lockfile's Vite requirement of Node 22.12 or newer.
Python and Node use the latest available patch in their selected release lines;
Python dependencies retain the version ranges in `pyproject.toml`.

Both jobs run the existing `bash scripts/gate.sh`; Windows uses Git Bash.
`GATE_TEST_CMD=python scripts/ci_pytest.py` replaces only the gate's pytest
invocation. The normal forbidden-reference, secret, whitespace and untracked
handoff checks still run, even when tests fail. Full checkout history preserves
the gate's `origin/main..HEAD` commit-message check. On pushes to `main`, that
range may be empty because the revision is already on `origin/main`.

The workflow also checks committed whitespace before building, because the UI
build can modify tracked generated assets and make the normal gate inspect the
working-tree diff instead of the latest commit. These checks keep the existing
gate semantics; they are not a scan of every historical commit.

## Skip and collection policy

`scripts/ci_pytest.py` invokes the full `tests` tree through pytest's public
plugin hooks. It forces `CT_STATE_BACKENDS=json,sqlite`, disables live-model
opt-in and third-party plugin autoload, clears `PYTEST_ADDOPTS`, and rejects
command-line selectors. Each collected test using `state_dir` must have both
backend cases, including each combination of its other parameter values. The
checker compares values within the collection and preserves duplicate counts;
pytest's Cartesian-product indices need not match between backends.

Skips match an exact node ID and exact reason in `expected_skips()`. There are
no directory wildcards, class-wide allowances or pooled skip budgets. Fewer
skips are acceptable. Another test cannot consume an unused allowance.
New skips, changed reasons, duplicate skips, teardown skips, xfail/xpass,
deselection and collection skips fail the job. Files matching pytest's normal
`test_*.py` / `*_test.py` names must contribute collected items, except the
three explicitly named Windows omissions. This detects newly ignored modules;
it does not prove that individual tests have not been deleted or renamed.

The reviewed allowances at the initial baseline are:

| Platform | Exact test(s) | Maximum skips | Required reason |
| --- | --- | ---: | --- |
| Both | `tests/explain/test_service.py::test_real_local_model[json]` and `[sqlite]` | 2 | `set CT_TEST_LLM=1 to test against a local model server` |
| Linux | `tests/report/test_reports.py::test_commander_reproduce_command_runs_in_cmd` | 1 | `runs the command through cmd.exe` |
| Linux | `tests/test_approval_io.py::test_deny_survives_windows_delete_handle[json]` and `[sqlite]` | 2 | `requires Windows file sharing semantics` |
| Linux | `tests/state/test_file_read_sharing.py::test_deny_response_survives_windows_inventory_sharing[json]` and `[sqlite]` | 2 | `requires Windows file sharing semantics` |
| Linux | `tests/state/test_file_read_sharing.py::test_windows_scope_retry_observes_revocation[json]` and `[sqlite]` | 2 | `requires Windows file sharing semantics` |
| Linux | `tests/state/test_file_read_sharing.py::test_json_run_read_survives_windows_sharing` | 1 | `requires Windows file sharing semantics` |
| Linux | `tests/state/test_file_read_sharing.py::test_audit_checkpoint_survives_windows_sharing` | 1 | `requires Windows file sharing semantics` |
| Linux | The 19 exact `tests/test_dev.py::DevelopmentModeTests` methods below | 19 | `UDS CLI is required for configuration and payload rendering.` |

The UDS CLI is not installed by this workflow. These configuration-rendering
tests are collected on Linux but skip without it. Other deployment tests use
fake command shims. This is a coverage limitation, not evidence of a successful
deployment or a fully exercised UDS integration. Installing a reviewed UDS CLI
for these tests is a future improvement; simply widening the allowance is not.

The exact UDS method allowlist is also stored as `UDS_TESTS` in the helper:

```text
test_normal_deployment_excludes_identity_and_credentials
test_dev_deployment_selects_bootstrap_and_prints_credentials
test_dev_retry_reuses_password
test_dev_existing_cluster_preserves_cluster_and_core
test_failed_verification_does_not_print_credentials
test_identity_script_requires_dev_opt_in
test_identity_payload_accepts_special_characters_without_output
test_identity_script_rejects_other_contexts
test_master_bootstrap_preserves_valid_existing_admin
test_master_bootstrap_refuses_to_reset_invalid_existing_admin
test_identity_bootstrap_unlocks_disabled_user_without_resetting_password
test_identity_bootstrap_stops_when_unlock_fails
test_identity_bootstrap_rejects_disabled_account_after_login
test_standalone_setup_creates_credentials_without_deployment
test_standalone_setup_reuses_saved_password
test_standalone_setup_does_not_print_credentials_on_failure
test_standalone_setup_requires_deployment_kubeconfig
test_standalone_setup_rejects_other_contexts_before_creating_password
test_standalone_setup_rejects_arguments
```

That permits at most **30 skipped cases on Linux and 2 on Windows**, with every
case individually constrained. Missing Git or Bash is not an allowed skip on
either runner. Windows runs the command-shell and file-sharing tests that
Linux skips.

`tests/conftest.py` already excludes these Windows modules before collection:

- `tests/test_deploy.py`
- `tests/test_dev.py`
- `tests/test_existing.py`

Their fake tool shims use executable Python shebangs that do not work reliably
under Git Bash with Windows interpreter paths. They are **uncollected modules,
not passed tests or pytest skips**, and are reported separately. CI does not
add ignores on Linux or alter the existing Windows behavior.

## Reports and maintenance

Each job uploads `.build/ci/pytest.xml` and `.build/ci/policy.json` for 14 days,
including after failures when those files exist. Only those two paths are
uploaded. The policy JSON lists collected node IDs, observed skips and reasons,
allowed skips, Windows omissions, outcome counts, policy errors and the final
pytest exit code. A failing policy makes the normal gate red even if pytest
would otherwise accept its skips. The gate prints only the tail of pytest's
output; inspect the reports for the complete case inventory and failures.

To review a new allowance, identify its exact node ID, platform and reason,
explain the missing coverage here, update the helper and run its focused tests.
Do not increase a numerical threshold to hide a missing dependency.

Focused helper verification (tiny synthetic suites, no application suite):

```text
python -m pytest tests/ops/test_ci_policy.py -q
```

Full CI-equivalent gate, after installing dependencies and building the UI,
from Bash or Git Bash:

```bash
GATE_TEST_CMD='python scripts/ci_pytest.py' bash scripts/gate.sh
```

## Permissions, dependencies and limits

The workflow grants only `contents: read`, uses `pull_request` rather than a
privileged PR trigger, and disables persisted checkout credentials. It requests
no repository secrets, deployment environments, cloud credentials, range access
or model service. Dependency installation needs build-time internet access;
the application's offline runtime and runtime dependencies are unchanged.
The tests use fixtures, mocked tools and local temporary state. Hosted runner
networking is not an enforced egress sandbox.

All actions are official upstream actions pinned to release commit SHAs,
verified against their release tags:

| Action | Release | Commit |
| --- | --- | --- |
| `actions/checkout` | [v4.2.2](https://github.com/actions/checkout/releases/tag/v4.2.2) | `11bd71901bbe5b1630ceea73d27597364c9af683` |
| `actions/setup-python` | [v5.6.0](https://github.com/actions/setup-python/releases/tag/v5.6.0) | `a26af69be951a213d495a4c3e4e4022e16d87065` |
| `actions/setup-node` | [v4.4.0](https://github.com/actions/setup-node/releases/tag/v4.4.0) | `49933ea5288caeca8642d1e84afbd3f7d6820020` |
| `actions/upload-artifact` | [v4.6.2](https://github.com/actions/upload-artifact/releases/tag/v4.6.2) | `ea165f8d65b6e75b540449e92b4886f43607fa02` |

Full SHA pins and minimal token permissions follow the
[GitHub Actions security guidance](https://docs.github.com/en/actions/reference/security/secure-use).
The helper uses [pytest reporting and collection hooks](https://docs.pytest.org/en/stable/reference/reference.html#hooks).
Review upstream release notes and resolve new tags to commits before updating
pins. A passing workflow verifies the configured checks; it does not establish
live-cloud, real-range, live-model or browser end-to-end coverage. Browser
automation requiring new dependencies and release-time model checks remain
separate work under TST-02. Branch-protection settings are also separate from
adding this workflow.

Initial implementation validation: all 19 focused helper tests passed on
Windows with Python 3.12 and pytest 9.2. Their child processes run tiny synthetic
suites only. Neither the full repository suite nor a hosted Linux/Windows
workflow run is claimed here. The UI build is configured for GitHub and was not
rerun locally as part of this isolated CI change.
