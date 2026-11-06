# Regression CI (TST-01)

`.github/workflows/regression.yml` runs on pull requests and pushes to `main`.
Each matrix job uses Python 3.12 and Node 22 on a hosted runner:

The job deadline is 90 minutes, including dependency installation and the UI
build. The account-access candidate's local Windows gate took 57 minutes
38 seconds for 6,540 passes and 22 expected skips. This observed local duration
does not predict hosted runner speed; the larger budget accommodates the growing
suite without relaxing individual test deadlines, required checks or skip policy.

The full Linux account-access run exposed `select()`'s fixed descriptor-number
limit in dependency and vulnerability subprocess readers. Both now use the
platform selector with a nonblocking check and explicit resource closure; the
native Windows pipe path is unchanged. Three real-process reproductions with
POSIX pipe descriptors at or above 1024 failed before the correction. The two
affected modules then passed 55 tests on Windows 3.12 and 55 on native Linux
3.12, including output limits, cancellation and inherited-pipe deadlines, with
no skips. These focused results do not replace the full release gate.

| Runner | Pytest state backends | Collection |
| --- | --- | --- |
| `ubuntu-24.04` | JSON and SQLite in the same run | Every test module, including the three deployment modules |
| `windows-2022` | JSON and SQLite in the same run | All except the three existing omissions listed below |

The workflow installs the existing `.[dev]` Python dependencies and runs `npm ci`
against `cyberthunder/ui/package-lock.json`. `npm run build` runs TypeScript and
Vite before pytest, so the existing UI asset test inspects the fresh build.
`npm test` also runs the source component and utility regressions with Node's
built-in test runner before the Python gate. A UI test failure fails the job.
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

Unhandled background thread exceptions fail both ordinary pytest and the CI
runner. Scan tests that do not exercise explanations disable precomputation;
worker tests explicitly start, wait for, and stop their workers.
The shared fixture also fails the test that leaves an explanation worker running
and stops that worker before later tests install their own network guards.

New skips, changed reasons, duplicate skips, teardown skips, xfail/xpass,
deselection and collection skips fail the job. Files matching pytest's normal
`test_*.py` / `*_test.py` names must contribute collected items, except the
three explicitly named Windows omissions. This detects newly ignored modules;
it does not prove that individual tests have not been deleted or renamed.

The reviewed allowances are:

| Platform | Exact test(s) | Maximum skips | Required reason |
| --- | --- | ---: | --- |
| Both | `tests/explain/test_service.py::test_real_local_model[json]` and `[sqlite]` | 2 | `set CT_TEST_LLM=1 to test against a local model server` |
| Windows | `tests/engine/test_inventory_guard.py::test_fifo_or_link_replacement_refuses_promptly_and_releases_target_lock` for `existing_fifo`, `fifo_at_open`, and `symlink_at_open` | 3 | `POSIX FIFO and O_NOFOLLOW semantics` |
| Windows | `tests/security/test_oidc.py::test_posix_private_permissions` | 1 | `POSIX ownership/mode enforcement; Windows requires deployment ACLs` |
| Windows | `tests/security/test_access.py::test_fifo_is_rejected_without_opening_or_waiting` | 1 | `requires POSIX FIFO` |
| Windows | `tests/security/test_oidc.py::test_symlink_cache_and_directory_rejected` | 1 | `POSIX symlinks; Windows reparse handling has a separate fixture` |
| Windows | `tests/security/test_access_file_trust.py::test_posix_policy_write_permissions_denied` for `[400]`, `[386]`, `[438]`, `[950]` | 4 | `requires POSIX owner/mode and descriptor-relative filesystem semantics` |
| Windows | `tests/security/test_access_file_trust.py::test_posix_writable_parent_denied` for `[504]`, `[455]` | 2 | `requires POSIX owner/mode and descriptor-relative filesystem semantics` |
| Windows | `tests/security/test_access_file_trust.py::test_posix_untrusted_owner_denied[file]` and `[parent]` | 2 | `requires POSIX owner/mode and descriptor-relative filesystem semantics` |
| Windows | `tests/security/test_access_file_trust.py::test_posix_permission_change_during_parse_denied` | 1 | `requires POSIX owner/mode and descriptor-relative filesystem semantics` |
| Windows | `tests/security/test_access_file_trust.py::test_posix_root_sticky_directory_exception_never_applies_to_file` | 1 | `requires POSIX owner/mode and descriptor-relative filesystem semantics` |
| Windows | `tests/security/test_access_file_trust.py::test_posix_parent_swap_to_symlink_before_open_denied_and_fds_closed` | 1 | `requires POSIX owner/mode and descriptor-relative filesystem semantics` |
| Windows | `tests/security/test_kube_credentials.py::test_real_posix_config_permission_failure` for `[420]`, `[416]`, `[438]` | 3 | `real POSIX file permissions` |
| Linux | `tests/security/test_oidc.py::test_windows_junction_cache_path_rejected` | 1 | `Windows directory junction fixture` |
| Linux | `tests/security/test_access_file_trust.py::test_actual_windows_junction_parent_denied` | 1 | `requires Windows NTFS junction support` |
| Linux | 63 exact native Windows cases listed in `WINDOWS_FILE_TRUST_TESTS` and `WINDOWS_FILE_TRUST_REVIEW_TESTS` in `scripts/ci_pytest.py` | 63 | `native Windows security descriptors and file sharing` |
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

Credential-resolver tests add 44 exact POSIX cases skipped on Windows and six
native Windows cases skipped on Linux. Their node IDs, reasons and receipt
hashes are recorded in [platform-skips.json](credential-resolver-review/platform-skips.json)
and mirrored in `CREDENTIAL_RESOLVER_SKIPS`. Every case ran successfully on its
native platform. The allowances do not waive actual service-logon provisioning,
kubelet mount acceptance or remote authentication. See
[credential resolver validation](CREDENTIAL_RESOLVERS.md#focused-validation-and-compatibility-migration).

The operator utilities add four exact POSIX audit-anchor protection cases and
one POSIX client-storage case skipped on Windows, plus one native Windows
client-storage case skipped on Linux. [Their receipt hashes and exact reasons](operator-platform-skips.json)
are mirrored in `NATIVE_OPERATOR_SKIPS`. Signed-checkpoint and authenticated-client
fixtures do not establish independent off-node custody or a live enclave login.

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

The node assessment adds 13 exact Linux-only cases on Windows and nine exact
Windows-only cases on Linux. Their literal IDs and reasons are listed in
`NODE_HARDENING_SKIPS` in `scripts/ci_pytest.py` and independently exercised in
[the native review receipts](NODE_HARDENING_REVIEW.md). These are individual
case allowances, not module omissions.

That permits at most **104 skipped cases on Linux and 35 on Windows**, with every
case individually constrained. Missing Git or Bash is not an allowed skip on
either runner. Windows runs the command-shell and file-sharing tests that
Linux skips.

Linux runs the three FIFO/no-follow inventory races that Windows cannot execute.
Those cases were also exercised in WSL during rollback review. The remaining
inventory validation tests run on both platforms; limited Windows link-creation
privileges use a metadata fixture rather than skipping the rejection check.

The access-policy and kubeconfig additions above cover 14 POSIX-only cases on
Windows and one Windows-only junction case on Linux. Numeric parameters are
pytest's decimal IDs for the octal permission values. Linux executes those
POSIX checks; Windows executes both the access-policy and OIDC real junction
checks. The kubeconfig module currently has no Windows-only junction test.
The real symlink and hardlink tests must execute on both runners. Runtime
reasons such as `symlink creation unavailable`, `hardlink creation unavailable`,
or a Windows junction creation error are deliberately not allowances. If a
runner cannot create the required links, its capability must be provisioned
or the failed coverage reviewed; the skip checker remains red.

Windows mode bits and `st_uid` do not establish an owner SID or DACL. Protected
runtime files now use native SID/DACL validation with pinned handle chains;
unavailable native validation fails closed. Conservative checks can reject a
safe but unsupported descriptor rather than guessing effective access. Before
deployment, provision and review restrictive DACLs on the policy, kubeconfig,
referenced credential material, and every ancestor directory. Untrusted accounts
must not be able to write, replace/delete, take ownership, or change permissions
on them. Restrict secret-file reads to the intended service account and trusted
administrators; give the service only the rights its operation requires. Check
effective inherited permissions for the actual service identity and other local
accounts. The native fixtures prove those tested cases, not the actual deployed
service account's protection. The read-only node assessment also does not enforce
future file creation or cover encryption. See
[account access and file trust](ACCOUNT_ACCESS.md) for the runtime boundary.

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

The file-trust skip-policy follow-up was checked against actual pytest reports
from these four modules, with plugin autoload disabled:

```text
python -m pytest -o addopts= -q -rs -p no:cacheprovider tests/security/test_access.py tests/security/test_access_file_trust.py tests/security/test_kube_credentials.py tests/security/test_oidc.py
```

Windows Python 3.12.10 / pytest 9.2.0 recorded 294 passes and 15 expected skips
across the access, access-file-trust and kubeconfig modules. WSL Python 3.14.4 /
pytest 9.2.0 recorded 308 passes and one expected junction skip in those same
modules. The WSL run used native Linux cryptography and the shared environment's
pure Python test dependencies; it is not the hosted Python 3.12 CI environment.
All 14 new Windows-skipped cases passed on Linux. Both real junction cases
(access policy and OIDC) passed on Windows. Real symlink and hardlink cases
passed on both platforms. All observed skip node IDs and reasons matched the
reviewed platform map; there were no unexpected capability skips on Windows.

The accompanying OIDC module had 208 passes, two expected skips and one failure
on Windows: `test_total_deadline_stops_trickle_responses[slow_body]` observed no
server request. An isolated rerun of that case together with the 41 policy
tests passed (42 passes, no skips):

```text
python -m pytest -o addopts= -q -p no:cacheprovider tests/ops/test_ci_policy.py "tests/security/test_oidc.py::test_total_deadline_stops_trickle_responses[slow_body]"
```

The initial WSL OIDC run exposed 24 failures caused by incomplete loopback TLS
fixture certificates. The fixtures now include the certificate extensions
required by strict TLS validation; production trust checks were not weakened.
The corrected focused Linux OIDC run passed 229 tests with one documented
Windows-junction skip. Browser-session and API identity checks subsequently
passed 123 tests on each platform without skips; see [BROWSER_IDENTITY](BROWSER_IDENTITY.md).
Full exact-commit gates, hosted Python 3.12 runners and Windows deployment DACL
acceptance remain separate checks.
