"""Run the full regression suite with the reviewed CI skip policy (docs/CI.md)."""
from __future__ import annotations

from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import sys
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
BACKENDS = ("json", "sqlite")
WINDOWS_IGNORED = frozenset({
    "tests/test_deploy.py", "tests/test_dev.py", "tests/test_existing.py",
})
MODEL_REASON = "set CT_TEST_LLM=1 to test against a local model server"
SHARING_REASON = "requires Windows file sharing semantics"
UDS_REASON = "UDS CLI is required for configuration and payload rendering."
# Exact names: a new test in this class must not silently inherit an allowance.
UDS_TESTS = (
    "test_normal_deployment_excludes_identity_and_credentials",
    "test_dev_deployment_selects_bootstrap_and_prints_credentials",
    "test_dev_retry_reuses_password",
    "test_dev_existing_cluster_preserves_cluster_and_core",
    "test_failed_verification_does_not_print_credentials",
    "test_identity_script_requires_dev_opt_in",
    "test_identity_payload_accepts_special_characters_without_output",
    "test_identity_script_rejects_other_contexts",
    "test_master_bootstrap_preserves_valid_existing_admin",
    "test_master_bootstrap_refuses_to_reset_invalid_existing_admin",
    "test_identity_bootstrap_unlocks_disabled_user_without_resetting_password",
    "test_identity_bootstrap_stops_when_unlock_fails",
    "test_identity_bootstrap_rejects_disabled_account_after_login",
    "test_standalone_setup_creates_credentials_without_deployment",
    "test_standalone_setup_reuses_saved_password",
    "test_standalone_setup_does_not_print_credentials_on_failure",
    "test_standalone_setup_requires_deployment_kubeconfig",
    "test_standalone_setup_rejects_other_contexts_before_creating_password",
    "test_standalone_setup_rejects_arguments",
)


def expected_skips(platform: str) -> dict[str, str]:
    if platform not in {"linux", "win32"}:
        raise ValueError(f"Unsupported CI platform: {platform}")
    allowed = {
        f"tests/explain/test_service.py::test_real_local_model[{backend}]": MODEL_REASON
        for backend in BACKENDS
    }
    if platform == "linux":
        allowed.update({
            f"tests/test_dev.py::DevelopmentModeTests::{name}": UDS_REASON
            for name in UDS_TESTS
        })
        allowed["tests/report/test_reports.py::test_commander_reproduce_command_runs_in_cmd"] = (
            "runs the command through cmd.exe"
        )
        for node in (
            "tests/test_approval_io.py::test_deny_survives_windows_delete_handle",
            "tests/state/test_file_read_sharing.py::test_deny_response_survives_windows_inventory_sharing",
            "tests/state/test_file_read_sharing.py::test_windows_scope_retry_observes_revocation",
        ):
            allowed.update({f"{node}[{backend}]": SHARING_REASON for backend in BACKENDS})
        for name in (
            "test_json_run_read_survives_windows_sharing",
            "test_audit_checkpoint_survives_windows_sharing",
        ):
            allowed[f"tests/state/test_file_read_sharing.py::{name}"] = SHARING_REASON
    return allowed


class RegressionPolicy:
    def __init__(self, root: Path, platform: str):
        self.root = root.resolve()
        self.platform = platform
        self.allowed = expected_skips(platform)
        self.errors: list[str] = []
        self.skips: list[dict] = []
        self.outcomes: Counter = Counter()
        self.collected: list[str] = []
        self.ignored: list[str] = []
        self.seen_skips: set[str] = set()

    def pytest_collectreport(self, report):
        if report.skipped:
            self.errors.append(f"Collection skipped: {report.nodeid}")

    def pytest_deselected(self, items):
        self.errors.extend(f"Deselected: {item.nodeid}" for item in items)

    def pytest_collection_finish(self, session):
        self.collected = [item.nodeid for item in session.items]
        modules = {node.split("::", 1)[0] for node in self.collected}
        expected = {
            path.relative_to(self.root).as_posix()
            for path in (self.root / "tests").rglob("*.py")
            if path.name.startswith("test_") or path.name.endswith("_test.py")
        }
        omitted = expected - modules
        allowed_omissions = WINDOWS_IGNORED if self.platform == "win32" else frozenset()
        self.ignored = sorted(omitted & allowed_omissions)
        self.errors.extend(f"Module not collected: {name}" for name in sorted(omitted - allowed_omissions))

        # Check every state fixture test, including each combination of other parameters.
        state_cases = defaultdict(Counter)
        for item in session.items:
            if "state_dir" not in item.fixturenames:
                continue
            spec = getattr(item, "callspec", None)
            if spec is None or "state_dir" not in spec.params:
                self.errors.append(f"State backend not parametrized: {item.nodeid}")
                continue
            # Pytest may number other parameter indices across the entire Cartesian product,
            # so their indices differ between backends. Compare the actual parameter values
            # within this collection and retain multiplicity for duplicate values.
            other = tuple(sorted((key, type(value).__module__, type(value).__qualname__, repr(value))
                                 for key, value in spec.params.items() if key != "state_dir"))
            key = (item.nodeid.split("[", 1)[0], other)
            state_cases[key][spec.params["state_dir"]] += 1
        if not state_cases:
            self.errors.append("No state backend cases collected")
        for (node, other), backends in state_cases.items():
            if set(backends) != set(BACKENDS) or len(set(backends.values())) != 1:
                self.errors.append(f"Incomplete state backends: {node}: {dict(backends)}")

    def pytest_runtest_logreport(self, report):
        self.outcomes[f"{report.when}:{report.outcome}"] += 1
        if hasattr(report, "wasxfail"):
            self.errors.append(f"Unexpected xfail/xpass: {report.nodeid}")
        if not report.skipped:
            return
        reason = str(report.longrepr[2]) if isinstance(report.longrepr, tuple) else str(report.longrepr)
        reason = reason.removeprefix("Skipped: ")
        accepted = (
            not hasattr(report, "wasxfail")
            and report.when in {"setup", "call"}
            and self.allowed.get(report.nodeid) == reason
            and report.nodeid not in self.seen_skips
        )
        self.skips.append({"nodeid": report.nodeid, "phase": report.when, "reason": reason, "allowed": accepted})
        self.seen_skips.add(report.nodeid)
        if not accepted:
            self.errors.append(f"Unexpected skip: {report.nodeid} ({report.when}): {reason}")

    def pytest_sessionfinish(self, session, exitstatus):
        if self.errors and exitstatus == pytest.ExitCode.OK:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED
        output = self.root / ".build" / "ci"
        output.mkdir(parents=True, exist_ok=True)
        (output / "policy.json").write_text(json.dumps({
            "platform": self.platform,
            "backends": list(BACKENDS),
            "collected": self.collected,
            "ignored_modules": self.ignored,
            "skip_allowances": self.allowed,
            "skips": self.skips,
            "outcomes": dict(self.outcomes),
            "errors": self.errors,
            "exit_code": int(session.exitstatus),
        }, indent=2) + "\n", encoding="utf-8")

    def pytest_terminal_summary(self, terminalreporter):
        terminalreporter.section("CI regression policy")
        terminalreporter.write_line(f"Collected {len(self.collected)} cases; {len(self.skips)} skips")
        for module in self.ignored:
            terminalreporter.write_line(f"Known Windows collection omission: {module}")
        for error in self.errors:
            terminalreporter.write_line(error, red=True)
        terminalreporter.write_line("CI POLICY FAIL" if self.errors else "CI POLICY PASS")


def main() -> int:
    os.chdir(ROOT)
    # A developer's local selection or installed plugin must not narrow the CI run.
    os.environ["PYTEST_ADDOPTS"] = ""
    os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    os.environ["CT_STATE_BACKENDS"] = ",".join(BACKENDS)
    os.environ["CT_STATE_BACKEND"] = "json"
    os.environ["CT_TEST_LLM"] = "0"
    output = ROOT / ".build" / "ci"
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ct-ci-") as state:
        os.environ["CT_STATE_DIR"] = state
        return int(pytest.main(
            ["tests", "-ra", "--strict-markers", f"--junitxml={output / 'pytest.xml'}"],
            plugins=[RegressionPolicy(ROOT, sys.platform)],
        ))


if __name__ == "__main__":
    if len(sys.argv) != 1:
        sys.exit("CI requires the full suite; test selectors and extra options are not accepted")
    sys.exit(main())
