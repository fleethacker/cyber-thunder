"""Exercise CI enforcement against tiny synthetic suites, never the repository suite."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest
import yaml

from scripts.ci_pytest import (
    MODEL_REASON, SHARING_REASON, UDS_REASON, UDS_TESTS, WINDOWS_IGNORED,
    RegressionPolicy, expected_skips,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = '''import os
import pytest
@pytest.fixture(params=os.environ["CT_STATE_BACKENDS"].split(","))
def state_dir(request):
    return request.param
'''


def run_suite(tmp_path, files=None, *, conftest=FIXTURES, options=""):
    (tmp_path / "scripts").mkdir()
    shutil.copy(ROOT / "scripts/ci_pytest.py", tmp_path / "scripts/ci_pytest.py")
    sources = {
        "pytest.ini": f"[pytest]\naddopts = -q {options}\n",
        "tests/conftest.py": conftest,
        "tests/test_backends.py": "def test_backend(state_dir):\n    assert state_dir in ('json', 'sqlite')\n",
        **(files or {}),
    }
    for name, source in sources.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    env = dict(os.environ, CT_TEST_LLM="1", CT_STATE_BACKENDS="json", PYTEST_ADDOPTS="-k nonexistent")
    result = subprocess.run(
        [sys.executable, "scripts/ci_pytest.py"], cwd=tmp_path, env=env,
        capture_output=True, text=True, timeout=60,
    )
    report_path = tmp_path / ".build/ci/policy.json"
    assert report_path.exists(), result.stdout + result.stderr
    return result, json.loads(report_path.read_text(encoding="utf-8"))


def test_full_runner_overrides_local_selection_and_live_model_opt_in(tmp_path):
    result, report = run_suite(tmp_path, {"tests/test_environment.py": '''import os
def test_environment():
    assert os.environ["CT_TEST_LLM"] == "0"
    assert os.environ["CT_STATE_BACKEND"] == "json"
    assert os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
'''})
    assert result.returncode == report["exit_code"] == 0, result.stdout + result.stderr
    assert len(report["collected"]) == 3
    assert report["errors"] == [] and report["skips"] == []
    assert (tmp_path / ".build/ci/pytest.xml").is_file()


def test_exact_optional_model_skips_remain_allowed(tmp_path):
    result, report = run_suite(tmp_path, {"tests/explain/test_service.py": f'''import pytest
@pytest.mark.skip(reason={MODEL_REASON!r})
def test_real_local_model(state_dir):
    raise AssertionError("must not contact a model")
'''})
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(report["skips"]) == 2 and all(s["allowed"] for s in report["skips"])


def test_unhandled_background_thread_failure_is_red(tmp_path):
    result, report = run_suite(tmp_path, {"tests/test_thread.py": '''import threading
def test_background():
    def fail():
        raise RuntimeError("background work failed")
    worker = threading.Thread(target=fail)
    worker.start()
    worker.join()
'''})
    assert result.returncode == report["exit_code"] == 1
    assert "PytestUnhandledThreadExceptionWarning" in result.stdout
    assert "background work failed" in result.stdout


def test_leaked_explanation_worker_fails_its_own_test(tmp_path, monkeypatch):
    monkeypatch.setenv("PYTHONPATH", str(ROOT))
    result, report = run_suite(tmp_path, {
        "tests/test_backends.py": "def test_backend(state_dir):\n    assert state_dir.is_dir()\n",
        "tests/test_worker.py": '''from cyberthunder.explain.worker import ExplainWorker
from cyberthunder.findings.schema import Finding
def test_leaked_worker(state_dir):
    worker = ExplainWorker(lambda finding: None)
    worker.submit(Finding(host="fixture", source="test", rule_id="rule", title="test", severity="low", status="open"))
    assert worker.wait_idle(timeout=2)
''',
    }, conftest=(ROOT / "tests/conftest.py").read_text(encoding="utf-8"))
    assert result.returncode == report["exit_code"] == 1, result.stdout + result.stderr
    assert report["outcomes"]["teardown:failed"] == 2
    assert "test_leaked_worker[json] left 1 explanation worker(s) running" in result.stdout
    assert "test_leaked_worker[sqlite] left 1 explanation worker(s) running" in result.stdout


@pytest.mark.parametrize("source, diagnostic", [
    ("import pytest\n@pytest.mark.skip(reason='new dependency')\ndef test_new(): pass\n", "Unexpected skip"),
    ("import pytest\npytest.skip('module unavailable', allow_module_level=True)\n", "Collection skipped"),
    ("import pytest\n@pytest.mark.xfail(reason='known bug')\ndef test_new(): assert False\n", "Unexpected xfail/xpass"),
    ("import pytest\n@pytest.mark.xfail(reason='known bug')\ndef test_new(): pass\n", "Unexpected xfail/xpass"),
    ("import pytest\ndef test_new(): pytest.skip('runtime skip')\n", "Unexpected skip"),
    ("import pytest\n@pytest.fixture\ndef resource():\n    yield\n    pytest.skip('teardown skip')\n"
     "def test_new(resource): pass\n", "Unexpected skip"),
])
def test_unexpected_skip_and_expected_failure_are_red(tmp_path, source, diagnostic):
    result, report = run_suite(tmp_path, {"tests/test_new.py": source})
    assert result.returncode == report["exit_code"] == 1
    assert any(diagnostic in error for error in report["errors"]), report


def test_changed_reason_does_not_borrow_a_model_allowance(tmp_path):
    result, report = run_suite(tmp_path, {"tests/explain/test_service.py": '''import pytest
@pytest.mark.skip(reason="model connection failed")
def test_real_local_model(state_dir): pass
'''})
    assert result.returncode == 1
    assert all(not s["allowed"] for s in report["skips"])


def test_new_collection_ignore_is_red(tmp_path):
    result, report = run_suite(tmp_path, {"tests/test_new.py": "def test_new(): pass\n"},
                               conftest=FIXTURES + "\ncollect_ignore = ['test_new.py']\n")
    assert result.returncode == 1
    assert "Module not collected: tests/test_new.py" in report["errors"]


def test_deselection_is_red(tmp_path):
    result, report = run_suite(tmp_path, {"tests/test_new.py": "def test_new(): pass\n"}, options="-k backend")
    assert result.returncode == 1
    assert "Deselected: tests/test_new.py::test_new" in report["errors"]


def test_missing_backend_is_red(tmp_path):
    result, report = run_suite(tmp_path, conftest=FIXTURES.replace(
        'os.environ["CT_STATE_BACKENDS"].split(",")', '["json"]'))
    assert result.returncode == 1
    assert any("Incomplete state backends" in error for error in report["errors"])


def test_cartesian_parameters_match_values_across_backends(tmp_path):
    result, report = run_suite(tmp_path, {"tests/test_cartesian.py": '''import pytest
@pytest.mark.parametrize("action,value", [("read", {"active": True}), ("write", {"active": False})])
@pytest.mark.parametrize("attempt", [1, 2])
def test_combination(state_dir, action, value, attempt):
    assert state_dir in ("json", "sqlite")
'''})
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(report["collected"]) == 10 and report["errors"] == []


def test_duplicate_parameter_values_keep_backend_multiplicity(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test_duplicate.py").write_text("def test_case(): pass\n", encoding="utf-8")
    def item(backend, index):
        return SimpleNamespace(nodeid=f"tests/test_duplicate.py::test_case[{backend}-{index}]",
                               fixturenames=["state_dir"],
                               callspec=SimpleNamespace(params={"state_dir": backend, "value": "same"},
                                                        indices={"state_dir": 0, "value": index}))
    items = [item("json", 0), item("json", 1), item("sqlite", 2), item("sqlite", 3)]
    complete = RegressionPolicy(tmp_path, "win32")
    complete.pytest_collection_finish(SimpleNamespace(items=items))
    assert complete.errors == []
    incomplete = RegressionPolicy(tmp_path, "win32")
    incomplete.pytest_collection_finish(SimpleNamespace(items=items[:-1]))
    assert any("Incomplete state backends" in error for error in incomplete.errors)


@pytest.mark.parametrize("source, code", [
    ("def test_new(): assert False\n", 1),
    ("raise RuntimeError('collection error')\n", 2),
])
def test_native_pytest_failures_are_preserved(tmp_path, source, code):
    result, report = run_suite(tmp_path, {"tests/test_new.py": source})
    assert result.returncode == report["exit_code"] == code


def test_windows_omissions_are_explicit_and_not_linux_allowances(tmp_path):
    for name in WINDOWS_IGNORED:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("def test_example(): pass\n", encoding="utf-8")
    for platform in ("linux", "win32"):
        policy = RegressionPolicy(tmp_path, platform)
        policy.pytest_collection_finish(SimpleNamespace(items=[]))
        omissions = [error for error in policy.errors if error.startswith("Module not collected:")]
        assert len(omissions) == (3 if platform == "linux" else 0)
        assert set(policy.ignored) == (WINDOWS_IGNORED if platform == "win32" else set())


def test_allowances_are_bounded_by_exact_node_reason_and_platform():
    linux, windows = expected_skips("linux"), expected_skips("win32")
    assert len(linux) == 110 and len(windows) == 102
    native_acl = {node: reason for node, reason in linux.items()
                  if node.startswith("tests/security/test_windows_file_trust.py::")}
    assert len(native_acl) == 46
    assert set(native_acl.values()) == {"native Windows security descriptors and file sharing"}
    assert not any(node.startswith("tests/security/test_windows_file_trust.py::") for node in windows)
    native_review = {node: reason for node, reason in linux.items()
                     if node.startswith("tests/security/test_windows_file_trust_review.py::")}
    assert len(native_review) == 17
    assert all(node.count("::") == 1 for node in native_acl | native_review)
    assert "tests/security/test_windows_file_trust.py::test_parent_mutation_including_delete_child_is_rejected[parent-2]" in native_acl
    assert set(native_review.values()) == {"native Windows security descriptors and file sharing"}
    assert not any(node.startswith("tests/security/test_windows_file_trust_review.py::") for node in windows)
    assert len(UDS_TESTS) == 19
    assert UDS_REASON not in linux.values()
    assert sum(reason == SHARING_REASON for reason in linux.values()) == 8
    policy = RegressionPolicy(ROOT, "linux")
    node = next(iter(linux))
    report = SimpleNamespace(nodeid=node, when="setup", outcome="skipped", skipped=True,
                             longrepr=("file.py", 1, "Skipped: " + linux[node]))
    policy.pytest_runtest_logreport(report)
    policy.pytest_runtest_logreport(report)
    assert [skip["allowed"] for skip in policy.skips] == [True, False]
    with pytest.raises(ValueError, match="Unsupported CI platform"):
        expected_skips("unknown")


@pytest.mark.parametrize("platform,node,reason", [
    ("win32", "tests/test_release_vulnerability_evidence.py::EvidenceTests::test_fifo_is_rejected_without_open", "POSIX special file"),
    ("linux", "tests/test_release_vulnerability_evidence.py::ProcessTests::test_retained_traceback_cannot_retain_open_process_handle", "Windows native handle lifetime"),
])
def test_release_evidence_skips_require_the_exact_native_case(platform, node, reason):
    other = "linux" if platform == "win32" else "win32"
    for host, case, detail, accepted in (
        (platform, node, reason, True), (other, node, reason, False),
        (platform, node + "_new", reason, False), (platform, node, reason + " changed", False),
    ):
        policy = RegressionPolicy(ROOT, host)
        policy.pytest_runtest_logreport(SimpleNamespace(nodeid=case, when="call", outcome="skipped", skipped=True,
            longrepr=("file.py", 1, "Skipped: " + detail)))
        assert policy.skips[0]["allowed"] is accepted


@pytest.mark.parametrize("platform,node,reason", [
    *[("win32", f"tests/security/test_access_file_trust.py::{name}",
       "requires POSIX owner/mode and descriptor-relative filesystem semantics") for name in (
        "test_posix_policy_write_permissions_denied[400]",
        "test_posix_policy_write_permissions_denied[386]",
        "test_posix_policy_write_permissions_denied[438]",
        "test_posix_policy_write_permissions_denied[950]",
        "test_posix_writable_parent_denied[504]",
        "test_posix_writable_parent_denied[455]",
        "test_posix_untrusted_owner_denied[file]",
        "test_posix_untrusted_owner_denied[parent]",
        "test_posix_permission_change_during_parse_denied",
        "test_posix_root_sticky_directory_exception_never_applies_to_file",
        "test_posix_parent_swap_to_symlink_before_open_denied_and_fds_closed",
    )],
    *[("win32", f"tests/security/test_kube_credentials.py::test_real_posix_config_permission_failure[{mode}]",
       "real POSIX file permissions") for mode in (420, 416, 438)],
    ("linux", "tests/security/test_access_file_trust.py::test_actual_windows_junction_parent_denied",
     "requires Windows NTFS junction support"),
])
def test_file_trust_skip_requires_exact_case_reason_platform_and_phase(platform, node, reason):
    other_platform = "linux" if platform == "win32" else "win32"
    for host, candidate, explanation, phase, accepted in (
        (platform, node, reason, "setup", True),
        (other_platform, node, reason, "setup", False),
        (platform, node, reason + " changed", "setup", False),
        (platform, node + "[new-case]", reason, "setup", False),
        (platform, node, reason, "teardown", False),
    ):
        policy = RegressionPolicy(ROOT, host)
        policy.pytest_runtest_logreport(SimpleNamespace(
            nodeid=candidate, when=phase, outcome="skipped", skipped=True,
            longrepr=("file.py", 1, "Skipped: " + explanation),
        ))
        assert policy.skips[0]["allowed"] is accepted
        assert bool(policy.errors) is not accepted


@pytest.mark.parametrize("node,reason", [
    ("tests/security/test_access_file_trust.py::test_symlink_at_any_component_is_rejected_before_open[file]",
     "symlink creation unavailable on this filesystem (errno=13, winerror=1314)"),
    ("tests/security/test_access_file_trust.py::test_actual_windows_junction_parent_denied",
     "Windows junction creation unavailable (winerror=5)"),
    ("tests/security/test_kube_credentials.py::test_real_symlinks_in_file_or_parent_chain_are_denied[False]",
     "symlink creation unavailable"),
    ("tests/security/test_kube_credentials.py::test_real_symlinks_in_file_or_parent_chain_are_denied[True]",
     "symlink creation unavailable"),
    ("tests/security/test_kube_credentials.py::test_hardlinked_credential_files_are_denied",
     "hardlink creation unavailable"),
])
def test_missing_real_filesystem_capability_is_not_a_platform_allowance(node, reason):
    for platform in ("linux", "win32"):
        policy = RegressionPolicy(ROOT, platform)
        policy.pytest_runtest_logreport(SimpleNamespace(
            nodeid=node, when="call", outcome="skipped", skipped=True,
            longrepr=("file.py", 1, "Skipped: " + reason),
        ))
        assert policy.skips[0]["allowed"] is False
        assert any("Unexpected skip" in error for error in policy.errors)


@pytest.mark.parametrize("platform,receipt_name,count", [("linux", "linux", 9), ("win32", "windows", 13)])
def test_node_assessment_allowances_match_native_review_and_refuse_other_cases(platform, receipt_name, count):
    receipt = json.loads((ROOT / f"docs/node-hardening-review/{receipt_name}.json").read_text())
    expected = {row["nodeid"]: row["reason"] for row in receipt["assessment_skips"]}
    actual = {node: reason for node, reason in expected_skips(platform).items()
              if node.startswith(("tests/security/test_node_hardening.py::",
                                  "tests/security/test_node_hardening_review.py::"))}
    assert actual == expected and len(actual) == count
    other = "linux" if platform == "win32" else "win32"
    for node, reason in actual.items():
        for host, candidate, explanation, phase, accepted in (
            (platform, node, reason, "setup", True),
            (other, node, reason, "setup", False),
            (platform, node + "[new]", reason, "setup", False),
            (platform, node, reason + " changed", "setup", False),
            (platform, node, reason, "teardown", False),
        ):
            policy = RegressionPolicy(ROOT, host)
            policy.pytest_runtest_logreport(SimpleNamespace(
                nodeid=candidate, when=phase, outcome="skipped", skipped=True,
                longrepr=("file.py", 1, "Skipped: " + explanation),
            ))
            assert policy.skips[0]["allowed"] is accepted
            assert bool(policy.errors) is not accepted


@pytest.mark.parametrize("platform,count", [("linux", 6), ("win32", 44)])
def test_credential_skip_allowances_match_native_receipts_and_fail_closed(platform, count):
    receipt = json.loads((ROOT / "docs/credential-resolver-review/platform-skips.json").read_text())
    expected = receipt["platforms"][platform]["skips"]
    modules = ("tests/security/test_secret_mounts_posix.py::",
               "tests/security/test_secret_resolver.py::",
               "tests/security/test_wincred_resolver.py::")
    actual = {node: reason for node, reason in expected_skips(platform).items()
              if node.startswith(modules)}
    assert actual == expected and len(actual) == count
    other = "linux" if platform == "win32" else "win32"
    for node, reason in actual.items():
        for host, candidate, explanation, phase, accepted in (
            (platform, node, reason, "setup", True),
            (other, node, reason, "setup", False),
            (platform, node + "[new]", reason, "setup", False),
            (platform, node, reason + " changed", "setup", False),
            (platform, node, reason, "teardown", False),
        ):
            policy = RegressionPolicy(ROOT, host)
            policy.pytest_runtest_logreport(SimpleNamespace(
                nodeid=candidate, when=phase, outcome="skipped", skipped=True,
                longrepr=("file.py", 1, "Skipped: " + explanation),
            ))
            assert policy.skips[0]["allowed"] is accepted
            assert bool(policy.errors) is not accepted


@pytest.mark.parametrize("platform,count", [("linux", 1), ("win32", 5)])
def test_operator_skip_allowances_match_native_receipts(platform, count):
    receipt = json.loads((ROOT / "docs/operator-platform-skips.json").read_text())
    actual = {node: reason for node, reason in expected_skips(platform).items()
              if node.startswith(("tests/audit/test_anchor_review.py::", "tests/client/"))}
    assert actual == receipt["skips"][platform] and len(actual) == count
    other = "linux" if platform == "win32" else "win32"
    assert not set(actual).intersection(expected_skips(other))


def test_workflow_has_read_only_triggers_full_matrix_and_immutable_actions():
    workflow = yaml.safe_load((ROOT / ".github/workflows/regression.yml").read_text(encoding="utf-8"))
    # PyYAML's YAML 1.1 loader reads the unquoted Actions key 'on' as True.
    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers) == {"pull_request", "push"}
    assert triggers["push"]["branches"] == ["main"]
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["regression"]
    assert job["strategy"]["matrix"]["os"] == ["ubuntu-24.04", "windows-2022"]
    assert job["env"]["GATE_TEST_CMD"] == "python scripts/ci_pytest.py"
    steps = job["steps"]
    checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["fetch-depth"] == 0
    assert checkout["with"]["persist-credentials"] is False
    commands = [step["run"] for step in steps if "run" in step]
    assert "bash scripts/gate.sh" in commands and "npm run build" in commands and "npm test" in commands
    assert commands.index("git show --check --format= HEAD") < commands.index("npm run build")
    assert commands.index("npm run build") < commands.index("npm test") < commands.index("bash scripts/gate.sh")
    for step in steps:
        if "uses" in step:
            action, sha = step["uses"].split("@")
            assert action in {"actions/checkout", "actions/setup-python", "actions/setup-node", "actions/upload-artifact"}
            assert len(sha) == 40 and all(char in "0123456789abcdef" for char in sha)


@pytest.mark.parametrize("platform,count", [("linux", 1), ("win32", 3)])
def test_scap_import_skips_match_review_receipts(platform, count):
    receipt = json.loads((ROOT / "docs/scap-import-platform-skips.json").read_text())
    actual = {node: reason for node, reason in expected_skips(platform).items()
              if node.startswith("tests/ingest/test_scap_review.py::")}
    assert actual == receipt["skips"][platform] and len(actual) == count
    common = set(expected_skips("linux")) & set(actual)
    if platform == "win32":
        assert common == {"tests/ingest/test_scap_review.py::test_database_writer_wait_rechecks_authority[json]"}


@pytest.mark.parametrize("platform,count", [("linux", 14), ("win32", 13)])
def test_ssh_key_skip_policy_matches_opposite_platform_evidence(platform, count):
    rows = json.loads((ROOT / "docs/ssh-key-platform-skips.json").read_text())
    source_platform = "windows" if platform == "win32" else platform
    selected = [row for row in rows if row["skip_on"] == source_platform]
    expected = {row["nodeid"]: row["reason"] for row in selected}
    actual = {node: reason for node, reason in expected_skips(platform).items()
              if node.startswith("tests/security/test_ssh_key_credentials.py::")}
    assert actual == expected and len(selected) == len(actual) == count
    opposite = "linux" if platform == "win32" else "win32"
    for row in selected:
        assert row["passes_on"] == ("linux" if opposite == "linux" else "windows")
        assert len(row["evidence_sha256"]) == 64
        assert row["nodeid"] not in expected_skips(opposite)
    for node, reason in actual.items():
        for host, candidate, explanation, phase, accepted in (
            (platform, node, reason, "setup", True),
            (opposite, node, reason, "setup", False),
            (platform, node + "[new]", reason, "setup", False),
            (platform, node, reason + " changed", "setup", False),
            (platform, node, reason, "teardown", False),
        ):
            policy = RegressionPolicy(ROOT, host)
            policy.pytest_runtest_logreport(SimpleNamespace(
                nodeid=candidate, when=phase, outcome="skipped", skipped=True,
                longrepr=("file.py", 1, "Skipped: " + explanation),
            ))
            assert policy.skips[0]["allowed"] is accepted
            assert bool(policy.errors) is not accepted


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_scan_writer_skip_does_not_allow_sqlite_or_changed_cases(platform):
    node = "tests/scan_workers/test_review.py::test_sqlite_writer_admission_rechecks_authority[json]"
    reason = "SQLite writer admission is specific to the SQLite backend"
    assert expected_skips(platform)[node] == reason
    for candidate, explanation, phase, accepted in (
        (node, reason, "call", True),
        (node.replace("[json]", "[sqlite]"), reason, "call", False),
        (node + "[new]", reason, "call", False),
        (node, reason + " changed", "call", False),
        (node, reason, "teardown", False),
    ):
        policy = RegressionPolicy(ROOT, platform)
        policy.pytest_runtest_logreport(SimpleNamespace(
            nodeid=candidate, when=phase, outcome="skipped", skipped=True,
            longrepr=("file.py", 1, "Skipped: " + explanation),
        ))
        assert policy.skips[0]["allowed"] is accepted
        assert bool(policy.errors) is not accepted
