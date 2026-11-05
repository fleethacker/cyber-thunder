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
    assert len(linux) == 30 and len(windows) == 5
    assert sum(reason == UDS_REASON for reason in linux.values()) == len(UDS_TESTS) == 19
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
