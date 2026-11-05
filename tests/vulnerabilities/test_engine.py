from __future__ import annotations

import json
import subprocess
import sys
import time

import pytest

from cyberthunder.vulnerabilities import engine
from cyberthunder.vulnerabilities.errors import UpdateStopped, VulnerabilityConflict, VulnerabilityUnavailable


@pytest.mark.parametrize("version,supported", [("0.71.0", False), ("0.71.1", True), ("0.75.0", True),
    ("1.0.0", True), ("0.71.1-rc.1", False), ("0.71.1-dev", False), ("0.71.1+build.1", True),
    ("not-a-version SECRET=token", False)])
def test_minimum_patched_version(monkeypatch, tmp_path, version, supported):
    monkeypatch.setattr(engine, "executable", lambda _: sys.executable)
    monkeypatch.setattr(engine, "run", lambda *a, **k: f"Version: {version}\n".encode())
    result = engine.probe("fixture", tmp_path)
    assert result["supported"] == supported
    assert "SECRET" not in json.dumps(result)


def test_environment_is_allowlisted_and_isolated(monkeypatch, tmp_path):
    for name in ("TRIVY_DB_REPOSITORY", "trivy_java_db_repository", "TRIVY_CONFIG", "TRIVY_INSECURE",
                 "TRIVY_TOKEN", "TRIVY_RUN_AS_PLUGIN", "TRIVY_SERVER", "TRIVY_CACHE_DIR",
                 "TRIVY_DB_REPOSITORIES", "TRIVY_SKIP_DB_UPDATE", "TRIVY_TIMEOUT",
                 "TRIVY_SKIP_JAVA_DB_UPDATE", "DOCKER_AUTH_CONFIG", "LD_PRELOAD", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(name, "secret-value")
    env = engine.environment(tmp_path)
    assert all("TRIVY" not in k.upper() for k in env)
    assert "secret-value" not in env.values()
    assert env["HOME"] == env["DOCKER_CONFIG"] == env["TMPDIR"] == str(tmp_path)
    assert "PATH" in {k.upper() for k in env}


def test_real_subprocess_runner_uses_argv_and_controlled_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("TRIVY_DB_REPOSITORY", "attacker.invalid/secret")
    code = "import os,json; print(json.dumps({'override':os.getenv('TRIVY_DB_REPOSITORY'),'home':os.environ['HOME']}))"
    result = engine.run([sys.executable, "-c", code], home=tmp_path, timeout=5, guard=lambda: None, capture=True)
    assert json.loads(result) == {"override": None, "home": str(tmp_path)}


def test_real_runner_timeout_terminates_child(tmp_path):
    started = time.monotonic()
    with pytest.raises(UpdateStopped, match="timed out"):
        engine.run([sys.executable, "-c", "import time; time.sleep(60)"], home=tmp_path,
                   timeout=0.2, guard=lambda: None)
    assert time.monotonic() - started < 5


def test_real_runner_guard_terminates_child(tmp_path):
    calls = 0
    def guard():
        nonlocal calls
        calls += 1
        if calls > 2:
            raise UpdateStopped("link disconnected")
    started = time.monotonic()
    with pytest.raises(UpdateStopped, match="disconnected"):
        engine.run([sys.executable, "-c", "import time; time.sleep(60)"], home=tmp_path, timeout=5, guard=guard)
    assert time.monotonic() - started < 5


def test_real_runner_bounds_version_output_and_sanitizes_errors(tmp_path):
    with pytest.raises(VulnerabilityUnavailable, match="output"):
        engine.run([sys.executable, "-c", "print('X' * 1000000)"], home=tmp_path, timeout=5,
                   guard=lambda: None, capture=True)
    with pytest.raises(VulnerabilityUnavailable) as error:
        engine.run([sys.executable, "-c", "import sys; print('SECRET=token');sys.exit(1)"],
                   home=tmp_path, timeout=5, guard=lambda: None)
    assert "SECRET" not in str(error.value)


def test_operation_lock_is_shared_with_another_process(svc):
    code = ("import sys,time; from pathlib import Path; "
            "from cyberthunder.vulnerabilities.storage import Lease; "
            "lease=Lease(Path(sys.argv[1])); print('ready',flush=True); time.sleep(15)")
    process = subprocess.Popen([sys.executable, "-c", code, str(svc.root / "operation.lock")],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert process.stdout.readline().strip() == "ready"
        with pytest.raises(VulnerabilityConflict):
            svc.update(actor="joshua", background=False)
    finally:
        process.terminate()
        process.communicate(timeout=5)


def test_batch_and_shell_wrappers_are_refused(monkeypatch):
    monkeypatch.setattr(engine.shutil, "which", lambda _: "C:/unsafe/wrapper.cmd")
    with pytest.raises(VulnerabilityUnavailable):
        engine.executable("wrapper")


def test_exited_parent_with_inherited_output_does_not_block_runner(tmp_path):
    code = ("import subprocess,sys; "
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(4)']); "
            "print('Version: 0.71.1', flush=True)")
    started = time.monotonic()
    with pytest.raises(VulnerabilityUnavailable, match="output"):
        engine.run([sys.executable, "-c", code], home=tmp_path, timeout=2,
                   guard=lambda: None, capture=True)
    assert time.monotonic() - started < 3
