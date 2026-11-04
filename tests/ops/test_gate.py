"""Run scripts/gate.sh against throwaway git repositories: banned content turns it RED, a clean repo is GREEN."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "scripts" / "gate.sh"


def _bash():
    found = shutil.which("bash")
    # on Windows the first bash on PATH can be the WSL launcher, which cannot see these paths
    if found and "system32" not in found.lower():
        return found
    for cand in (os.path.join(os.environ.get("ProgramFiles", ""), "Git", "bin", "bash.exe"),
                 os.path.join(os.environ.get("ProgramFiles", ""), "Git", "usr", "bin", "bash.exe")):
        if os.path.exists(cand):
            return cand
    return None


BASH = _bash()
pytestmark = pytest.mark.skipif(not (BASH and shutil.which("git")), reason="bash and git are required")


def word(codes):  # the gate must never find these words in this repo, so build them at runtime
    return "".join(chr(c) for c in codes)


BANNED_A = word([67, 108, 97, 117, 100, 101])
BANNED_B = word([65, 110, 116, 104, 114, 111, 112, 105, 99])
HANDOFF = word([67, 76, 65, 85, 68, 69]) + ".md"
KEY_HEADER = "-----" + "BEGIN PRIVATE KEY-----\n"


def git(repo, *args):
    subprocess.run(["git", "-c", "user.name=Test Sailor", "-c", "user.email=sailor@example.invalid",
                    "-c", "commit.gpgsign=false", *args], cwd=repo, check=True, capture_output=True)


def make_repo(tmp_path, files, message="first commit"):
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    git(repo, "init", "-q")
    shutil.copy(GATE, repo / "scripts" / "gate.sh")
    (repo / "README.txt").write_text("a small project\n", encoding="utf-8", newline="\n")
    for name, text in files.items():
        (repo / name).write_text(text, encoding="utf-8", newline="\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return repo


def run_gate(repo, test_cmd="true"):
    env = dict(os.environ, GATE_TEST_CMD=test_cmd)
    r = subprocess.run([BASH, "scripts/gate.sh"], cwd=repo, env=env, capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout


def test_clean_repo_is_green(tmp_path):
    rc, out = run_gate(make_repo(tmp_path, {}))
    assert rc == 0, out
    assert "GATE GREEN" in out and "FAIL" not in out


@pytest.mark.parametrize("name,text,failing", [
    ("notes.txt", f"written with {BANNED_A}\n", "forbidden references"),
    ("notes.txt", f"vendor: {BANNED_B.lower()}\n", "forbidden references"),
    ("key.txt", KEY_HEADER, "secret scan"),
    ("cfg.py", "pass" + "word = 'hunter2hunter2'\n", "secret scan"),  # split so this file passes its own scan
    (HANDOFF.lower(), "handoff\n", "handoff file untracked"),
    ("ws.txt", "trailing space \n", "git diff --check"),
])
def test_bad_content_is_red(tmp_path, name, text, failing):
    rc, out = run_gate(make_repo(tmp_path, {name: text}))
    assert rc != 0 and "GATE RED" in out, out
    assert f"FAIL  {failing}" in out, out


def test_automated_trailer_in_commit_message_is_red(tmp_path):
    rc, out = run_gate(make_repo(tmp_path, {}, message="add thing\n\nCo-Authored-By: Someone <a@b.invalid>"))
    assert rc != 0 and "FAIL  forbidden references" in out


def test_failing_tests_are_red(tmp_path):
    rc, out = run_gate(make_repo(tmp_path, {}), test_cmd="false")
    assert rc != 0 and "FAIL  tests" in out
