"""Shared pytest fixtures. Each module keeps its own fixtures under tests/fixtures/<module>/."""
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURES = ROOT / "tests" / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


# Every test that takes a state directory runs once per document backend (json files, sqlite); the backend
# reaches AppContext, StateStore and CLI subprocesses through CT_STATE_BACKEND. CT_STATE_BACKENDS=json narrows
# a local run to one backend; the gate runs both.
STATE_BACKENDS = tuple(b.strip() for b in os.environ.get("CT_STATE_BACKENDS", "json,sqlite").split(",") if b.strip())


@pytest.fixture(params=STATE_BACKENDS)
def state_dir(tmp_path, monkeypatch, request) -> Path:
    """Isolated state directory on the parametrized backend; also clears the kill-switch env override."""
    monkeypatch.delenv("CT_KILL", raising=False)
    monkeypatch.setenv("CT_STATE_BACKEND", request.param)
    d = tmp_path / "state"
    d.mkdir()
    return d

# The UDS deployment guard tests (tests/test_deploy.py, test_dev.py, test_existing.py) drive bash scripts through
# fake tool shims with a Python shebang. Under Git Bash on Windows that shebang resolves to a path containing a
# space ("C:\Program Files\..."), which bash cannot execute, so those modules only run on Linux and macOS.
if sys.platform == "win32":
    collect_ignore = ["test_deploy.py", "test_dev.py", "test_existing.py"]
