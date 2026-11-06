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


def pytest_configure(config):
    if os.name == "nt":
        from tests.windows_acl import create_root, register_root, track_databases
        if config.option.basetemp is not None:
            # Explicit --basetemp retains its normal pytest behavior. Its ancestors
            # must already be protected; test ACL mutations stay inside that root.
            register_root(config.option.basetemp)
            return
        root = create_root()
        config._ct_windows_temporary = (root, tempfile.tempdir, track_databases(root))
        config.option.basetemp = str(root / "pytest")
        general = root / "temporary"
        general.mkdir()
        tempfile.tempdir = str(general)


def pytest_unconfigure(config):
    temporary = getattr(config, "_ct_windows_temporary", None)
    if temporary is not None:
        from tests.windows_acl import remove_root
        root, previous, close_databases = temporary
        tempfile.tempdir = previous
        close_databases()
        remove_root(root)


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture(autouse=True)
def _explanation_worker_lifecycle(monkeypatch, request):
    """Attribute leaked explanation workers to their owning test and stop them before the next test."""
    from cyberthunder.explain.worker import ExplainWorker

    created = []
    original = ExplainWorker.__init__

    def track(worker, *args, **kwargs):
        original(worker, *args, **kwargs)
        created.append(worker)

    monkeypatch.setattr(ExplainWorker, "__init__", track)
    yield
    leaked = [worker for worker in created if worker.alive]
    for worker in leaked:
        worker.stop(timeout=5)
    assert not leaked, f"{request.node.nodeid} left {len(leaked)} explanation worker(s) running; shut them down explicitly"


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
