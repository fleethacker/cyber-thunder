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


@pytest.fixture
def state_dir(tmp_path, monkeypatch) -> Path:
    """Isolated state directory; also clears the kill-switch env override."""
    monkeypatch.delenv("CT_KILL", raising=False)
    d = tmp_path / "state"
    d.mkdir()
    return d
