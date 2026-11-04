"""Snapshot helpers: where the engine keeps before-state, step results and file copies for one proposal.

Layout under store.snapshot_dir(<proposal_id>):
  before_state.json        BeforeState as captured by the adapter
  fix.json                 the FixEntry exactly as it was proposed (what the approver saw)
  apply.json / verify.json / rollback.json   step results
  files/<remote path>      copies of files captured before the change
  after/<remote path>      copies of the same files read back after the change (for the diff view)

Remote paths are mapped to local relative paths the same way on Windows and Linux: backslashes become
slashes, a drive letter is dropped, and the leading slash is stripped.
"""
from __future__ import annotations

import difflib
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from cyberthunder.remediation.models import BeforeState

BEFORE_STATE = "before_state.json"
FILES_DIR = "files"
AFTER_DIR = "after"
EXCERPT_CHARS = 4000


def _write(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    tmp.replace(path)
    return path


def _read(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def rel_path(remote_path: str) -> str:
    p = remote_path.replace("\\", "/")
    if len(p) > 1 and p[1] == ":":
        p = p[2:]
    p = p.lstrip("/")
    # never let a captured path climb out of the snapshot directory
    parts = [x for x in p.split("/") if x not in ("", ".", "..")]
    return "/".join(parts)


def file_copy(snap_dir: str | Path, remote_path: str, *, after: bool = False) -> Path:
    """Local path that holds the before (or after) copy of a remote file."""
    return Path(snap_dir) / (AFTER_DIR if after else FILES_DIR) / rel_path(remote_path)


def save_before_state(snap_dir: str | Path, before: BeforeState) -> Path:
    return _write(Path(snap_dir) / BEFORE_STATE, before.to_dict())


def load_before_state(snap_dir: str | Path) -> BeforeState | None:
    d = _read(Path(snap_dir) / BEFORE_STATE)
    return BeforeState.from_dict(d) if d else None


def save_result(snap_dir: str | Path, name: str, obj: Any) -> Path:
    """Save a step result (apply, verify, rollback, fix) as <name>.json. Accepts dataclasses and dicts."""
    if hasattr(obj, "to_dict"):
        data = obj.to_dict()
    elif is_dataclass(obj):
        data = asdict(obj)
    else:
        data = obj
    return _write(Path(snap_dir) / f"{name}.json", data)


def load_result(snap_dir: str | Path, name: str) -> Any:
    return _read(Path(snap_dir) / f"{name}.json")


def read_text(path: Path, limit: int = EXCERPT_CHARS) -> str | None:
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")[:limit]


def text_diff(before: str | None, after: str | None, name: str = "file") -> str:
    """Unified diff of two texts; empty string when they are identical or both missing."""
    a = (before or "").splitlines(keepends=True)
    b = (after or "").splitlines(keepends=True)
    return "".join(difflib.unified_diff(a, b, fromfile=f"{name} (before)", tofile=f"{name} (after)"))
