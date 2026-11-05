"""The json backend: one file per document under the state directory, the layout the tool has always had.

A document at logical path "scans/<id>/run.json" is the file <state_dir>/scans/<id>/run.json, written as
indented UTF-8 JSON by temp file and rename, so a reader never sees half a document. Also used by StateStore
for every JSON path that is a file rather than a document, whichever backend holds the documents.
"""
from __future__ import annotations

import json
import os
import re
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from cyberthunder.state import Backend, is_document, match_pattern, normalize_prefix

_LOCK_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def replace_file(tmp: Path, dest: Path) -> None:
    """os.replace that survives the Windows moment in which another process has `dest` open for reading (the
    UI polling a run, a second API worker re-reading the proposals): retry briefly instead of losing the write.
    Shared by the json backend, the approval gate, the inventory and the audit head checkpoint."""
    for attempt in range(20):
        try:
            os.replace(tmp, dest)
            return
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(0.05)


def read_text_retry(p: Path) -> str:
    """Read UTF-8 text across a transient Windows replacement; persistent access errors still raise.
    Parsing and missing-file behavior belong to the caller, outside the retry."""
    for attempt in range(20):
        try:
            return p.read_text(encoding="utf-8")
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(0.05)


def write_json_file(p: Path, data: Any) -> None:
    """Indented JSON by temp file and rename, the way every document file has always been written."""
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    replace_file(tmp, p)


def read_json_file(p: Path, default: Any = None) -> Any:
    if not p.exists():
        return default
    return json.loads(read_text_retry(p))


@contextmanager
def file_lock(path: Path, timeout: float = 15.0) -> Iterator[None]:
    """Exclusive lock on a lock file next to the data; msvcrt on Windows, flock elsewhere. The same primitive
    the audit chain, the approval gate and the inventory use for their own files."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(path, "a+b")
    deadline = time.monotonic() + timeout
    try:
        if os.name == "nt":
            import msvcrt
            fh.seek(0)
            while True:
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise TimeoutError(f"state lock busy: {path}")
                    time.sleep(0.02)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()


class JsonFilesBackend(Backend):
    name = "json"

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _abs(self, path: str) -> Path:
        return self.root.joinpath(*[part for part in path.split("/") if part])

    def _logical(self, p: Path) -> str:
        return p.relative_to(self.root).as_posix()

    # -- documents ------------------------------------------------------------------------------------
    def get(self, path: str) -> Any | None:
        return read_json_file(self._abs(path), None)

    def put(self, path: str, doc: Any, *, mtime: float | None = None) -> None:
        p = self._abs(path)
        write_json_file(p, doc)
        if mtime is not None:
            os.utime(p, (mtime, mtime))

    def delete(self, path: str) -> bool:
        p = self._abs(path)
        try:
            p.unlink()
        except FileNotFoundError:
            return False
        p.with_suffix(p.suffix + ".tmp").unlink(missing_ok=True)
        return True

    def list(self, prefix: str = "", pattern: str | None = None) -> list[tuple[str, float]]:
        prefix = normalize_prefix(prefix)
        base = self._abs(prefix) if prefix else self.root
        if not base.is_dir():
            return []
        found = base.glob(pattern) if pattern else base.rglob("*.json")
        out: list[tuple[str, float]] = []
        for p in found:
            if not p.is_file() or p.name.endswith(".tmp"):
                continue
            rel = self._logical(p)
            if pattern is not None and not match_pattern(rel[len(prefix):], pattern):
                continue
            try:
                out.append((rel, p.stat().st_mtime))
            except OSError:
                continue
        return sorted(out)

    # -- locking, info --------------------------------------------------------------------------------
    def lock(self, name: str):
        safe = _LOCK_NAME.sub("_", name).strip("._") or "state"
        return file_lock(self.root / f"{safe}.lock")

    def location(self) -> str:
        return str(self.root)

    def size_bytes(self) -> int:
        total = 0
        for rel, _ in self.list():
            if is_document(rel):
                try:
                    total += self._abs(rel).stat().st_size
                except OSError:
                    continue
        return total
