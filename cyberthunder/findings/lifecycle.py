"""Nonblocking, non-reentrant finding lifecycle locks shared by every process."""
from __future__ import annotations

from contextlib import contextmanager
import errno
import hashlib
import os
from pathlib import Path
import threading


class ReviewConflict(RuntimeError):
    """Reload or retry after the competing finding operation has completed."""


class LifecycleReentry(ReviewConflict):
    """Waiting cannot help when this same thread already owns the lock."""


_owned = threading.local()


def finding_key(finding_id: str) -> str:
    return hashlib.sha256(finding_id.encode("utf-8")).hexdigest()


def _try_lock(handle, *, windows: bool) -> None:
    if windows:
        import msvcrt
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock(handle, *, windows: bool) -> None:
    if windows:
        import msvcrt
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def _lock_path(path: Path):
    key = os.path.normcase(os.path.abspath(path))
    if getattr(_owned, "pid", None) != os.getpid():
        _owned.pid, _owned.paths = os.getpid(), set()
    if key in _owned.paths:
        raise LifecycleReentry("finding lifecycle is busy in this operation; publish after releasing its guard")
    path.parent.mkdir(parents=True, exist_ok=True)
    acquired = False
    windows = os.name == "nt"
    with path.open("a+b") as handle:
        try:
            try:
                _try_lock(handle, windows=windows)
                acquired = True
                _owned.paths.add(key)
            except OSError as exc:
                if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK} or getattr(exc, "winerror", None) == 33:
                    raise ReviewConflict("finding lifecycle is busy with a review, scan publication or remediation; retry") from exc
                raise
            yield
        finally:
            # Unlocking a failed acquisition can mask contention or release an unrelated lock.
            if acquired:
                try:
                    _unlock(handle, windows=windows)
                finally:
                    _owned.paths.remove(key)


def finding_lifecycle_lock(root: Path, finding_id: str):
    return _lock_path(root / "finding_reviews" / "locks" / f"{finding_key(finding_id)}.lock")


def review_coordination_lock(root: Path):
    return _lock_path(root / "finding_reviews.lock")
