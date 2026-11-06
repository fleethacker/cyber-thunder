"""Nonblocking lifecycle locks with a fixed cross-process descriptor bound.

Every operation on an identity takes its SHA-256 stripe. A publication takes
each affected stripe once and retains all of them through the write. Collisions
only add exclusion; they never let the same identity use different locks.
Protocol v2 requires draining all v1 workers before switching a shared state
directory. Do not change the stripe count/mapping without a protocol migration.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
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
LIFECYCLE_STRIPES = 256


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


def _check_reentry(path: Path) -> str:
    key = os.path.normcase(os.path.abspath(path))
    if getattr(_owned, "pid", None) != os.getpid():
        _owned.pid, _owned.paths = os.getpid(), set()
    if key in _owned.paths:
        raise LifecycleReentry("finding lifecycle is busy in this operation; publish after releasing its guard")
    return key


@contextmanager
def _lock_path(path: Path):
    key = _check_reentry(path)
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


def _stripe_path(root: Path, finding_id: str) -> Path:
    # Never use process-randomized hash() or configurable stripe counts.
    stripe = int(finding_key(finding_id), 16) % LIFECYCLE_STRIPES
    return root / "finding_reviews" / "lifecycle-v2" / f"stripe-{stripe:03d}.lock"


@contextmanager
def finding_lifecycle_locks(root: Path, finding_ids):
    """Hold at most 256 descriptors; unwind every acquisition on any conflict.

    Deduplicate before acquiring: different identities may share a stripe, but
    taking an already-owned stripe in a nested operation remains non-reentrant.
    Acquisitions never wait, including when a caller holds coordination first.
    """
    paths = {_stripe_path(root, finding_id) for finding_id in finding_ids}
    # A busy earlier stripe must not mask known same-thread reentry as retryable
    # contention. Check the entire bounded set before attempting any OS lock.
    for path in paths:
        _check_reentry(path)
    with ExitStack() as stack:
        for path in sorted(paths):
            stack.enter_context(_lock_path(path))
        yield


def finding_lifecycle_lock(root: Path, finding_id: str):
    return finding_lifecycle_locks(root, (finding_id,))


def review_coordination_lock(root: Path):
    return _lock_path(root / "finding_reviews.lock")
