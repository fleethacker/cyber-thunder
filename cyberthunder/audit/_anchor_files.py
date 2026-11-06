"""Bounded, protected local I/O for checkpoint artifacts and receiver state."""
from contextlib import contextmanager
import os
from pathlib import Path
import tempfile

from cyberthunder.audit.chain import file_lock
from cyberthunder.security.kube_credentials import (
    _native_path, _open_protected, _owner, _parents, _protection, _read, _stamp,
)


def native_path(value):
    return _native_path(value)


def read(path, maximum, *, private=False):
    # Reuse the credential reader's POSIX owner/mode, stable descriptor and native Windows checks.
    return _read(native_path(path), "audit anchor", private, maximum, _owner(None))[0]


@contextmanager
def parent(path):
    path = native_path(path)
    before = _parents(path, _owner(None))
    failure = None
    if os.name == "nt":
        from cyberthunder.security.file_trust import protected_parent
        with protected_parent(path, creating=True):
            # Finish native parent revalidation before propagating application
            # errors; the native wrapper intentionally sanitizes OSError itself.
            try:
                yield path
            except BaseException as exc:
                failure = exc
    else:
        try:
            yield path
        except BaseException as exc:
            failure = exc
    if before != _parents(path, _owner(None)):
        raise ValueError("anchor directory changed")
    if failure is not None:
        raise failure


@contextmanager
def stream(path, maximum):
    """Stable bounded file descriptor; caller must also enforce its streaming byte limit."""
    path, owner = native_path(path), _owner(None)
    parents = _parents(path, owner)
    before = path.lstat()
    _protection(before, private=False, owner=owner)
    if not 0 <= before.st_size <= maximum:
        raise ValueError("anchor input size")
    with _open_protected(path, False) as source:
        opened = os.fstat(source.fileno())
        _protection(opened, private=False, owner=owner)
        if _stamp(before) != _stamp(opened):
            raise ValueError("anchor input changed")
        yield source
        after = os.fstat(source.fileno())
        current = path.lstat()
        if (_stamp(opened) != _stamp(after) or opened.st_ctime_ns != after.st_ctime_ns
                or _stamp(before) != _stamp(current) or before.st_ctime_ns != current.st_ctime_ns
                or parents != _parents(path, owner)):
            raise ValueError("anchor input changed")


def _check_created(fd, path):
    _protection(os.fstat(fd), private=False, owner=_owner(None))
    if os.name == "nt":
        from cyberthunder.security.file_trust import check_open_file
        check_open_file(fd, path)


@contextmanager
def locked(path):
    """Use the existing audit writer's OS lock, without acquiring any other lock inside it."""
    with parent(path) as path:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            pass
        else:
            try:
                _check_created(fd, path)
            finally:
                os.close(fd)
        # A protected read handle cannot coexist with another process's writable
        # Windows lock handle. Validate the actual descriptor after acquiring it.
        before = path.lstat()
        _protection(before, private=False, owner=_owner(None))
        if before.st_size > 1024:
            raise ValueError("anchor lock size")
        with file_lock(path) as handle:
            opened = os.fstat(handle.fileno())
            _check_created(handle.fileno(), path)
            if _stamp(before) != _stamp(opened):
                raise ValueError("anchor lock changed")
            yield
            _check_created(handle.fileno(), path)
            if _stamp(opened) != _stamp(path.lstat()):
                raise ValueError("anchor lock changed")


def _sync_parent(path):
    if os.name != "nt":
        fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def write(path, raw, *, expected=None):
    """Atomic publication. New artifacts never overwrite; state replacement requires exact prior bytes.

    Only the import operation may replace state, while holding that state's writer lock.
    No private key material is ever written here.
    """
    with parent(path) as path:
        if expected is not None and read(path, len(expected) + 1) != expected:
            raise ValueError("anchor state changed")
        fd, name = tempfile.mkstemp(prefix=".audit-anchor-", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as target:
                _check_created(target.fileno(), temporary)
                target.write(raw)
                target.flush()
                os.fsync(target.fileno())
            if read(temporary, len(raw)) != raw:
                raise ValueError("anchor output changed")
            if expected is None:
                # Atomic no-clobber publication on supported local filesystems. Readers
                # conservatively refuse the brief two-link interval before cleanup.
                os.link(temporary, path)
                temporary.unlink()
            else:
                if read(path, len(expected) + 1) != expected:
                    raise ValueError("anchor state changed")
                os.replace(temporary, path)
            _sync_parent(path)
            if read(path, len(raw)) != raw:
                raise ValueError("anchor output changed")
        finally:
            temporary.unlink(missing_ok=True)
