"""Atomic local cache I/O. The service must own its cache directory and ACLs."""

import hashlib
import os
from pathlib import Path
import stat
import tempfile

MAX_CACHE_BYTES = 524288
_UNCHECKED = object()


def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _check_parent(path: Path) -> None:
    # Do not resolve symlinks before checking: the configured path is the boundary.
    for parent in path.parents:
        info = parent.lstat()
        if _is_link(info) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("Unsafe cache directory")
    info = path.parent.stat()
    if os.name != "nt" and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
        raise ValueError("Unsafe cache directory")


def _check_file(info: os.stat_result) -> None:
    if _is_link(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("Unsafe cache file")
    if os.name != "nt" and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
        raise ValueError("Unsafe cache file")
    if info.st_size > MAX_CACHE_BYTES:
        raise ValueError("Oversized cache")


def read_cache(path: Path) -> bytes | None:
    if os.name == "nt":
        from .file_trust import open_protected
        try:
            with open_protected(path) as stream:
                _check_file(os.fstat(stream.fileno()))
                data = stream.read(MAX_CACHE_BYTES + 1)
                if len(data) > MAX_CACHE_BYTES:
                    raise ValueError("Oversized cache")
                return data
        except FileNotFoundError:
            return None
    _check_parent(path)
    try:
        original = path.lstat()
    except FileNotFoundError:
        return None
    _check_file(original)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        actual = os.fstat(stream.fileno())
        _check_file(actual)
        if (actual.st_dev, actual.st_ino) != (original.st_dev, original.st_ino):
            raise ValueError("Cache changed during open")
        data = stream.read(MAX_CACHE_BYTES + 1)
    if len(data) > MAX_CACHE_BYTES:
        raise ValueError("Oversized cache")
    return data


def digest(data: bytes | None) -> bytes | None:
    """Bind a live verifier to the exact cache bytes it loaded or published."""
    return hashlib.sha256(data).digest() if data is not None else None


def check_cache(path: Path, expected_digest: bytes | None) -> None:
    if digest(read_cache(path)) != expected_digest:
        raise ValueError("Cache invalidated")


def write_cache(path: Path, data: bytes, *, expected_digest=_UNCHECKED) -> None:
    if os.name == "nt":
        from .file_trust import protected_parent
        with protected_parent(path, creating=True):
            read_cache(path)  # Even an unconditional write must reject an unsafe existing file.
            _write_cache(path, data, expected_digest=expected_digest)
        return
    _write_cache(path, data, expected_digest=expected_digest)


def _write_cache(path: Path, data: bytes, *, expected_digest=_UNCHECKED) -> None:
    if len(data) > MAX_CACHE_BYTES:
        raise ValueError("Oversized cache")
    _check_parent(path)
    try:
        _check_file(path.lstat())
    except FileNotFoundError:
        pass
    if expected_digest is not _UNCHECKED:
        check_cache(path, expected_digest)
    fd, temporary = tempfile.mkstemp(prefix=".oidc-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            if os.name == "nt":
                from .file_trust import check_open_file
                check_open_file(stream.fileno(), temporary)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # Recheck before replacing; the protected parent prevents hostile races.
        _check_parent(path)
        try:
            _check_file(path.lstat())
        except FileNotFoundError:
            pass
        if expected_digest is not _UNCHECKED:
            check_cache(path, expected_digest)
        if os.name == "nt":
            # A newly created file inherits ACEs that need not apply to its parent.
            # Validate the actual completed temporary object before publication.
            if read_cache(Path(temporary)) != data:
                raise ValueError("Cache changed before publication")
            read_cache(path)
        os.replace(temporary, path)
        if os.name == "nt" and read_cache(path) != data:
            raise ValueError("Cache changed during publication")
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
