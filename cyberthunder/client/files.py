"""Bounded protected local files; native Windows trust is shared with the server."""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
import os
from pathlib import Path
import stat
import sys

from .errors import ClientError


def path(value):
    result = Path(value)
    if (not result.is_absolute() or ".." in result.parts or len(result.parts) > 128
            or len(str(result)) > 4096 or result == Path(result.anchor)):
        raise ClientError("protected_path_required")
    return result


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def check(fd, *, directory=False, private=False):
    info = os.fstat(fd)
    if (not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or (not directory and info.st_nlink != 1)
            or info.st_uid not in ({os.geteuid()} if private else {0, os.geteuid()})):
        raise ClientError("file_protection_unproved")
    if private:
        if info.st_mode & 0o077:
            raise ClientError("file_protection_unproved")
    elif info.st_mode & 0o022 and not (directory and info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
        raise ClientError("file_protection_unproved")
    if any("acl" in key.lower() for key in os.listxattr(fd)):
        raise ClientError("file_protection_unproved")
    return info


@contextmanager
def parents(value):
    """Pin ancestors without resolving links. Caller owns the leaf operation."""
    value = path(value)
    try:
        if os.name == "nt":
            from cyberthunder.security.file_trust import protected_parent
            with protected_parent(value, creating=True):
                yield None
        elif sys.platform.startswith("linux"):
            with ExitStack() as stack:
                fd = None
                seen = []
                for parent in reversed(value.parents):
                    name = parent if fd is None else parent.name
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    opened = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                    stack.callback(os.close, opened)
                    actual = check(opened, directory=True)
                    if stamp(info) != stamp(actual):
                        raise ClientError("file_protection_unproved")
                    seen.append((fd, name, opened, actual))
                    fd = opened
                yield fd
                for parent_fd, name, opened, before in seen:
                    actual = check(opened, directory=True)
                    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    # Child creation is intentional; parent identity/rights must remain stable.
                    if stamp(before)[:5] != stamp(actual)[:5] or stamp(actual)[:5] != stamp(named)[:5]:
                        raise ClientError("file_protection_unproved")
        else:
            raise ClientError("platform_not_supported")
    except ClientError:
        raise
    except (OSError, ValueError, TypeError, AttributeError):
        raise ClientError("file_protection_unproved") from None


def read(value, *, private=False, maximum=65536, missing=False):
    value = path(value)
    try:
        if os.name == "nt":
            from cyberthunder.security.file_trust import open_protected
            with open_protected(value, private=private) as stream:
                size = os.fstat(stream.fileno()).st_size
                raw = stream.read(maximum + 1)
                if len(raw) != size:
                    raise ClientError("file_protection_unproved")
        else:
            with parents(value) as parent_fd:
                try:
                    fd = os.open(value.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
                except FileNotFoundError:
                    if missing:
                        return None
                    raise
                try:
                    before = check(fd, private=private)
                    if before.st_size > maximum:
                        raise ClientError("file_protection_unproved")
                    raw = os.read(fd, maximum + 1)
                    if len(raw) != before.st_size:
                        raise ClientError("file_protection_unproved")
                    after = check(fd, private=private)
                    named = os.stat(value.name, dir_fd=parent_fd, follow_symlinks=False)
                    if stamp(before) != stamp(after) or stamp(after) != stamp(named):
                        raise ClientError("file_protection_unproved")
                finally:
                    os.close(fd)
        if len(raw) > maximum:
            raise ClientError("file_protection_unproved")
        return raw
    except FileNotFoundError:
        if missing:
            return None
        raise ClientError("protected_file_unavailable") from None
    except ClientError:
        raise
    except (OSError, ValueError, TypeError, AttributeError):
        raise ClientError("file_protection_unproved") from None
