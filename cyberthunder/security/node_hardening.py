"""Read-only, bounded permission observations; never a node compliance attestation.

No state/context/database is initialized and no file contents are read. Windows
uses the same native trust implementation as the protected runtime loaders.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
import os
from pathlib import Path
import stat
import sys
import time


@dataclass(frozen=True)
class Limits:
    entries: int = 2048
    depth: int = 24
    seconds: float = 10.0

    def __post_init__(self):
        if (type(self.entries) is not int or not 1 <= self.entries <= 8192
                or type(self.depth) is not int or not 1 <= self.depth <= 48
                or type(self.seconds) not in {int, float} or not 0 < self.seconds <= 30):
            raise ValueError("invalid assessment bounds")


class _Problem(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _posix_metadata(fd, *, directory, private):
    info = os.fstat(fd)
    if (not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or (not directory and info.st_nlink != 1)):
        raise _Problem("unsafe", "special_or_hardlinked_file")
    if info.st_uid not in {0, os.geteuid()}:
        raise _Problem("unsafe", "foreign_owner")
    if private:
        if info.st_mode & 0o077:
            raise _Problem("unsafe", "group_or_other_permissions")
    elif info.st_mode & 0o022:
        if not (directory and info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
            raise _Problem("unsafe", "writable_ancestor")
    # Do not guess ACL semantics, inherited masks or a different platform's ACLs.
    if not hasattr(os, "listxattr"):
        raise _Problem("unknown", "extended_permissions_unavailable")
    if any("acl" in name.lower() for name in os.listxattr(fd)):
        raise _Problem("unknown", "extended_acl_requires_review")
    return info


@contextmanager
def _posix_node(path, *, directory, private=True, parent_fd=None):
    name = path if parent_fd is None else path.name
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if stat.S_ISLNK(before.st_mode):
        raise _Problem("unsafe", "redirected_path")
    if (not (stat.S_ISDIR(before.st_mode) if directory else stat.S_ISREG(before.st_mode))
            or (not directory and before.st_nlink != 1)):
        raise _Problem("unsafe", "special_or_hardlinked_file")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if directory:
        flags |= os.O_DIRECTORY
    fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        opened = _posix_metadata(fd, directory=directory, private=private)
        if _stamp(before) != _stamp(opened):
            raise _Problem("unknown", "changed_during_assessment")
        yield fd
        after = _posix_metadata(fd, directory=directory, private=private)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if _stamp(opened) != _stamp(after) or _stamp(after) != _stamp(named):
            raise _Problem("unknown", "changed_during_assessment")
    finally:
        os.close(fd)


@contextmanager
def _posix_root(path):
    with ExitStack() as stack:
        fd = None
        for component in (*reversed(path.parents), path):
            fd = stack.enter_context(_posix_node(component, directory=True,
                                                private=component == path, parent_fd=fd))
        yield fd


def _windows_directory_acl(snapshot, trusted):
    # The shared native validator has already proved owner, descriptor structure,
    # parent integrity and effective mutation rights. Add whole-state directory
    # privacy and future-child inheritance checks, using its expanded ACE masks.
    from . import file_trust as ft
    _, (_, _, entries) = snapshot
    for kind, flags, mask, trustee in entries:
        if kind != 0 or trustee in trusted | {ft._OWNER_RIGHTS}:
            continue
        if flags & 3 and mask & ~0x1F01FF:
            raise _Problem("unknown", "unrecognized_inherited_rights")
        if not flags & 8 and mask & (0x1 | 0x4):  # list directory / add subdirectory
            raise _Problem("unsafe", "foreign_directory_access")
        if flags & 3 and mask & (ft._FILE_WRITE | ft._DIRECTORY_WRITE | 0x25):
            raise _Problem("unsafe", "foreign_inherited_access")


@contextmanager
def _windows_node(path, *, directory, **_):
    from . import file_trust as ft
    if not directory:
        with ft.open_protected(path, private=True):
            yield None  # Metadata only: never call read on the checked stream.
        return
    # A synthetic child name checks and pins the directory without creating it.
    with ft.protected_parent(path / ".assessment-placeholder", creating=True) as (native, trusted):
        handle = native.open(path, directory=True)
        try:
            before = native.inspect(handle, path, trusted, directory=True, creating=True)
            _windows_directory_acl(before, trusted)
            stamp = _stamp(path.lstat())
            yield None
            after = native.inspect(handle, path, trusted, directory=True, creating=True)
            _windows_directory_acl(after, trusted)
            if before != after or stamp != _stamp(path.lstat()):
                raise _Problem("unknown", "changed_during_assessment")
        finally:
            native.CloseHandle(handle)


def _category(relative):
    names = {"audit.jsonl": "audit", "audit.jsonl.head": "audit",
             "state.db": "sqlite_database", "state.db-wal": "sqlite_wal",
             "state.db-shm": "sqlite_shared_memory", "state.db-journal": "sqlite_journal",
             "auth": "keys_and_auth", "keys": "keys_and_auth", "snapshots": "rollback_snapshots",
             "scans": "scan_evidence", "outbox": "export", "synced": "export", "reports": "export"}
    return "state_root" if not relative else names.get(relative[0], "other_state")


def assess(state_root: str | Path, *, limits: Limits | None = None) -> dict:
    """Observe existing state metadata under the executing OS identity.

    'protected' covers only observed owner/permission metadata, not encryption,
    service confinement, application contents, future writes, restore or compliance.
    Arbitrary paths, filenames, SIDs and exception messages never enter the report.
    """
    limits = limits or Limits()
    started = time.monotonic()
    rows = []
    complete = True
    root_device = None

    def observation(relative, kind):
        row = {"entry": len(rows), "category": _category(relative), "kind": kind,
               "status": "unknown", "code": "not_assessed"}
        rows.append(row)
        return row

    def failure(row, error):
        nonlocal complete
        complete = False
        row.update(status="unknown", code="permissions_unproved")
        if isinstance(error, _Problem):
            row.update(status=error.status, code=error.code)
        elif isinstance(error, FileNotFoundError):
            row["code"] = "missing_or_removed"

    def visit(path, relative, *, directory, parent_fd=None, root=False):
        nonlocal complete, root_device
        row = observation(relative, "directory" if directory else "file")
        try:
            if time.monotonic() - started >= limits.seconds:
                raise _Problem("unknown", "time_limit")
            if len(relative) > limits.depth:
                raise _Problem("unknown", "depth_limit")
            if os.name == "nt":
                context = _windows_node(path, directory=directory)
            elif sys.platform.startswith("linux") and hasattr(os, "O_NOFOLLOW"):
                context = _posix_root(path) if root else _posix_node(path, directory=directory, parent_fd=parent_fd)
            else:
                raise _Problem("unknown", "platform_not_supported")
            with context as fd:
                info = path.lstat() if os.name == "nt" else os.fstat(fd)
                if root:
                    root_device = info.st_dev
                elif info.st_dev != root_device:
                    raise _Problem("unknown", "different_filesystem")
                if directory:
                    # scandir streams entries; never materialize an unbounded directory.
                    with os.scandir(path if os.name == "nt" else fd) as entries:
                        for entry in entries:
                            if len(rows) >= limits.entries or time.monotonic() - started >= limits.seconds:
                                raise _Problem("unknown", "entry_or_time_limit")
                            child = path / entry.name
                            entry_info = entry.stat(follow_symlinks=False)
                            if (stat.S_ISLNK(entry_info.st_mode)
                                    or getattr(entry_info, "st_file_attributes", 0) & 0x400):
                                bad = observation((*relative, entry.name), "redirect")
                                failure(bad, _Problem("unsafe", "redirected_path"))
                            else:
                                visit(child, (*relative, entry.name), directory=stat.S_ISDIR(entry_info.st_mode), parent_fd=fd)
            # Native calls cannot be interrupted. Once final handle validation
            # returns, an elapsed budget must still make the observation incomplete.
            if time.monotonic() - started >= limits.seconds:
                raise _Problem("unknown", "time_limit")
            row.update(status="protected", code="observed_permissions_protected")
        except (_Problem, OSError, ValueError, TypeError, AttributeError) as error:
            failure(row, error)

    try:
        raw = os.fspath(state_root)
        path = Path(raw)
        if (not path.is_absolute() or ".." in path.parts or len(path.parts) > 128
                or len(raw) > 4096 or path == Path(path.anchor)):
            raise _Problem("unknown", "absolute_bounded_state_path_required")
        visit(path, (), directory=True, root=True)
    except (_Problem, OSError, ValueError, TypeError) as error:
        failure(observation((), "directory"), error)
    statuses = {row["status"] for row in rows}
    result = "unsafe" if "unsafe" in statuses else "unknown" if "unknown" in statuses or not complete else "protected"
    return {"version": 1, "read_only": True,
            "state_tree": {"status": result, "complete": complete, "entries_observed": len(rows),
                           "scope": "current_owner_and_permission_metadata", "observations": rows},
            "runtime_file_guards": {"scope": "selected_policy_kubernetes_credentials_and_oidc_cache",
                                    "whole_state_enforced": False},
            "limits": {"entries": limits.entries, "depth": limits.depth, "seconds": limits.seconds},
            "pending": ["external_credentials_and_backups", "future_file_creation_and_umask",
                        "local_volume_and_encryption_acceptance", "service_account_and_container_confinement",
                        "consistent_backup_restore_drill", "node_stig_review", "isso_review_and_authorization"],
            "notes": ["No file contents read; no application, database, ACL or service changes.",
                      "Directory enumeration may update filesystem access timestamps.",
                      "Run under the service OS identity; privileged accounts remain trusted.",
                      "A bounded observation is not an atomic snapshot or continuing enforcement.",
                      "A blocked native metadata call cannot be interrupted by the between-entry time bound."]}
