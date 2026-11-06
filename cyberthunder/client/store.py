"""Per-OS-user opaque session storage. No application state or resolver dependency."""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import json
import math
import os
from pathlib import Path
import secrets
import time

from . import files
from .errors import ClientError, decode


def user_root():
    if os.name == "nt":
        from ctypes import wintypes
        import uuid
        shell = ctypes.WinDLL("shell32", use_last_error=True)
        ole = ctypes.WinDLL("ole32", use_last_error=True)
        guid = ctypes.create_string_buffer(uuid.UUID("F1B32785-6FBA-4FCF-9D55-7B8E7F157091").bytes_le)
        value = wintypes.LPWSTR()
        shell.SHGetKnownFolderPath.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.HANDLE, ctypes.POINTER(wintypes.LPWSTR)]
        shell.SHGetKnownFolderPath.restype = ctypes.c_long
        ole.CoTaskMemFree.argtypes = [ctypes.c_void_p]
        if shell.SHGetKnownFolderPath(guid, 0, None, ctypes.byref(value)) != 0:
            raise ClientError("user_storage_unavailable")
        try:
            return Path(value.value) / "CyberThunderClient"
        finally:
            ole.CoTaskMemFree(ctypes.cast(value, ctypes.c_void_p))
    import pwd
    return Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".cyberthunder-client"


def user_binding():
    if os.name != "nt":
        return "uid:" + str(os.geteuid())
    from cyberthunder.security import file_trust as ft
    users = ft._api().trusted_sids() - {ft._SYSTEM, ft._ADMINS, ft._INSTALLER}
    if len(users) != 1:
        raise ClientError("interactive_user_storage_required")
    return "sid:" + next(iter(users))


def _private_directory(root, fd):
    if os.name != "nt":
        files.check(fd, directory=True, private=True)
        return
    from cyberthunder.security import file_trust as ft
    native, trusted = ft._api(), ft._api().trusted_sids()
    handle = native.open(root, directory=True)
    try:
        _, (_, _, entries) = native.inspect(handle, root, trusted, directory=True, creating=True)
        for kind, flags, mask, trustee in entries:
            if kind == 0 and trustee not in trusted | {ft._OWNER_RIGHTS}:
                if (not flags & 8 and mask & 0x5) or (flags & 3 and mask & (ft._FILE_WRITE | ft._DIRECTORY_WRITE | 0x25)):
                    raise ClientError("private_user_directory_required")
    finally:
        native.CloseHandle(handle)


class TokenStore:
    def __init__(self, profile_digest, *, root=None):
        if len(profile_digest) != 64 or any(c not in "0123456789abcdef" for c in profile_digest):
            raise ClientError("profile_invalid")
        self.profile = profile_digest
        self.root = files.path(root if root is not None else user_root())
        self.data = self.root / (profile_digest + ".json")
        self.lockfile = self.root / (profile_digest + ".lock")
        self._held = False

    def _prepare(self):
        # Repository and node-state directories are not client credential storage.
        for ancestor in (self.root, *self.root.parents):
            if (ancestor / ".git").exists() or (ancestor / ".git").is_symlink():
                raise ClientError("client_storage_must_be_outside_repository")
        state = os.environ.get("CT_STATE_DIR")
        if state and self.root.is_relative_to(Path(state).absolute()):
            raise ClientError("client_storage_must_be_outside_state")
        with files.parents(self.root) as parent_fd:
            try:
                if os.name == "nt":
                    self.root.mkdir(mode=0o700)
                else:
                    os.mkdir(self.root.name, mode=0o700, dir_fd=parent_fd)
            except FileExistsError:
                pass

    @contextmanager
    def locked(self):
        if self._held:
            raise ClientError("client_store_already_locked")
        fd = None
        acquired = False
        try:
            self._prepare()
            with files.parents(self.lockfile) as parent_fd:
                _private_directory(self.root, parent_fd)
                if os.name == "nt":
                    import msvcrt
                    from cyberthunder.security import file_trust as ft
                    native = ft._api()
                    handle = native.CreateFileW("\\\\?\\" + str(ft._path(self.lockfile)), 0xC0000000, 3, None, 4, 0x00200000, None)
                    if handle == ft._INVALID_HANDLE:
                        raise ClientError("client_store_unavailable")
                    try:
                        native.inspect(handle, self.lockfile, native.trusted_sids(), private=True)
                        fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
                    except BaseException:
                        native.CloseHandle(handle)
                        raise
                else:
                    fd = os.open(self.lockfile.name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent_fd)
                    files.check(fd, private=True)
                deadline = time.monotonic() + 5
                while True:
                    try:
                        if os.name == "nt":
                            os.lseek(fd, 0, os.SEEK_SET)
                            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                        else:
                            import fcntl
                            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        acquired = self._held = True
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise ClientError("client_store_busy") from None
                        time.sleep(0.05)
                try:
                    yield self
                    _private_directory(self.root, parent_fd)
                finally:
                    self._held = False
                    if os.name == "nt":
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    acquired = False
        except ClientError:
            raise
        except (OSError, ValueError, TypeError, AttributeError):
            raise ClientError("client_store_unavailable") from None
        finally:
            self._held = False
            if fd is not None:
                os.close(fd)

    def _require_lock(self):
        if not self._held:
            raise ClientError("client_store_lock_required")

    def empty(self, previous=None):
        return {"version": 1, "profile": self.profile, "owner": user_binding(),
                "generation": secrets.token_hex(16), "phase": "empty", "session": None,
                "observed_at": max(time.time(), (previous or {}).get("observed_at", 0))}

    def load(self):
        self._require_lock()
        raw = files.read(self.data, private=True, missing=True)
        if raw is None:
            return self.empty()
        value = decode(raw)
        if (value.keys() != {"version", "profile", "owner", "generation", "phase", "session", "observed_at"}
                or type(value["version"]) is not int or value["version"] != 1 or value["profile"] != self.profile
                or value["owner"] != user_binding() or not isinstance(value["generation"], str)
                or len(value["generation"]) != 32 or any(c not in "0123456789abcdef" for c in value["generation"])
                or value["phase"] not in {"empty", "ready", "refreshing"}
                or (value["phase"] == "empty" and value["session"] is not None)
                or (value["phase"] != "empty" and not isinstance(value["session"], dict))
                or type(value["observed_at"]) not in {int, float} or not math.isfinite(value["observed_at"])):
            raise ClientError("client_store_invalid")
        if value["phase"] == "refreshing":
            value = self.empty(value)
            self.save(value)
        return value

    def save(self, value):
        self._require_lock()
        temporary = self.root / (".client-" + secrets.token_hex(16))
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        if len(raw) > 65536:
            raise ClientError("client_store_invalid")
        try:
            with files.parents(self.data) as parent_fd:
                _private_directory(self.root, parent_fd)
                files.read(self.data, private=True, missing=True)
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
                fd = os.open(temporary if os.name == "nt" else temporary.name, flags, 0o600, dir_fd=parent_fd)
                try:
                    if os.name == "nt":
                        from cyberthunder.security.file_trust import check_open_file
                        check_open_file(fd, temporary, private=True)
                    else:
                        files.check(fd, private=True)
                    view = memoryview(raw)
                    while view:
                        view = view[os.write(fd, view):]
                    os.fsync(fd)
                finally:
                    os.close(fd)
                if files.read(temporary, private=True) != raw:
                    raise ClientError("client_store_changed")
                if os.name == "nt":
                    os.replace(temporary, self.data)
                else:
                    os.replace(temporary.name, self.data.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                    os.fsync(parent_fd)
                if files.read(self.data, private=True) != raw:
                    raise ClientError("client_store_changed")
        except ClientError:
            raise
        except (OSError, ValueError, TypeError):
            raise ClientError("client_store_unavailable") from None
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
