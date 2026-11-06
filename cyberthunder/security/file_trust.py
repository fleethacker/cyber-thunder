"""Native Windows file trust. POSIX callers retain their existing owner/mode checks.

This proves a conservative permission boundary, not arbitrary users' effective access:
dangerous allow ACEs are rejected even if a deny ACE might counteract them. No ACLs
or privileges are changed. All diagnostics exclude paths, SIDs and file contents.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
import ctypes as c
from ctypes import wintypes as w
from functools import lru_cache
import os
from pathlib import Path
import re


class FileTrustError(ValueError):
    """The local Windows permission boundary could not be proved."""


def _fail():
    raise FileTrustError("Windows file protection is unavailable or unsafe") from None


_SYSTEM = "S-1-5-18"
_ADMINS = "S-1-5-32-544"
_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
_OWNER_RIGHTS = "S-1-3-4"
_READ_CONTROL = 0x20000
_MUTATE = 0x10000 | 0x40000 | 0x80000 | 0x10 | 0x100  # DELETE, WRITE_DAC/OWNER, write EA/attributes
_FILE_WRITE = _MUTATE | 0x2 | 0x4
_DIRECTORY_WRITE = _MUTATE | 0x40  # DELETE_CHILD defeats a child's own DELETE restriction
_REPARSE = 0x400
_DIRECTORY = 0x10
_INVALID_HANDLE = c.c_void_p(-1).value


class _FileInfo(c.Structure):
    _fields_ = [("attributes", w.DWORD), ("created", w.FILETIME), ("accessed", w.FILETIME),
                ("written", w.FILETIME), ("volume", w.DWORD), ("size_hi", w.DWORD), ("size_lo", w.DWORD),
                ("links", w.DWORD), ("index_hi", w.DWORD), ("index_lo", w.DWORD)]


class _Acl(c.Structure):
    _fields_ = [("revision", w.BYTE), ("reserved", w.BYTE), ("size", w.WORD),
                ("count", w.WORD), ("reserved2", w.WORD)]


class _GenericMapping(c.Structure):
    _fields_ = [("read", w.DWORD), ("write", w.DWORD), ("execute", w.DWORD), ("all", w.DWORD)]


class _Native:
    def __init__(self):
        if os.name != "nt":
            _fail()
        self.kernel = c.WinDLL("kernel32", use_last_error=True)
        self.adv = c.WinDLL("advapi32", use_last_error=True)
        ptr = c.c_void_p
        def bind(library, name, result, args):
            fn = getattr(library, name)
            fn.restype, fn.argtypes = result, args
            setattr(self, name, fn)
        bind(self.kernel, "CreateFileW", w.HANDLE, [w.LPCWSTR, w.DWORD, w.DWORD, ptr, w.DWORD, w.DWORD, w.HANDLE])
        bind(self.kernel, "CloseHandle", w.BOOL, [w.HANDLE])
        bind(self.kernel, "GetFileType", w.DWORD, [w.HANDLE])
        bind(self.kernel, "GetFileInformationByHandle", w.BOOL, [w.HANDLE, c.POINTER(_FileInfo)])
        bind(self.kernel, "GetFinalPathNameByHandleW", w.DWORD, [w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD])
        bind(self.kernel, "GetVolumeInformationByHandleW", w.BOOL,
             [w.HANDLE, w.LPWSTR, w.DWORD, c.POINTER(w.DWORD), c.POINTER(w.DWORD), c.POINTER(w.DWORD), w.LPWSTR, w.DWORD])
        bind(self.kernel, "GetDriveTypeW", w.UINT, [w.LPCWSTR])
        bind(self.kernel, "GetCurrentProcess", w.HANDLE, [])
        bind(self.kernel, "GetCurrentThread", w.HANDLE, [])
        bind(self.kernel, "LocalFree", ptr, [ptr])
        bind(self.adv, "OpenProcessToken", w.BOOL, [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)])
        bind(self.adv, "OpenThreadToken", w.BOOL, [w.HANDLE, w.DWORD, w.BOOL, c.POINTER(w.HANDLE)])
        bind(self.adv, "GetTokenInformation", w.BOOL, [w.HANDLE, c.c_int, ptr, w.DWORD, c.POINTER(w.DWORD)])
        bind(self.adv, "ConvertSidToStringSidW", w.BOOL, [ptr, c.POINTER(w.LPWSTR)])
        bind(self.adv, "IsValidSid", w.BOOL, [ptr])
        bind(self.adv, "GetLengthSid", w.DWORD, [ptr])
        bind(self.adv, "GetSecurityInfo", w.DWORD,
             [w.HANDLE, c.c_int, w.DWORD, c.POINTER(ptr), ptr, c.POINTER(ptr), ptr, c.POINTER(ptr)])
        bind(self.adv, "IsValidSecurityDescriptor", w.BOOL, [ptr])
        bind(self.adv, "GetSecurityDescriptorControl", w.BOOL, [ptr, c.POINTER(w.WORD), c.POINTER(w.DWORD)])
        bind(self.adv, "IsValidAcl", w.BOOL, [ptr])
        bind(self.adv, "GetAce", w.BOOL, [ptr, w.DWORD, c.POINTER(ptr)])
        bind(self.adv, "MapGenericMask", None, [c.POINTER(w.DWORD), c.POINTER(_GenericMapping)])

    def sid(self, pointer):
        if not pointer or not self.IsValidSid(pointer):
            _fail()
        text = w.LPWSTR()
        if not self.ConvertSidToStringSidW(pointer, c.byref(text)):
            _fail()
        try:
            return text.value
        finally:
            self.LocalFree(c.cast(text, c.c_void_p))

    def trusted_sids(self):
        token = w.HANDLE()
        # This application does not use OS thread impersonation. Do not silently
        # trust a process owner while the kernel is checking a different token.
        if self.OpenThreadToken(self.GetCurrentThread(), 8, True, c.byref(token)):
            self.CloseHandle(token)
            _fail()
        if c.get_last_error() != 1008:  # ERROR_NO_TOKEN
            _fail()
        if not self.OpenProcessToken(self.GetCurrentProcess(), 8, c.byref(token)):
            _fail()
        try:
            length = w.DWORD()
            self.GetTokenInformation(token, 1, None, 0, c.byref(length))
            if not 0 < length.value <= 65536:
                _fail()
            buffer = c.create_string_buffer(length.value)
            if not self.GetTokenInformation(token, 1, buffer, length, c.byref(length)):
                _fail()
            user = self.sid(c.cast(buffer, c.POINTER(c.c_void_p))[0])
            return frozenset({user, _SYSTEM, _ADMINS, _INSTALLER})
        finally:
            self.CloseHandle(token)

    def open(self, path, *, directory):
        access = _READ_CONTROL | 0x80 if directory else 0x80000000  # metadata or GENERIC_READ
        # Keep ancestor names pinned. On files, also exclude concurrent data writers.
        share = 3 if directory else 1  # FILE_SHARE_READ [| FILE_SHARE_WRITE], never DELETE
        flags = 0x00200000 | (0x02000000 if directory else 0)  # OPEN_REPARSE_POINT, BACKUP_SEMANTICS
        handle = self.CreateFileW("\\\\?\\" + str(path), access, share, None, 3, flags, None)
        if handle == _INVALID_HANDLE:
            if c.get_last_error() in {2, 3}:
                raise FileNotFoundError("Protected file is absent") from None
            _fail()
        return handle

    def acl(self, handle, trusted, *, private=False, directory=False, creating=False):
        owner, acl, descriptor = c.c_void_p(), c.c_void_p(), c.c_void_p()
        if self.GetSecurityInfo(handle, 1, 5, c.byref(owner), None, c.byref(acl), None, c.byref(descriptor)):
            _fail()
        try:
            control, revision = w.WORD(), w.DWORD()
            if (not descriptor or not self.IsValidSecurityDescriptor(descriptor)
                    or not self.GetSecurityDescriptorControl(descriptor, c.byref(control), c.byref(revision))
                    or not control.value & 4 or not acl or not self.IsValidAcl(acl)):
                _fail()  # absent and null DACLs grant unrestricted access
            owner_sid = self.sid(owner)
            if owner_sid not in trusted:
                _fail()  # owners can normally obtain WRITE_DAC even without an allow ACE
            header = c.cast(acl, c.POINTER(_Acl)).contents
            if header.count > 1024 or header.size > 65535 or header.revision not in {2, 4}:
                _fail()
            forbidden = _DIRECTORY_WRITE | (0x6 if creating else 0) if directory else _FILE_WRITE | (0x21 if private else 0)
            entries = []
            for index in range(header.count):
                ace = c.c_void_p()
                if not self.GetAce(acl, index, c.byref(ace)):
                    _fail()
                address = ace.value
                if not acl.value + c.sizeof(_Acl) <= address <= acl.value + header.size - 8:
                    _fail()
                kind, flags = c.string_at(ace, 2)
                size = c.cast(address + 2, c.POINTER(w.WORD))[0]
                if size < 16 or address + size > acl.value + header.size or flags & ~0x1F or kind not in {0, 1}:
                    _fail()  # conditional, callback and object ACEs are deliberately unsupported
                sid_pointer = c.c_void_p(address + 8)
                if not self.IsValidSid(sid_pointer) or self.GetLengthSid(sid_pointer) != size - 8:
                    _fail()
                trustee = self.sid(sid_pointer)
                mask = w.DWORD(c.cast(address + 4, c.POINTER(w.DWORD))[0])
                mapping = _GenericMapping(0x120089, 0x120116, 0x1200A0, 0x1F01FF)
                self.MapGenericMask(c.byref(mask), c.byref(mapping))
                entries.append((kind, flags, mask.value, trustee))
                # Inherit-only does not apply to this object. Denies cannot expand
                # rights; never subtract them from grants using guessed memberships.
                if kind == 0 and not flags & 8 and trustee not in trusted | {_OWNER_RIGHTS}:
                    if mask.value & forbidden or mask.value & ~0x1F01FF:
                        _fail()
            return owner_sid, control.value, tuple(entries)
        finally:
            self.LocalFree(descriptor)

    def inspect(self, handle, path, trusted, *, private=False, directory=False, creating=False):
        info = _FileInfo()
        if self.GetFileType(handle) != 1 or not self.GetFileInformationByHandle(handle, c.byref(info)):
            _fail()
        if info.attributes & _REPARSE or bool(info.attributes & _DIRECTORY) != directory:
            _fail()
        if not directory and info.links != 1:
            _fail()
        final = c.create_unicode_buffer(32768)
        size = self.GetFinalPathNameByHandleW(handle, final, len(final), 0)
        expected = "\\\\?\\" + str(path)
        if not 0 < size < len(final) or final.value.rstrip("\\").casefold() != expected.rstrip("\\").casefold():
            _fail()
        identity = (info.volume, info.index_hi, info.index_lo, info.attributes)
        if not directory:
            identity += (info.links, info.size_hi, info.size_lo, info.created.dwHighDateTime,
                         info.created.dwLowDateTime, info.written.dwHighDateTime, info.written.dwLowDateTime)
        return identity, self.acl(handle, trusted, private=private, directory=directory, creating=creating)

    def volume(self, handle, path):
        flags = w.DWORD()
        if (self.GetDriveTypeW(str(path.anchor)) not in {2, 3, 6}
                or not self.GetVolumeInformationByHandleW(handle, None, 0, None, None, c.byref(flags), None, 0)
                or not flags.value & 8):  # FILE_PERSISTENT_ACLS; network/virtual aliases are unsupported
            _fail()


@lru_cache(maxsize=1)
def _api():
    try:
        return _Native()
    except (OSError, AttributeError, TypeError, ValueError):
        _fail()


def _path(value):
    path = Path(value)
    if (os.name != "nt" or not path.is_absolute() or not re.fullmatch(r"[A-Za-z]:", path.drive)
            or not 2 <= len(path.parts) <= 128 or len(str(path)) > 4096):
        _fail()
    for part in path.parts[1:]:
        if (part in {".", ".."} or part.endswith((".", " ")) or any(ord(ch) < 32 for ch in part)
                or any(ch in part for ch in ':*?<>|"') or Path(part).is_reserved()):
            _fail()
    return path


@contextmanager
def protected_parent(path, *, creating=False):
    """Pin and check every ancestor; creation also forbids foreign child creation."""
    try:
        path, native = _path(path), _api()
        trusted = native.trusted_sids()
        with ExitStack() as stack:
            parents = []
            for parent in reversed(path.parents):
                handle = native.open(parent, directory=True)
                stack.callback(native.CloseHandle, handle)
                options = {"directory": True, "creating": creating and parent == path.parent}
                before = native.inspect(handle, parent, trusted, **options)
                if not parents:
                    native.volume(handle, parent)
                parents.append((handle, parent, options, before))
            yield native, trusted
            for handle, parent, options, before in parents:
                if native.inspect(handle, parent, trusted, **options) != before:
                    _fail()
    except (OSError, AttributeError, TypeError):
        _fail()


@contextmanager
def open_protected(path, *, private=False):
    """Yield a checked binary stream with its complete ancestor chain pinned.

    Revalidate handle identity, owner and DACL before closing. A missing leaf raises
    FileNotFoundError; missing/unsafe parents and unavailable native APIs fail closed.
    """
    path = _path(path)
    import msvcrt
    missing = False
    with protected_parent(path) as (native, trusted):
        try:
            handle = native.open(path, directory=False)
        except FileNotFoundError:
            missing = True
        if not missing:
            try:
                before = native.inspect(handle, path, trusted, private=private)
                fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            except BaseException:
                native.CloseHandle(handle)
                raise
            try:
                stream = os.fdopen(fd, "rb")
            except BaseException:
                os.close(fd)
                raise
            with stream:
                yield stream
                if native.inspect(handle, path, trusted, private=private) != before:
                    _fail()
    if missing:
        raise FileNotFoundError("Protected file is absent") from None


def check_open_file(fd, path, *, private=False):
    """Check an already-created file before writing; caller must pin its parents."""
    import msvcrt
    try:
        native = _api()
        return native.inspect(msvcrt.get_osfhandle(fd), _path(path), native.trusted_sids(), private=private)
    except (OSError, AttributeError, TypeError):
        _fail()
