"""Disposable native ACL fixtures. Never change permissions outside registered test roots."""
import csv
import ctypes as c
from ctypes import wintypes as w
import gc
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from weakref import WeakSet

_roots = set()
_sid = None


def register_root(root):
    root = Path(root).absolute()
    assert root.parent != root and root.resolve() == root
    _roots.add(root)


def user_sid():
    global _sid
    if _sid is None:
        raw = subprocess.check_output(["whoami", "/user", "/fo", "csv", "/nh"], text=True)
        _sid = next(csv.reader([raw.strip()]))[1]
        assert _sid.startswith("S-1-")
    return _sid


def protected_aces(*, directory=False):
    inherit = "OICI" if directory else ""
    return "".join(f"(A;{inherit};FA;;;{sid})" for sid in (user_sid(), "SY", "BA"))


def set_dacl(path, aces=None, *, null=False):
    """Apply a deliberate fixture DACL, with numeric/well-known SDDL SIDs only."""
    path = Path(path).absolute()
    resolved = path.resolve()
    assert any(resolved == root or root in resolved.parents for root in _roots), "ACL fixture escaped its root"
    adv = c.WinDLL("advapi32", use_last_error=True)
    kernel = c.WinDLL("kernel32", use_last_error=True)
    ptr = c.c_void_p
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR, w.DWORD, c.POINTER(ptr), ptr]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = w.BOOL
    adv.GetSecurityDescriptorDacl.argtypes = [ptr, c.POINTER(w.BOOL), c.POINTER(ptr), c.POINTER(w.BOOL)]
    adv.GetSecurityDescriptorDacl.restype = w.BOOL
    adv.SetNamedSecurityInfoW.argtypes = [w.LPWSTR, c.c_int, w.DWORD, ptr, ptr, ptr, ptr]
    adv.SetNamedSecurityInfoW.restype = w.DWORD
    kernel.LocalFree.argtypes = [ptr]
    descriptor, acl = ptr(), ptr()
    if not null:
        sddl = "D:P" + (protected_aces(directory=path.is_dir()) if aces is None else aces)
        assert adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, c.byref(descriptor), None)
        present, defaulted = w.BOOL(), w.BOOL()
        assert adv.GetSecurityDescriptorDacl(descriptor, c.byref(present), c.byref(acl), c.byref(defaulted))
        assert present.value
    try:
        error = adv.SetNamedSecurityInfoW(str(path), 1, 0x80000004, None, None, acl, None)
        assert error == 0, f"fixture ACL update failed (Windows error {error})"
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)


def create_root():
    assert os.name == "nt"
    anchor = Path(tempfile.gettempdir()).anchor
    root = Path(tempfile.mkdtemp(prefix="ct-trust-tests-", dir=anchor)).absolute()
    assert root.parent == Path(anchor) and root.name.startswith("ct-trust-tests-")
    _roots.add(root)
    try:
        set_dacl(root)
    except BaseException:
        remove_root(root)
        raise
    return root


def track_databases(root):
    """Close retained test databases before removing this session's own root."""
    from cyberthunder.state.sqlite import SqliteBackend

    original = SqliteBackend.__init__
    retained = WeakSet()

    def initialize(database, *args, **kwargs):
        original(database, *args, **kwargs)
        if database.path.resolve().is_relative_to(root):
            retained.add(database)

    SqliteBackend.__init__ = initialize

    def close():
        SqliteBackend.__init__ = original
        for database in tuple(retained):
            database.close()

    return close


def remove_root(root):
    root = Path(root).absolute()
    assert root in _roots and root.resolve() == root and root.parent == Path(root.anchor)
    assert root.name.startswith("ct-trust-tests-")
    try:
        gc.collect()  # Release unreachable test contexts/SQLite connections before Windows deletion.
        shutil.rmtree(root)
    finally:
        _roots.remove(root)
