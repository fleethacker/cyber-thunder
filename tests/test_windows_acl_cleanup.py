"""Native cleanup boundaries for newly created, registered disposable roots."""
import ctypes
import os
from pathlib import Path
import stat
import subprocess

import pytest

from tests import windows_acl as acl


pytestmark = pytest.mark.skipif(os.name != "nt", reason="native Windows read-only attributes and reparse points")


@pytest.fixture
def roots():
    owned = []
    readonly = []
    links = []

    def create():
        root = acl.create_root()
        owned.append(root)
        return root

    create.readonly = readonly
    create.links = links
    yield create
    # Restore only entries created by this fixture, including after calibration
    # against the old helper. Never discover or retry pre-existing test roots.
    for path, directory in reversed(links):
        assert any(root in path.parents for root in owned)
        if path.is_symlink() or (path.exists() and path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            os.rmdir(path) if directory else path.unlink()
        elif path.exists():
            # Both ends are this fixture's own creations. Restore the explicitly
            # owned source's bit, then remove the alias; the helper must refuse it.
            source = next(p for p in readonly if p.exists() and p.samefile(path))
            assert any(root in source.parents for root in owned)
            assert source.resolve() == source and source.stat().st_nlink == 2
            source.chmod(stat.S_IREAD | stat.S_IWRITE)
            path.unlink()
    for path in readonly:
        if path.exists():
            assert any(root in path.parents for root in owned)
            assert path.resolve() == path and path.stat().st_nlink == 1
            path.chmod(stat.S_IREAD | stat.S_IWRITE)
    for root in reversed(owned):
        if root.exists():
            assert root.resolve() == root and root.parent == Path(root.anchor)
            assert root.name.startswith("ct-trust-tests-")
            acl.register_root(root)
            acl.remove_root(root)


def readonly_file(roots, root, name="readonly"):
    path = root / name
    path.write_bytes(b"disposable cleanup fixture")
    path.chmod(stat.S_IREAD)
    roots.readonly.append(path)
    assert path.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY
    return path


def denied():
    return ctypes.WinError(5)


def test_remove_root_removes_native_readonly_git_object(roots):
    root = roots()
    subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True)
    object_id = subprocess.check_output(["git", "hash-object", "-w", "--stdin"],
                                        cwd=root, input=b"disposable object\n").decode().strip()
    path = root / ".git" / "objects" / object_id[:2] / object_id[2:]
    roots.readonly.append(path)
    assert path.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY
    with pytest.raises(PermissionError) as fault:
        path.unlink()
    assert fault.value.winerror == 5
    acl.remove_root(root)
    assert not root.exists() and root not in acl._roots


def test_cleanup_refuses_unregistered_root_before_rmtree(roots, monkeypatch):
    root = roots()
    sentinel = readonly_file(roots, root)
    acl._roots.remove(root)
    with monkeypatch.context() as patch:
        patch.setattr(acl.shutil, "rmtree", lambda *a, **k: pytest.fail("unregistered cleanup"))
        with pytest.raises(AssertionError):
            acl.remove_root(root)
    assert sentinel.read_bytes() == b"disposable cleanup fixture"


@pytest.mark.parametrize("boundary", ["other-root", "parent-traversal", "unregistered"])
def test_readonly_retry_refuses_paths_outside_its_registered_root(roots, monkeypatch, boundary):
    root, outside = roots(), roots()
    sentinel = readonly_file(roots, outside)
    path = sentinel if boundary != "parent-traversal" else root / ".." / outside.name / sentinel.name
    if boundary == "unregistered":
        acl._roots.remove(root)
    with monkeypatch.context() as patch:
        patch.setattr(acl.os, "chmod", lambda *a, **k: pytest.fail("unsafe attribute change"))
        patch.setattr(acl.os, "unlink", lambda *a, **k: pytest.fail("unsafe unlink"))
        with pytest.raises(AssertionError):
            acl._retry_readonly(root, acl.os.unlink, path, denied())
    assert sentinel.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY
    assert sentinel.read_bytes() == b"disposable cleanup fixture"


def test_readonly_retry_refuses_hardlinked_file_without_changing_outside_attributes(roots):
    root, outside = roots(), roots()
    sentinel = readonly_file(roots, outside)
    alias = root / "alias"
    os.link(sentinel, alias)
    roots.links.append((alias, False))
    with pytest.raises(AssertionError, match="hardlink"):
        acl._retry_readonly(root, os.unlink, alias, denied())
    assert alias.exists() and sentinel.stat().st_nlink == 2
    assert sentinel.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY


@pytest.mark.parametrize("kind", ["junction", "file-symlink", "directory-symlink"])
def test_readonly_retry_refuses_reparse_points_and_their_children(roots, kind):
    root, outside = roots(), roots()
    sentinel = readonly_file(roots, outside)
    alias = root / "alias"
    if kind == "junction":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(alias), str(outside)],
                       check=True, capture_output=True)
    else:
        alias.symlink_to(sentinel if kind == "file-symlink" else outside,
                         target_is_directory=kind == "directory-symlink")
    directory = kind != "file-symlink"
    roots.links.append((alias, directory))
    assert alias.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
    for path in [alias, *([alias / sentinel.name] if directory else [])]:
        with pytest.raises(AssertionError, match="reparse|symlink"):
            acl._retry_readonly(root, os.unlink, path, denied())
    assert sentinel.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY
    assert sentinel.read_bytes() == b"disposable cleanup fixture"


@pytest.mark.parametrize("kind", ["writable", "sharing", "missing", "directory", "other-operation", "generic-permission"])
def test_readonly_retry_does_not_swallow_unrelated_errors(roots, monkeypatch, kind):
    root = roots()
    path = readonly_file(roots, root)
    error = ctypes.WinError({"sharing": 32, "missing": 2}.get(kind, 5))
    if kind == "generic-permission":
        error = PermissionError("not a native read-only unlink failure")
    operation = os.unlink
    if kind == "writable":
        path.chmod(stat.S_IREAD | stat.S_IWRITE)
    elif kind == "directory":
        path = root
        operation = os.rmdir
    elif kind == "other-operation":
        operation = os.scandir
    with monkeypatch.context() as patch:
        patch.setattr(acl.os, "chmod", lambda *a, **k: pytest.fail("unexpected attribute change"))
        with pytest.raises(OSError) as fault:
            acl._retry_readonly(root, operation, path, error)
    assert fault.value is error


def test_readonly_retry_attempts_unlink_once_and_propagates_second_error(roots, monkeypatch):
    root = roots()
    path = readonly_file(roots, root)
    retried = []
    error = ctypes.WinError(32)

    def busy(candidate):
        retried.append(Path(candidate))
        raise error

    with monkeypatch.context() as patch:
        patch.setattr(acl.os, "unlink", busy)
        with pytest.raises(PermissionError) as fault:
            acl._retry_readonly(root, busy, path, denied())
    assert fault.value is error and retried == [path]


def test_remove_root_keeps_registration_and_reports_unhandled_error(roots, monkeypatch):
    root = roots()
    path = root / "sentinel"
    path.write_bytes(b"retained")
    error = ctypes.WinError(32)

    def busy(*args, **kwargs):
        raise error

    with monkeypatch.context() as patch:
        patch.setattr(acl.shutil, "rmtree", busy)
        with pytest.raises(PermissionError) as fault:
            acl.remove_root(root)
    assert fault.value is error and root in acl._roots
    assert path.read_bytes() == b"retained"
