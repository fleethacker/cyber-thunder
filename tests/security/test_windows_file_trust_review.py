"""Independent native Windows regressions using only disposable local fixtures."""
import ctypes as c
from ctypes import wintypes as w
import os
from pathlib import Path
import struct

import pytest

from cyberthunder.control.principal import operation_scope, principal_scope
from cyberthunder.security import _oidc_cache as cache, file_trust as ft
from cyberthunder.security.oidc import OIDCValidator
from tests.security.test_kubernetes_account_integration import selected_cluster
from tests.security.test_kube_credentials import cert_material
from tests.security.test_oidc import offline_config, rejected, signing_keys, token
from tests.security.test_windows_file_trust import acl, read
from tests.windows_acl import protected_aces, set_dacl, user_sid

pytestmark = pytest.mark.skipif(os.name != "nt", reason="native Windows security descriptors and file sharing")


def test_add_file_can_set_reparse_data_while_directory_is_pinned(tmp_path, acl):
    directory, target = tmp_path / "empty", tmp_path / "target"
    directory.mkdir()
    target.mkdir()
    acl(directory, protected_aces(directory=True) + "(A;;0x2;;;S-1-1-0)")
    native = ft._api()
    pinned = native.open(directory, directory=True)
    writer = native.CreateFileW(str(directory), 0x2, 7, None, 3, 0x02200000, None)
    assert writer != c.c_void_p(-1).value
    ioctl = native.kernel.DeviceIoControl
    ioctl.argtypes = [w.HANDLE, w.DWORD, c.c_void_p, w.DWORD, c.c_void_p,
                     w.DWORD, c.POINTER(w.DWORD), c.c_void_p]
    ioctl.restype = w.BOOL
    # Open requests only FILE_ADD_FILE / FILE_WRITE_DATA, without WRITE_ATTRIBUTES.
    substitute = ("\\??\\" + str(target)).encode("utf-16-le")
    display = str(target).encode("utf-16-le")
    names = substitute + b"\0\0" + display + b"\0\0"
    data = struct.pack("<IHHHHHH", 0xA0000003, len(names) + 8, 0, 0,
                       len(substitute), len(substitute) + 2, len(display)) + names
    returned = w.DWORD()
    tagged = False
    try:
        with pytest.raises(ft.FileTrustError):
            native.acl(pinned, native.trusted_sids(), directory=True)
        buffer = c.create_string_buffer(data)
        assert ioctl(writer, 0x900A4, buffer, len(data), None, 0, c.byref(returned), None)
        tagged = True
        assert directory.lstat().st_file_attributes & 0x400
    finally:
        try:
            if tagged:
                deletion = c.create_string_buffer(struct.pack("<IHH", 0xA0000003, 0, 0))
                assert ioctl(writer, 0x900AC, deletion, 8, None, 0, c.byref(returned), None)
        finally:
            native.CloseHandle(writer)
            native.CloseHandle(pinned)


@pytest.mark.parametrize("trusted", [False, True])
def test_conditional_allow_ace_is_refused_for_any_trustee(tmp_path, acl, trusted):
    path = tmp_path / "conditional.json"
    path.write_bytes(b"{}")
    trustee = user_sid() if trusted else "S-1-1-0"
    acl(path, protected_aces() + f"(XA;;GR;;;{trustee};(@User.ct_trust == 1))")
    with pytest.raises(ft.FileTrustError):
        read(path)


@pytest.mark.parametrize("mask", [0x1, 0x20])
def test_private_file_refuses_individual_read_and_execute_grants(tmp_path, acl, mask):
    path = tmp_path / "key-fixture"
    path.write_bytes(b"disposable-private-bytes")
    acl(path, protected_aces() + f"(A;;0x{mask:x};;;S-1-1-0)")
    with pytest.raises(ft.FileTrustError):
        read(path, private=True)


@pytest.mark.parametrize("change", ["purge", "replace"])
def test_cache_final_destination_read_cannot_ignore_revocation(tmp_path, monkeypatch, change):
    path = tmp_path / "cache.json"
    original, newer, stale = b'{"watermark":1}', b'{"watermark":3}', b'{"watermark":2}'
    cache.write_cache(path, original)
    real_read = cache.read_cache
    attacked = []

    def revoke_after_temporary_check(candidate):
        data = real_read(candidate)
        if Path(candidate).name.startswith(".oidc-"):
            attacked.append(True)
            if change == "purge":
                path.unlink()
            else:
                path.write_bytes(newer)
        return data

    monkeypatch.setattr(cache, "read_cache", revoke_after_temporary_check)
    with pytest.raises(ValueError):
        cache.write_cache(path, stale, expected_digest=cache.digest(original))
    assert attacked == [True]
    assert real_read(path) == (None if change == "purge" else newer)
    assert not list(tmp_path.glob(".oidc-*"))


@pytest.mark.parametrize("change", ["bytes", "dacl"])
def test_cache_reopens_and_validates_published_file(tmp_path, monkeypatch, acl, change):
    path = tmp_path / "cache.json"
    cache.write_cache(path, b"old")
    replace = cache.os.replace
    called = []

    def corrupt_published(source, destination):
        replace(source, destination)
        called.append(True)
        if change == "bytes":
            path.write_bytes(b"different")
        else:
            acl(path, protected_aces() + "(A;;GW;;;S-1-1-0)")

    monkeypatch.setattr(cache.os, "replace", corrupt_published)
    with pytest.raises(ValueError):
        cache.write_cache(path, b"new", expected_digest=cache.digest(b"old"))
    assert called == [True] and not list(tmp_path.glob(".oidc-*"))


def test_acl_fixture_refuses_hardlink_aliases(tmp_path):
    original, alias = tmp_path / "original", tmp_path / "alias"
    original.write_bytes(b"fixture")
    os.link(original, alias)
    with pytest.raises(AssertionError, match="hardlinked"):
        set_dacl(alias)


@pytest.mark.parametrize("hazard", ["private-read", "parent-add-file", "native-unavailable"])
def test_kubernetes_protection_failure_stops_before_ambient_fallback(selected_cluster, monkeypatch, acl, hazard):
    ctx, target, person, config, _, calls = selected_cluster
    with principal_scope(person), operation_scope("scan"):
        transport = ctx.transport_for(target)
        if hazard == "private-read":
            acl(config, protected_aces() + "(A;;GR;;;S-1-1-0)")
        elif hazard == "parent-add-file":
            acl(config.parent, protected_aces(directory=True) + "(A;;0x2;;;S-1-1-0)")
        else:
            def unavailable():
                raise ft.FileTrustError("native API unavailable")
            monkeypatch.setattr(ft, "_api", unavailable)
        with pytest.raises(PermissionError):
            transport.run("kubectl get nodes")
    assert calls == []


def test_live_oidc_dacl_revocation_latches_without_reusing_memory_keys(tmp_path, signing_keys, acl):
    config = offline_config(tmp_path, signing_keys)
    validator = OIDCValidator(config)
    encoded = token(signing_keys)
    assert validator.validate(encoded)["sub"] == "operator-123"
    original = config.cache_path.read_bytes()
    acl(config.cache_path, protected_aces() + "(A;;GW;;;S-1-1-0)")
    rejected(validator, encoded)
    acl(config.cache_path)
    assert config.cache_path.read_bytes() == original
    rejected(validator, encoded)
