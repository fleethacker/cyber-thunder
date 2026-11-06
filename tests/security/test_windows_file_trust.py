"""Native Windows ACL and path attacks against disposable, protected local files."""
import ctypes as c
import os
from pathlib import Path

import pytest

from cyberthunder.control import access
from cyberthunder.security import file_trust as ft, _oidc_cache as cache
from cyberthunder.security.kube_credentials import guard_kubeconfig, validate_kubeconfig, KubeCredentialError
from tests.security.test_access_file_trust import policy_file, principal
from tests.security.test_kube_credentials import cert_material, document, account, write
from tests.windows_acl import set_dacl, protected_aces

pytestmark = pytest.mark.skipif(os.name != "nt", reason="native Windows security descriptors and file sharing")


@pytest.fixture
def acl():
    changed = []
    def change(path, entries=None, **kwargs):
        changed.append(path)
        set_dacl(path, entries, **kwargs)
    yield change
    for path in reversed(changed):
        if Path(path).exists():
            set_dacl(path)


def read(path, *, private=False):
    with ft.open_protected(path, private=private) as stream:
        return stream.read()


def test_fixture_is_genuinely_protected_and_checks_private_bytes(tmp_path):
    path = tmp_path / "private.pem"
    path.write_bytes(b"disposable-fixture")
    assert read(path, private=True) == b"disposable-fixture"
    with pytest.raises(FileNotFoundError):
        read(tmp_path / "absent")
    with pytest.raises(ft.FileTrustError):
        read(tmp_path / "absent-parent" / "absent")


@pytest.mark.parametrize("mask", [0x2, 0x4, 0x10, 0x100, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000])
def test_file_mutation_granted_to_everyone_is_rejected(tmp_path, acl, mask):
    path = tmp_path / "public.json"
    path.write_bytes(b"{}")
    acl(path, protected_aces() + f"(A;;0x{mask:x};;;S-1-1-0)")
    with pytest.raises(ft.FileTrustError):
        read(path)


@pytest.mark.parametrize("trustee", ["S-1-5-32-545", "S-1-5-11", "S-1-5-21-100-200-300-4444"])
def test_group_membership_or_unknown_sid_cannot_grant_file_mutation(tmp_path, acl, trustee):
    path = tmp_path / "policy.json"
    path.write_bytes(b"{}")
    acl(path, protected_aces() + f"(A;;GW;;;{trustee})")
    with pytest.raises(ft.FileTrustError):
        read(path)


def test_public_read_is_allowed_but_private_data_read_is_not(tmp_path, acl):
    path = tmp_path / "credential"
    path.write_bytes(b"fixture-only")
    acl(path, protected_aces() + "(A;;GR;;;S-1-1-0)")
    assert read(path) == b"fixture-only"
    with pytest.raises(ft.FileTrustError):
        read(path, private=True)
    # Metadata/READ_CONTROL does not grant access to credential bytes.
    acl(path, protected_aces() + "(A;;0x20080;;;S-1-1-0)")
    assert read(path, private=True) == b"fixture-only"


def test_null_dacl_and_unsupported_object_ace_are_rejected(tmp_path, acl):
    path = tmp_path / "policy.json"
    path.write_bytes(b"{}")
    acl(path, null=True)
    with pytest.raises(ft.FileTrustError):
        read(path)
    acl(path, protected_aces() + "(OA;;GR;00112233-4455-6677-8899-aabbccddeeff;;S-1-1-0)")
    with pytest.raises(ft.FileTrustError):
        read(path)


def test_owner_must_be_in_the_trusted_sid_set(tmp_path):
    path = tmp_path / "policy.json"
    path.write_bytes(b"{}")
    native = ft._api()
    handle = native.open(path, directory=False)
    try:
        trusted = native.trusted_sids()
        owner, _, _ = native.acl(handle, trusted)
        # Exercise the actual descriptor's owner, without creating another account
        # or enabling SeRestorePrivilege merely to manufacture a foreign owner.
        with pytest.raises(ft.FileTrustError):
            native.acl(handle, trusted - {owner})
    finally:
        native.CloseHandle(handle)


def test_owner_rights_is_only_accepted_for_a_checked_trusted_owner(tmp_path, acl):
    path = tmp_path / "policy.json"
    path.write_bytes(b"{}")
    acl(path, protected_aces() + "(A;;GA;;;S-1-3-4)")
    assert read(path) == b"{}"


def test_deny_ace_does_not_make_a_dangerous_allow_acceptable(tmp_path, acl):
    path = tmp_path / "policy.json"
    path.write_bytes(b"{}")
    acl(path, "(D;;0x2;;;S-1-1-0)" + protected_aces() + "(A;;0x2;;;S-1-1-0)")
    # The kernel really denies this write; our stricter proof still rejects the
    # dangerous allow instead of guessing effective rights for every account.
    with pytest.raises(PermissionError):
        path.write_bytes(b"cannot-write")
    with pytest.raises(ft.FileTrustError):
        read(path)


@pytest.mark.parametrize("mask", [0x40, 0x10000, 0x40000, 0x80000, 0x100, 0x10])
@pytest.mark.parametrize("ancestor", ["parent", "grandparent"])
def test_parent_mutation_including_delete_child_is_rejected(tmp_path, acl, mask, ancestor):
    directory = tmp_path / "outer" / "inner"
    directory.mkdir(parents=True)
    path = directory / "policy.json"
    path.write_bytes(b"{}")
    suspect = directory if ancestor == "parent" else directory.parent
    acl(suspect, protected_aces(directory=True) + f"(A;;0x{mask:x};;;S-1-1-0)")
    with pytest.raises(ft.FileTrustError):
        read(path)


def test_child_creation_is_safe_for_existing_reads_but_not_cache_creation(tmp_path, acl):
    path = tmp_path / "existing"
    path.write_bytes(b"public")
    acl(tmp_path, protected_aces(directory=True) + "(A;;0x6;;;S-1-1-0)")
    assert read(path) == b"public"
    with pytest.raises(ft.FileTrustError):
        cache.write_cache(tmp_path / "new-cache", b"{}")
    assert not (tmp_path / "new-cache").exists()


def test_inherit_only_grant_is_checked_on_new_cache_file_before_write(tmp_path, acl):
    acl(tmp_path, protected_aces(directory=True) + "(A;OIIO;GW;;;S-1-1-0)")
    path = tmp_path / "cache"
    with pytest.raises(ft.FileTrustError):
        cache.write_cache(path, b"public-jwks-fixture")
    assert not path.exists() and not list(tmp_path.glob(".oidc-*"))


def test_handles_prevent_file_and_parent_replacement_and_data_writes(tmp_path):
    directory = tmp_path / "guarded"
    directory.mkdir()
    path = directory / "policy.json"
    path.write_bytes(b"original")
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"replacement")
    with ft.open_protected(path) as stream:
        for attack in (lambda: os.replace(replacement, path),
                       lambda: directory.rename(tmp_path / "parked"),
                       lambda: path.write_bytes(b"changed")):
            with pytest.raises(PermissionError):
                attack()
        assert stream.read() == b"original"
    # Successful replacement after exit also proves the handles were released.
    os.replace(replacement, path)
    assert read(path) == b"replacement"


def test_dacl_change_after_read_invalidates_the_operation(tmp_path, acl):
    path = tmp_path / "credential"
    path.write_bytes(b"fixture-data")
    with pytest.raises(ft.FileTrustError):
        with ft.open_protected(path, private=True) as stream:
            assert stream.read() == b"fixture-data"
            acl(path, protected_aces() + "(A;;GR;;;S-1-1-0)")


def test_policy_dacl_change_during_parse_invalidates_decision(tmp_path, monkeypatch, acl):
    policy = policy_file(tmp_path / "access.json")
    parse = access._parse
    def change(raw):
        result = parse(raw)
        acl(policy.path, protected_aces() + "(A;;GW;;;S-1-1-0)")
        return result
    monkeypatch.setattr(access, "_parse", change)
    with pytest.raises(access.AccessDenied):
        policy.require(principal(), "read")


def test_replacement_between_policy_lstat_and_native_open_is_rejected(tmp_path, monkeypatch):
    policy = policy_file(tmp_path / "access.json")
    other = tmp_path / "other.json"
    other.write_bytes(policy.path.read_bytes())
    original = ft._Native.open
    def replace(self, path, *, directory):
        if path == policy.path:
            os.replace(other, path)
        return original(self, path, directory=directory)
    monkeypatch.setattr(ft._Native, "open", replace)
    with pytest.raises(access.AccessDenied):
        policy.require(principal(), "read")


def test_junction_created_between_checks_and_open_is_rejected(tmp_path, monkeypatch):
    import _winapi
    policy = policy_file(tmp_path / "guarded" / "access.json")
    alternate = tmp_path / "alternate"
    policy_file(alternate / "access.json")
    original = ft._Native.open
    def redirect(self, path, *, directory):
        if path == policy.path.parent:
            path.rename(tmp_path / "parked")
            _winapi.CreateJunction(str(alternate), str(path))
        return original(self, path, directory=directory)
    monkeypatch.setattr(ft._Native, "open", redirect)
    with pytest.raises(access.AccessDenied):
        policy.require(principal(), "read")


def test_native_api_unavailable_fails_closed_for_policy_and_cache(tmp_path, monkeypatch):
    policy = policy_file(tmp_path / "access.json")
    def unavailable(*a, **kw):
        raise OSError("private-native-error-canary")
    ft._api.cache_clear()
    monkeypatch.setattr(c, "WinDLL", unavailable)
    try:
        with pytest.raises(access.AccessDenied) as error:
            policy.require(principal(), "read")
        assert "private-native-error-canary" not in str(error.value)
        with pytest.raises(ft.FileTrustError):
            cache.read_cache(tmp_path / "missing-cache")
        with pytest.raises(ft.FileTrustError):
            cache.write_cache(tmp_path / "missing-cache", b"{}")
    finally:
        ft._api.cache_clear()


def test_kubeconfig_confidentiality_and_guard_recheck(tmp_path, cert_material, acl):
    path = write(tmp_path / "selected.yaml", document(cert_material))
    bound = validate_kubeconfig(account(path))
    assert bound.protection == "windows_dacl"
    acl(path, protected_aces() + "(A;;GR;;;S-1-1-0)")
    for operation in (lambda: validate_kubeconfig(account(path)), lambda: guard_kubeconfig(bound)):
        with pytest.raises(KubeCredentialError) as error:
            operation()
        assert "DoNotLog" not in str(error.value) and str(path) not in str(error.value)


def test_external_kube_public_certificates_and_private_key_have_distinct_rules(tmp_path, cert_material, acl):
    ca = write(tmp_path / "ca.pem", cert_material["ca"], private=False)
    cert = write(tmp_path / "client.pem", cert_material["client"], private=False)
    key = write(tmp_path / "client.key", cert_material["key"])
    doc = document(cert_material)
    cluster = doc["clusters"][0]["cluster"]
    del cluster["certificate-authority-data"]
    cluster["certificate-authority"] = str(ca)
    doc["users"][0]["user"] = {"client-certificate": str(cert), "client-key": str(key)}
    config = write(tmp_path / "selected.yaml", doc)
    for public in (ca, cert):
        acl(public, protected_aces() + "(A;;GR;;;S-1-1-0)")
    bound = validate_kubeconfig(account(config))
    assert bound.protection == "windows_dacl" and len(bound.files) == 4
    acl(key, protected_aces() + "(A;;GR;;;S-1-1-0)")
    with pytest.raises(KubeCredentialError):
        guard_kubeconfig(bound)
    with pytest.raises(KubeCredentialError):
        validate_kubeconfig(account(config))


def test_cache_integrity_allows_readers_and_rejects_writer_or_replacement(tmp_path, acl):
    path = tmp_path / "jwks.json"
    cache.write_cache(path, b'{"keys":[]}')
    before = cache.digest(cache.read_cache(path))
    acl(path, protected_aces() + "(A;;GR;;;S-1-1-0)")
    assert cache.read_cache(path) == b'{"keys":[]}'
    cache.write_cache(path, b'{"keys":[],"version":2}', expected_digest=before)
    with pytest.raises(ValueError):
        cache.write_cache(path, b"{}", expected_digest=before)
    acl(path, protected_aces() + "(A;;GW;;;S-1-1-0)")
    for operation in (lambda: cache.read_cache(path), lambda: cache.write_cache(path, b"{}")):
        with pytest.raises(ft.FileTrustError):
            operation()


@pytest.mark.parametrize("suffix", [":stream", ".", " "])
def test_windows_path_aliases_are_rejected(tmp_path, suffix):
    path = tmp_path / "file"
    path.write_bytes(b"{}")
    with pytest.raises(ft.FileTrustError):
        read(str(path) + suffix)
