"""Mock CredRead buffers only; never enumerate, read or write existing vault entries."""
import ctypes as c
from dataclasses import replace
import os
import traceback
import uuid

import pytest

from cyberthunder.control.principal import principal_scope
from cyberthunder.security import _wincred as wc, secret_resolver as sr
from tests.security.test_secret_resolver import account, no_canary


class FakeNative:
    def __init__(self, name, username, value):
        self.value = c.create_string_buffer(value.encode("utf-16-le"))
        self.item = wc._Credential()
        self.item.Type, self.item.TargetName, self.item.UserName = 1, name, username
        self.item.Persist = 2
        self.item.CredentialBlobSize = len(value.encode("utf-16-le"))
        self.item.CredentialBlob = c.cast(self.value, c.c_void_p)
        self.calls, self.freed = [], []
        self.identity = "fixture-process-logon"

    def logon(self):
        return self.identity

    def CredReadW(self, name, kind, flags, pointer):
        self.calls.append((name, kind, flags))
        c.cast(pointer, c.POINTER(c.POINTER(wc._Credential)))[0] = c.pointer(self.item)
        return True

    def CredFree(self, pointer):
        self.freed.append(bool(pointer))


@pytest.fixture
def native(account, monkeypatch):
    a = account
    name = sr.windows_target_name(a.binding, a.person, a.target)
    fake = FakeNative(name, a.binding.username, a.canary)
    monkeypatch.setattr(wc, "_api", lambda: fake)
    return fake, name


def test_exact_generic_read_matches_user_and_never_caches_value(account, native):
    a = account
    fake, name = native
    resolver = sr.SecretResolver({"SCOPED": sr.WindowsCredential(name)}, security_mode="fleet", auth_mode="oidc")
    with principal_scope(a.person):
        use = resolver.bind(a.binding, principal=a.person, target=a.target, purpose="scan", guard=a.guard, on_event=a.audit)
        for _ in range(2):
            with use.lease() as lease:
                assert lease.secret.reveal() == a.canary
    assert fake.calls == [(name, 1, 0), (name, 1, 0)]
    assert fake.freed == [True, True]
    no_canary(a.ctx.audit.path.read_text(), a.canary)
    assert name not in a.ctx.audit.path.read_text()
    assert all(e.backend == "wincred" for e in a.events)


@pytest.mark.parametrize("field,value", [
    ("UserName", "different-account"), ("TargetName", "different-target"), ("Type", 2), ("Flags", 4),
    ("TargetAlias", "fallback"), ("Persist", 3), ("AttributeCount", 1),
    ("CredentialBlobSize", 2562), ("CredentialBlobSize", 1), ("CredentialBlobSize", 0), ("CredentialBlob", None),
])
def test_native_response_mismatch_is_rejected_before_copy(account, native, monkeypatch, field, value):
    fake, name = native
    setattr(fake.item, field, value)
    monkeypatch.setattr(wc.c, "string_at", lambda *_: pytest.fail("mismatched vault value copied"))
    with pytest.raises(ValueError) as error:
        wc.read_password(name, account.binding.username)
    assert fake.freed == [True]
    assert error.value.__context__ is None
    no_canary(str(error.value), account.canary)


def test_changed_logon_and_impersonation_fail_closed(account, native, monkeypatch):
    fake, name = native
    states = iter(["first-logon", "different-logon"])
    monkeypatch.setattr(fake, "logon", lambda: next(states))
    with pytest.raises(ValueError):
        wc.read_password(name, account.binding.username)
    assert fake.freed == [True]
    fake.calls.clear()
    def impersonated():
        raise ValueError("impersonation")
    monkeypatch.setattr(fake, "logon", impersonated)
    with pytest.raises(ValueError):
        wc.read_password(name, account.binding.username)
    assert fake.calls == []


@pytest.mark.parametrize("blob", [b"\0\0", b"\0\xd8"])
def test_native_blob_rejects_nul_and_invalid_unicode(account, native, blob):
    fake, name = native
    fake.value = c.create_string_buffer(blob)
    fake.item.CredentialBlob = c.cast(fake.value, c.c_void_p)
    fake.item.CredentialBlobSize = len(blob)
    with pytest.raises(ValueError) as error:
        wc.read_password(name, account.binding.username)
    assert error.value.__context__ is None and fake.freed == [True]


def test_missing_native_entry_never_tries_another_store(account, native, monkeypatch):
    fake, name = native
    def missing(target, kind, flags, pointer):
        fake.calls.append((target, kind, flags))
        return False
    monkeypatch.setattr(fake, "CredReadW", missing)
    with pytest.raises(ValueError):
        wc.read_password(name, account.binding.username)
    assert fake.calls == [(name, 1, 0)] and fake.freed == []


@pytest.mark.parametrize("change", ["subject", "action", "generation", "username"])
def test_native_names_are_scoped_to_account_action_and_target_generation(account, native, change):
    a = account
    _, original = native
    person, binding, target = a.person, a.binding, a.target
    if change == "subject":
        person = replace(person, subject="same-display-different-subject")
        binding = replace(binding, provenance=replace(binding.provenance, subject=person.subject))
    elif change == "action":
        binding = replace(binding, provenance=replace(binding.provenance, action="apply"))
    elif change == "generation":
        target = replace(target, authorization_id=uuid.uuid4().hex)
    else:
        binding = replace(binding, username="different-remote-user")
    assert sr.windows_target_name(binding, person, target) != original
    resolver = sr.SecretResolver({"SCOPED": sr.WindowsCredential(original)}, security_mode="fleet", auth_mode="oidc")
    with principal_scope(a.person), pytest.raises(sr.SecretResolutionError):
        resolver.bind(binding, principal=person, target=target, purpose=binding.provenance.action, guard=a.guard, on_event=a.audit)


@pytest.mark.skipif(os.name != "nt", reason="native Windows token and CredReadW ABI with mocked credential data")
def test_native_windows_abi_and_current_logon_with_mocked_credread(account, native, monkeypatch):
    # Loading DLL functions and inspecting this process token reads no credentials.
    fake, name = native
    actual = wc._Native()
    assert actual.logon() == actual.logon()
    monkeypatch.setattr(actual, "CredReadW", fake.CredReadW)
    monkeypatch.setattr(actual, "CredFree", fake.CredFree)
    monkeypatch.setattr(wc, "_api", lambda: actual)
    assert wc.read_password(name, account.binding.username) == account.canary.encode()
    assert fake.calls == [(name, 1, 0)] and fake.freed == [True]


@pytest.mark.skipif(os.name != "nt", reason="native Windows thread impersonation with mocked credential data")
def test_native_windows_rejects_thread_impersonation_before_credread(account, native, monkeypatch):
    fake, name = native
    actual = wc._Native()
    monkeypatch.setattr(actual, "CredReadW", fake.CredReadW)
    monkeypatch.setattr(actual, "CredFree", fake.CredFree)
    monkeypatch.setattr(wc, "_api", lambda: actual)
    impersonate, revert = actual.adv.ImpersonateSelf, actual.adv.RevertToSelf
    impersonate.argtypes, impersonate.restype = [c.c_int], wc.w.BOOL
    revert.argtypes, revert.restype = [], wc.w.BOOL
    before = actual.logon()
    assert impersonate(2)  # SecurityImpersonation, using only this process's identity.
    try:
        with pytest.raises(ValueError) as error:
            wc.read_password(name, account.binding.username)
        assert error.value.__context__ is None
        assert not fake.calls and not fake.freed
    finally:
        assert revert()
    assert actual.logon() == before


@pytest.mark.parametrize("failure", ["read", "copy", "postread_token"])
def test_native_exception_frees_canary_buffer_and_sanitizes(account, native, monkeypatch, failure):
    fake, name = native

    def broken(*args):
        raise RuntimeError(account.canary)

    if failure == "read":
        original = fake.CredReadW

        def read(*args):
            original(*args)
            broken()

        monkeypatch.setattr(fake, "CredReadW", read)
    elif failure == "copy":
        monkeypatch.setattr(wc.c, "string_at", broken)
    else:
        calls = []

        def logon():
            if calls:
                broken()
            calls.append(True)
            return fake.identity

        monkeypatch.setattr(fake, "logon", logon)
    with pytest.raises(ValueError) as error:
        wc.read_password(name, account.binding.username)
    assert fake.freed == [True]
    assert error.value.__context__ is None and error.value.__cause__ is None
    no_canary("".join(traceback.format_exception(error.value)), account.canary)
