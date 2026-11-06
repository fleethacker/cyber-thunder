"""Real descriptor-relative filesystem attacks against disposable secret mounts."""
from dataclasses import replace
import os
import stat
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest

from cyberthunder.control.principal import principal_scope
from cyberthunder.security import secret_resolver as sr
from tests.security.test_secret_resolver import account


pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX dir_fd, ownership, modes and Kubernetes projection layout")


def projected(a, *, reader_gid=None):
    root = a.path.parent
    generation = root / "..2026_11_05_01"
    generation.mkdir(mode=0o700)
    a.path.rename(generation / "password")
    a.path.symlink_to("..data/password")
    (root / "..data").symlink_to(generation.name, target_is_directory=True)
    source = sr.MountedSecret(str(root), "password", layout="kubernetes", reader_gid=reader_gid)
    return replace(a.use, source=source), generation / "password"


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o666, 0o604, 0o601])
def test_regular_secret_rejects_group_or_public_permissions(account, mode):
    a = account
    a.path.chmod(mode)
    with principal_scope(a.person), pytest.raises(sr.SecretResolutionError), a.use.lease():
        pytest.fail("exposed credential read")


@pytest.mark.parametrize("attack", ["writable_parent", "fifo", "foreign_owner"])
def test_untrusted_nodes_fail_before_read(account, monkeypatch, attack):
    a = account
    if attack == "writable_parent":
        a.path.parent.chmod(0o777)
    elif attack == "fifo":
        a.path.unlink()
        os.mkfifo(a.path, 0o600)
    else:
        original = sr._protect
        def foreign(info, **kw):
            if not kw.get("directory"):
                from types import SimpleNamespace
                info = SimpleNamespace(st_uid=os.geteuid() + 10000)
            return original(info, **kw)
        monkeypatch.setattr(sr, "_protect", foreign)
    monkeypatch.setattr(sr.os, "read", lambda *_: pytest.fail("untrusted bytes read"))
    with principal_scope(a.person), pytest.raises(sr.SecretResolutionError), a.use.lease():
        pytest.fail("untrusted node accepted")


def test_projection_requires_explicit_layout_and_accepts_atomic_rotation(account):
    a = account
    use, value = projected(a)
    with principal_scope(a.person):
        with pytest.raises(sr.SecretResolutionError), a.use.lease():
            pytest.fail("regular profile followed a projection")
        with use.lease() as lease:
            assert lease.secret.reveal() == a.canary
        generation = value.parent.with_name("..2026_11_05_02")
        generation.mkdir(mode=0o700)
        rotated = "new-fixture-" + uuid.uuid4().hex
        (generation / "password").write_text(rotated, encoding="utf-8")
        (generation / "password").chmod(0o600)
        temporary = a.path.parent / "..data_tmp"
        temporary.symlink_to(generation.name)
        temporary.replace(a.path.parent / "..data")
        with use.lease() as lease:
            assert lease.secret.reveal() == rotated


@pytest.mark.parametrize("attack", ["absolute_data", "escaping_data", "escaping_key", "generation_redirect", "public_value", "hardlink"])
def test_projection_rejects_redirects_and_exposed_values(account, attack):
    a = account
    use, value = projected(a)
    root = a.path.parent
    if attack in {"absolute_data", "escaping_data"}:
        (root / "..data").unlink()
        (root / "..data").symlink_to(str(value.parent) if attack == "absolute_data" else "../elsewhere")
    elif attack == "escaping_key":
        a.path.unlink()
        a.path.symlink_to("../unrelated/password")
    elif attack == "generation_redirect":
        redirected = value.parent.with_name("..redirected")
        value.parent.rename(redirected)
        value.parent.symlink_to(redirected, target_is_directory=True)
    elif attack == "public_value":
        value.chmod(0o444)
    else:
        os.link(value, root / "extra-link")
    with principal_scope(a.person), pytest.raises(sr.SecretResolutionError), use.lease():
        pytest.fail("unsafe projection read")


def test_reader_group_requires_explicit_matching_dedicated_gid(account):
    a = account
    use, value = projected(a, reader_gid=os.getegid())
    value.chmod(0o440)
    with principal_scope(a.person):
        with use.lease() as lease:
            assert lease.secret.reveal() == a.canary
        for gid in (None, os.getegid() + 10000):
            denied = replace(use, source=replace(use.source, reader_gid=gid))
            with pytest.raises(sr.SecretResolutionError), denied.lease():
                pytest.fail("implicit group trust")
        value.chmod(0o444)
        with pytest.raises(sr.SecretResolutionError), use.lease():
            pytest.fail("world-readable projected secret accepted")


@pytest.mark.parametrize("projected,readonly,owner,accepted", [
    (True, True, 0, True), (True, False, 0, False),
    (False, True, 0, False), (True, True, 99999, False),
])
def test_only_root_owned_readonly_projection_can_relax_directory_write_bits(projected, readonly, owner, accepted):
    node = SimpleNamespace(st_uid=owner, st_mode=stat.S_IFDIR | 0o777)
    if accepted:
        sr._protect(node, directory=True, projected=projected, readonly=readonly)
    else:
        with pytest.raises(ValueError):
            sr._protect(node, directory=True, projected=projected, readonly=readonly)


@pytest.mark.parametrize("change", ["replace_file", "write_file", "rotate_projection", "replace_parent"])
def test_midread_identity_changes_are_refused(account, monkeypatch, change):
    a = account
    use, value = projected(a) if change == "rotate_projection" else (a.use, a.path)
    original = os.read
    def changed(fd, maximum):
        result = original(fd, maximum)
        if change == "replace_file":
            value.unlink()
            value.write_text(a.canary, encoding="utf-8")
            value.chmod(0o600)
        elif change == "write_file":
            value.write_text("altered-" + uuid.uuid4().hex, encoding="utf-8")
        elif change == "replace_parent":
            value.parent.rename(value.parent.with_name("moved"))
            value.parent.mkdir(mode=0o700)
        else:
            data = a.path.parent / "..data"
            data.unlink()
            data.symlink_to("..other-generation")
        return result
    monkeypatch.setattr(sr.os, "read", changed)
    with principal_scope(a.person), pytest.raises(sr.SecretResolutionError), use.lease():
        pytest.fail("changed file identity accepted")
