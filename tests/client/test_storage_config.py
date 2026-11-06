import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from cyberthunder.client import files
from cyberthunder.client.config import ClientProfile, endpoint
from cyberthunder.client.errors import ClientError, decode
from cyberthunder.client.store import TokenStore


@pytest.mark.parametrize("url", ["http://host/token", "https://u:secret@host/token", "https://host/token?next=x",
    "https://host/token#secret", "https://host/%2e%2e/token", "https://host/a/../token", "https://host//token",
    "https://*.host/token", "https://host:0/token", "https://host/token\nsecret"])
def test_ambiguous_endpoint_rejected(url):
    with pytest.raises(ClientError):
        endpoint(url)


@pytest.mark.parametrize("changes", [{"secret": "NEVER-PRINT"}, {"version": True}, {"client_id": "ct-api"},
    {"scope": "openid openid"}, {"token_endpoint": "https://other.test/token"}, {"api_base_url": "https://host/other"}])
def test_profile_is_exact_and_non_secret(profile_factory, changes):
    with pytest.raises(ClientError) as error:
        profile_factory(**changes)
    assert "NEVER-PRINT" not in str(error.value)


def test_duplicate_and_depth_bounded_json():
    for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":' + b'['*13 + b'0' + b']'*13 + b'}'):
        with pytest.raises(ClientError):
            decode(raw)


def test_store_roundtrip_tombstone_and_private_file(store):
    with store.locked():
        record = store.empty()
        record.update(phase="ready", session={"fixture_secret": "private-fixture"})
        store.save(record)
        assert store.load() == record
        cleared = store.empty(record)
        store.save(cleared)
        assert store.load()["generation"] != record["generation"]
    assert "private-fixture" not in store.data.read_text()
    assert not list(store.root.glob(".client-*"))
    if os.name == "posix":
        assert store.data.stat().st_mode & 0o777 == 0o600


def test_no_publish_without_lock_and_profile_binding(store):
    with pytest.raises(ClientError):
        store.save({})
    with store.locked():
        record = store.empty()
        store.save(record)
        record["profile"] = "0"*64
        store.save(record)
        with pytest.raises(ClientError, match="client_store_invalid"):
            store.load()


def test_interrupted_refresh_cannot_redeem_old_token(store):
    with store.locked():
        record = store.empty()
        record.update(phase="refreshing", session={"refresh_token": "never-replay"})
        store.save(record)
    with TokenStore(store.profile, root=store.root).locked() as second:
        assert second.load()["phase"] == "empty"
    assert "never-replay" not in store.data.read_text()


def test_failed_publication_preserves_previous_generation_and_removes_temporary(store, monkeypatch):
    with store.locked():
        record = store.empty()
        store.save(record)
        previous = store.data.read_bytes()
        attempted = []
        def fail(*args, **kwargs):
            attempted.append(True)
            raise OSError("fixture publication failed")
        monkeypatch.setattr("cyberthunder.client.store.os.replace", fail)
        with pytest.raises(ClientError):
            store.save({**record, "phase": "ready", "session": {"access_token": "new-private"}})
        assert attempted == [True]
        assert store.data.read_bytes() == previous
        assert not list(store.root.glob(".client-*"))


def test_file_privacy_is_native_and_no_silent_repair(store):
    with store.locked():
        store.save(store.empty())
    if os.name == "nt":
        from tests.windows_acl import protected_aces, set_dacl
        set_dacl(store.data, protected_aces() + "(A;;GR;;;S-1-1-0)")
    else:
        store.data.chmod(0o644)
    before = store.data.read_bytes()
    with store.locked():
        with pytest.raises(ClientError):
            store.load()
    assert store.data.read_bytes() == before


def test_hardlinked_token_file_is_refused(store):
    with store.locked():
        store.save(store.empty())
    os.link(store.data, store.root / "copy")
    with store.locked():
        with pytest.raises(ClientError):
            store.load()


def test_repository_and_node_state_are_not_token_locations(tmp_path, profile, monkeypatch):
    (tmp_path / ".git").write_text("fixture")
    with pytest.raises(ClientError, match="outside_repository"):
        with TokenStore(profile.digest, root=tmp_path / "client").locked():
            pass
    (tmp_path / ".git").unlink()
    monkeypatch.setenv("CT_STATE_DIR", str(tmp_path))
    with pytest.raises(ClientError, match="outside_state"):
        with TokenStore(profile.digest, root=tmp_path / "client").locked():
            pass


def test_native_cross_process_lock_serializes_store(store):
    script = ('import sys\nfrom cyberthunder.client.store import TokenStore\n'
              'with TokenStore(sys.argv[2],root=sys.argv[1]).locked():\n print("acquired",flush=True)\n')
    with store.locked():
        process = subprocess.Popen([sys.executable, "-c", script, str(store.root), store.profile],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            with pytest.raises(subprocess.TimeoutExpired):
                process.communicate(timeout=0.4)
        except BaseException:
            process.kill()
            process.communicate()
            raise
    stdout, stderr = process.communicate(timeout=8)
    assert process.returncode == 0 and stdout.strip() == "acquired" and not stderr


@pytest.mark.skipif(os.name != "posix", reason="native Linux symlink and mode checks")
def test_linux_symlink_and_unsafe_parent(store, tmp_path):
    store.root.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ClientError):
        with store.locked():
            pass
    store.root.unlink()
    tmp_path.chmod(0o777)
    with pytest.raises(ClientError):
        with store.locked():
            pass


@pytest.mark.skipif(os.name != "nt", reason="native Windows inherited DACL privacy")
def test_windows_inherited_public_read_never_receives_token_bytes(store):
    from tests.windows_acl import set_dacl, protected_aces
    store.root.mkdir()
    set_dacl(store.root, protected_aces(directory=True) + "(A;OICIIO;GR;;;S-1-1-0)")
    with pytest.raises(ClientError):
        with store.locked():
            store.save(store.empty())
    assert not store.data.exists()
