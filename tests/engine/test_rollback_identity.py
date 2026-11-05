"""Endpoint declarations bind actions without exposing hashes of credential values."""
import copy
import json
import os
from pathlib import Path

import pytest

from cyberthunder.control.approvals import ProposalState
from cyberthunder.remediation import rollback_guard, snapshot
from .conftest import HOST
from .test_engine import SAILOR, root_login_proposal


def test_unknown_secret_options_and_environment_do_not_affect_public_binding(make_ctx, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    target = ctx.inventory.get(HOST)
    target.credential_ref = "TEST_REFERENCE"
    target.options.update(password="private-one", config={"token": "private-two"},
                          password_env="PRIVATE_ENV_NAME", seed_config="private-three")
    monkeypatch.setenv("CT_CRED_TEST_REFERENCE", "private-four")
    monkeypatch.setenv("PRIVATE_ENV_NAME", "private-five")
    original = rollback_guard.identity(target)
    target.options.update(password="changed-one", config={"token": "changed-two"},
                          password_env="CHANGED_ENV_NAME", seed_config="changed-three")
    monkeypatch.setenv("CT_CRED_TEST_REFERENCE", "changed-four")
    assert rollback_guard.identity(target) == original
    assert rollback_guard.digest(rollback_guard.identity(target)) == rollback_guard.digest(original)
    encoded = json.dumps(original)
    assert all(value not in encoded for value in ("private-", "changed-", "PRIVATE_ENV_NAME", "CHANGED_ENV_NAME"))
    ctx.inventory.save()
    digest = rollback_guard.digest
    def inspect_digest(value):
        assert "changed-" not in json.dumps(value, default=str)
        return digest(value)
    monkeypatch.setattr(rollback_guard, "digest", inspect_digest)
    p = root_login_proposal(ctx)
    assert ctx.engine.execute(p.id, actor=SAILOR).state is ProposalState.VERIFIED
    evidence = snapshot.load_result(ctx.store.snapshots_dir / p.id, "execution")
    assert evidence["target"] == original
    assert "changed-" not in json.dumps(list(ctx.audit.records()))
    # Credential rotation is deliberately not attested by this endpoint binding.
    target.options["password"] = "rotated-value"
    ctx.inventory.save()
    assert ctx.engine.rollback(p.id, actor=SAILOR).state is ProposalState.ROLLED_BACK
    assert any("no credential-rotation" in note for note in ctx.engine.rollback_status(p.id)["limitations"])


@pytest.mark.parametrize("key,value", [("fixture_dir", "other"), ("config_path", "other"),
                                      ("key_file", "other"), ("kubeconfig", "other"),
                                      ("context", "other"), ("kubectl", "other"),
                                      ("ca_trust_path", "other"), ("ssl", True),
                                      ("transport", "kerberos"), ("cert_validation", "ignore")])
def test_nonsecret_connection_declarations_change_binding(make_ctx, key, value):
    target = copy.deepcopy(make_ctx(auto_propose=False).inventory.get(HOST))
    before = rollback_guard.identity(target)
    target.options[key] = value
    assert rollback_guard.identity(target) != before


@pytest.mark.parametrize("damage", ["missing", "unreadable", "metadata_changed"])
def test_required_connection_file_change_blocks_before_transport(make_ctx, fake_adapter, monkeypatch, tmp_path, damage):
    ctx = make_ctx(auto_propose=False)
    key = tmp_path / "connection-key"
    key.write_bytes(b"private-key-material")
    target = ctx.inventory.get(HOST)
    target.transport = "ssh"
    target.options["key_file"] = str(key)
    ctx.inventory.save()
    monkeypatch.setattr(ctx, "transport_for", fake_adapter.make_transport)
    p = root_login_proposal(ctx)
    ctx.engine.execute(p.id, actor=SAILOR)
    if damage == "missing":
        key.unlink()
    elif damage == "metadata_changed":
        key.write_bytes(b"different-private-key-material")
    else:
        original_open = Path.open
        def denied(path, *args, **kwargs):
            if path == key:
                raise PermissionError("private diagnostic")
            return original_open(path, *args, **kwargs)
        monkeypatch.setattr(Path, "open", denied)
    count = len(fake_adapter.transports_made)
    with pytest.raises(rollback_guard.RollbackBlocked) as error:
        ctx.engine.rollback(p.id, actor=SAILOR)
    assert "private" not in str(error.value)
    assert ctx.engine.rollback_status(p.id)["status"] == "blocked"
    assert len(fake_adapter.transports_made) == count
    assert ctx.gate.get(p.id).state is ProposalState.VERIFIED


def test_connection_file_contents_are_never_hashed(make_ctx, tmp_path, monkeypatch):
    target = copy.deepcopy(make_ctx(auto_propose=False).inventory.get(HOST))
    key = tmp_path / "connection-key"
    key.write_bytes(b"first-secret")
    target.transport = "ssh"
    target.options["key_file"] = str(key)
    info = key.stat()
    original = rollback_guard.identity(target)
    key.write_bytes(b"other-secret")  # equal length; metadata cannot attest content or privilege
    os.utime(key, ns=(info.st_atime_ns, info.st_mtime_ns))
    monkeypatch.setattr(Path, "read_bytes", lambda *args: pytest.fail("identity read credential bytes"))
    monkeypatch.setattr(Path, "read_text", lambda *args, **kwargs: pytest.fail("identity read credential text"))
    assert rollback_guard.identity(target) == original


def test_nested_data_in_allowlisted_declaration_is_not_hashed(make_ctx):
    target = make_ctx(auto_propose=False).inventory.get(HOST)
    target.options["context"] = {"token": "private-value"}
    with pytest.raises(rollback_guard.RollbackBlocked, match="must be a string") as error:
        rollback_guard.identity(target)
    assert "private-value" not in str(error.value)


def test_identity_changes_at_last_restore_boundary_block_without_result(make_ctx, fake_adapter, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    p = root_login_proposal(ctx)
    ctx.engine.execute(p.id, actor=SAILOR)
    append = ctx.audit.append
    def retarget(action, *args, **kwargs):
        result = append(action, *args, **kwargs)
        if action == "remediation.rollback_started":
            ctx.inventory.update(HOST, address="changed-endpoint")
            ctx.inventory.save()
        return result
    monkeypatch.setattr(ctx.audit, "append", retarget)
    monkeypatch.setattr(fake_adapter, "rollback", lambda *args: pytest.fail("restore ran after retargeting"))
    with pytest.raises(rollback_guard.RollbackBlocked, match="identity changed"):
        ctx.engine.rollback(p.id, actor=SAILOR)
    assert ctx.gate.get(p.id).state is ProposalState.VERIFIED
    assert snapshot.load_result(ctx.store.snapshots_dir / p.id, "rollback") is None
