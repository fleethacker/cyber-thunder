"""Persisted-scope and nonsecret-binding regressions; no target access."""
from copy import deepcopy
import json
import os
from pathlib import Path

import pytest

from cyberthunder.inventory.targets import ScopeViolation, Target
from cyberthunder.remediation import dependencies as dep, dependencies_binding as binding, dependencies_io as io
from cyberthunder.remediation.engine import EngineError

from .test_dependencies import ACTOR, HOST, seed, wire


@pytest.mark.parametrize("when", ["before", "factory", "read", "close"])
@pytest.mark.parametrize("problem", ["missing", "unreadable", "invalid"])
def test_persisted_inventory_required_at_every_guard(ctx, tmp_path, monkeypatch, when, problem):
    proposal, _, root, _ = seed(ctx, tmp_path)
    calls, transport = wire(ctx, monkeypatch, root)
    path = ctx.inventory.path
    original_open = binding.os.open

    def invalidate():
        if problem == "missing":
            path.unlink()
        elif problem == "invalid":
            path.write_text('{"targets":"not-an-inventory"}', encoding="utf-8")
        else:
            def denied(value, *args, **kwargs):
                if Path(value) == path:
                    raise PermissionError("synthetic-private-error")
                return original_open(value, *args, **kwargs)
            monkeypatch.setattr(binding.os, "open", denied)

    if when == "before":
        invalidate()
        monkeypatch.setattr(ctx, "transport_for", lambda _: pytest.fail("opened with unverifiable scope"))
    elif when == "factory":
        def factory(_):
            invalidate()
            return transport
        monkeypatch.setattr(ctx, "transport_for", factory)
    elif when == "close":
        monkeypatch.setattr(transport, "close", invalidate)
    else:
        original_read = io.read_command
        def read(*args, **kwargs):
            result = original_read(*args, **kwargs)
            invalidate()
            return result
        monkeypatch.setattr(io, "read_command", read)
    with pytest.raises(ScopeViolation, match="persisted inventory is unverifiable") as exc:
        dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)
    assert "synthetic-private-error" not in str(exc.value)
    assert len(calls) == (0 if when in ("before", "factory") else 1)
    assert not any(r["action"] == "remediation.dependencies" for r in ctx.audit.records())


@pytest.mark.parametrize("problem", ["no_path", "missing_target", "false_scope", "string_scope",
                                     "missing_scope", "duplicate", "duplicate_key", "aliases",
                                     "oversized", "directory", "invalid_option", "deep"])
def test_current_target_rejects_invalid_persisted_snapshot(ctx, tmp_path, problem):
    seed(ctx, tmp_path)
    target = ctx.inventory.get(HOST).to_dict()
    path = ctx.inventory.path
    data = {"targets": [target]}
    if problem == "no_path":
        ctx.inventory.path = None
    elif problem == "missing_target":
        data["targets"] = []
    elif problem == "false_scope":
        target["in_scope"] = False
    elif problem == "string_scope":
        target["in_scope"] = "false"
    elif problem == "missing_scope":
        target.pop("in_scope")
    elif problem == "duplicate":
        data["targets"].append(deepcopy(target))
    elif problem == "invalid_option":
        target["options"]["key_file"] = {"not": "a path"}
    if problem == "duplicate_key":
        path.write_text('{"targets":[],"targets":[' + json.dumps(target) + ']}', encoding="utf-8")
    elif problem == "aliases":
        path.write_text("targets: &scope [*scope]\n", encoding="utf-8")
    elif problem == "oversized":
        path.write_bytes(b" " * (binding.MAX_INVENTORY_BYTES + 1))
    elif problem == "directory":
        path.unlink()
        path.mkdir()
    elif problem == "deep":
        path.write_text('[' * 100 + ']' * 100, encoding="utf-8")
    else:
        path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ScopeViolation):
        dep.current_target(ctx, HOST)


@pytest.mark.parametrize("side", ["cached", "disk"])
def test_current_target_rejects_connection_disagreement_even_with_unchanged_stat(ctx, tmp_path, side):
    seed(ctx, tmp_path)
    if side == "cached":
        ctx.inventory.get(HOST).address = "192.0.2.88"
    else:
        path = ctx.inventory.path
        before = path.stat()
        raw = path.read_bytes()
        assert b"192.0.2.99" in raw
        path.write_bytes(raw.replace(b"192.0.2.99", b"192.0.2.88"))
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        assert ctx.inventory._file_sig() == ctx.inventory._sig
    with pytest.raises(EngineError, match="cached and persisted"):
        dep.current_target(ctx, HOST)


def test_current_target_is_detached_and_refreshes_persisted_scope(ctx, tmp_path):
    seed(ctx, tmp_path)
    target = dep.current_target(ctx, HOST)
    target.options["context"] = "detached"
    assert "context" not in dep.current_target(ctx, HOST).options
    path = ctx.inventory.path
    data = {"targets": [ctx.inventory._targets[HOST].to_dict()]}
    data["targets"][0]["in_scope"] = False
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ScopeViolation):
        dep.current_target(ctx, HOST)


def test_current_target_reads_json_and_rejects_duplicate_keys(ctx, tmp_path):
    seed(ctx, tmp_path)
    path = tmp_path / "inventory.json"
    row = ctx.inventory.get(HOST).to_dict()
    path.write_text(json.dumps({"targets": [row]}), encoding="utf-8")
    ctx.inventory.path = path
    assert dep.current_target(ctx, HOST).id == HOST
    path.write_text('{"targets":[],"targets":[' + json.dumps(row) + ']}', encoding="utf-8")
    with pytest.raises(ScopeViolation):
        dep.current_target(ctx, HOST)


@pytest.mark.parametrize("field", ["key_file", "kubeconfig", "ca_trust_path", "credential_ref"])
@pytest.mark.parametrize("problem", ["missing", "unreadable", "oversized", "directory", "symlink"])
def test_required_files_fail_unverifiable(tmp_path, monkeypatch, field, problem):
    path = tmp_path / "synthetic-private-reference"
    if problem == "directory":
        path.mkdir()
    elif problem == "symlink":
        real = tmp_path / "regular"
        real.write_bytes(b"synthetic content")
        try:
            path.symlink_to(real)
        except OSError:
            pytest.skip("symlink creation unavailable on this host")
    elif problem != "missing":
        path.write_bytes(b"x" * (binding.MAX_FILE_BYTES + 1) if problem == "oversized" else b"synthetic content")
    if problem == "unreadable":
        original = binding.os.open
        def denied(value, *args, **kwargs):
            if Path(value) == path:
                raise PermissionError("synthetic-private-error")
            return original(value, *args, **kwargs)
        monkeypatch.setattr(binding.os, "open", denied)
    target = Target("host", "host", "linux", transport="ssh")
    if field == "credential_ref":
        target.credential_ref = str(path)
    else:
        target.options[field] = str(path)
    with pytest.raises(EngineError, match="binding is unverifiable") as exc:
        dep.target_binding_sha256(target)
    assert "synthetic-private" not in str(exc.value)


def test_environment_and_unknown_options_are_not_a_password_guess_oracle(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = Target("host", "host", "linux", transport="ssh", credential_ref="ordinary-label")
    hashes = []
    for candidate in (None, "synthetic-one", "synthetic-two", "synthetic-three"):
        if candidate is None:
            monkeypatch.delenv("CT_CRED_ordinary-label", raising=False)
        else:
            monkeypatch.setenv("CT_CRED_ordinary-label", candidate)
        target.options.update(password=candidate, credential=candidate, token=candidate,
                              nested={"client-secret": candidate})
        hashes.append(dep.target_binding_sha256(target))
    assert len(set(hashes)) == 1
    assert not (tmp_path / "ordinary-label").exists()


@pytest.mark.parametrize("field", ["key_file", "kubeconfig", "ca_trust_path"])
def test_file_contents_never_enter_published_binding(tmp_path, monkeypatch, field):
    path = tmp_path / "synthetic-file"
    path.write_bytes(b"synthetic-secret-one")
    target = Target("host", "host", "linux", options={field: str(path)})
    original = binding.os.read
    hashes = []
    # Substitute same-length read bytes with actual stat/identity fixed. Hashing
    # file contents would distinguish guesses; checking metadata/readability won't.
    for candidate in (b"synthetic-secret-one", b"synthetic-secret-two", b"synthetic-secret-xxx"):
        def read(fd, count):
            block = original(fd, count)
            return candidate if block else block
        monkeypatch.setattr(binding.os, "read", read)
        hashes.append(dep.target_binding_sha256(target))
    assert len(set(hashes)) == 1


def test_required_file_changed_during_read_is_unverifiable(tmp_path, monkeypatch):
    path = tmp_path / "key-file"
    path.write_bytes(b"synthetic content")
    target = Target("host", "host", "linux", options={"key_file": str(path)})
    original = binding.os.read
    def read(fd, count):
        block = original(fd, count)
        if block:
            path.write_bytes(b"changed")
        return block
    monkeypatch.setattr(binding.os, "read", read)
    with pytest.raises(EngineError, match="binding is unverifiable"):
        dep.target_binding_sha256(target)


def test_required_file_metadata_change_and_disappearance(ctx, tmp_path, monkeypatch):
    proposal, _, root, _ = seed(ctx, tmp_path)
    path = tmp_path / "key-file"
    path.write_bytes(b"synthetic content")
    ctx.inventory.get(HOST).options["key_file"] = str(path)
    ctx.inventory.save()
    before = dep.target_binding_sha256(dep.current_target(ctx, HOST))
    path.write_bytes(b"synthetic changed content")
    assert dep.target_binding_sha256(dep.current_target(ctx, HOST)) != before
    _, transport = wire(ctx, monkeypatch, root)
    monkeypatch.setattr(transport, "close", path.unlink)
    with pytest.raises(EngineError, match="binding is unverifiable"):
        dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)
    assert not any(r["action"] == "remediation.dependencies" for r in ctx.audit.records())


def test_rotation_is_explicitly_unattested_in_packet(ctx, tmp_path, monkeypatch):
    proposal, _, root, _ = seed(ctx, tmp_path)
    _, transport = wire(ctx, monkeypatch, root)
    monkeypatch.setattr(transport, "close", lambda: monkeypatch.setenv("CT_CRED_private-ref", "synthetic-rotation"))
    packet = dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)
    assert not packet["complete"]
    assert any("credential rotation" in text and "effective privileges" in text and "not attested" in text
               for text in packet["unknowns"])
    assert "synthetic-rotation" not in json.dumps(packet)
