"""Persisted scope cannot be replaced by cached inventory after deletion or corruption."""
import copy
import json
import os
import stat
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from cyberthunder.control.approvals import ProposalState
from cyberthunder.inventory.targets import Inventory, ScopeViolation, Target
from cyberthunder.remediation import rollback_guard, rollback_scope, snapshot
from cyberthunder.remediation.models import ApplyResult, HealthResult, VerifyResult
from .conftest import HOST
from .test_engine import SAILOR, root_login_proposal, sshd


def prepare(make_ctx, fake_adapter, monkeypatch, operation):
    ctx = make_ctx(auto_propose=False)
    p = root_login_proposal(ctx)
    if operation == "verify":
        monkeypatch.setattr(fake_adapter, "verify", lambda *args: VerifyResult(ok=True, rule_passed=None, health=HealthResult(True)))
        ctx.engine.execute(p.id, actor=SAILOR)
    elif operation == "rollback":
        ctx.engine.execute(p.id, actor=SAILOR)
    return ctx, p


@pytest.mark.parametrize("operation", ["execute", "verify", "rollback"])
@pytest.mark.parametrize("damage", ["missing", "malformed", "invalid_scope", "unreadable", "bad_shape"])
def test_persisted_inventory_failure_blocks_before_transport(make_ctx, fake_adapter, monkeypatch, operation, damage):
    ctx, p = prepare(make_ctx, fake_adapter, monkeypatch, operation)
    path = ctx.inventory.path
    # Cache is populated and would keep granting scope when the source disappears.
    assert ctx.inventory.assert_in_scope(HOST)
    if damage == "missing":
        path.unlink()
        assert ctx.inventory.assert_in_scope(HOST)  # reproduce the owning Inventory bug without changing it
    elif damage == "malformed":
        path.write_text("targets: [\ncredential: private-parser-value", encoding="utf-8")
    elif damage == "unreadable":
        def denied(*args, **kwargs):
            raise PermissionError("private-parser-value")
        monkeypatch.setattr(rollback_guard, "_inventory_text", denied)
    else:
        row = ctx.inventory.get(HOST).to_dict()
        row["in_scope"] = "true"
        path.write_text(json.dumps({"targets": [row]} if damage == "invalid_scope" else {"targets": {}}), encoding="utf-8")
    before, count, state = sshd(ctx), len(fake_adapter.transports_made), ctx.gate.get(p.id).state
    with pytest.raises(ScopeViolation, match="persisted inventory") as error:
        getattr(ctx.engine, operation)(p.id, actor=SAILOR)
    assert "private-parser-value" not in str(error.value)
    assert len(fake_adapter.transports_made) == count and sshd(ctx) == before
    assert ctx.gate.get(p.id).state is state
    assert any(r["action"] == "action.blocked" and r["subject"] == p.id for r in ctx.audit.records())
    status = ctx.engine.rollback_status(p.id)
    assert status["status"] == "blocked" and "private-parser-value" not in json.dumps(status)


@pytest.mark.parametrize("boundary", ["live_preflight", "rollback_started"])
def test_removal_during_manual_rollback_prevents_restore(make_ctx, fake_adapter, monkeypatch, boundary):
    ctx, p = prepare(make_ctx, fake_adapter, monkeypatch, "rollback")
    if boundary == "live_preflight":
        inspect = rollback_guard.inspect
        def disappear(*args, **kwargs):
            result = inspect(*args, **kwargs)
            if kwargs.get("live"):
                ctx.inventory.path.unlink()
            return result
        monkeypatch.setattr(rollback_guard, "inspect", disappear)
    else:
        append = ctx.audit.append
        def disappear(action, *args, **kwargs):
            result = append(action, *args, **kwargs)
            if action == "remediation.rollback_started":
                ctx.inventory.path.unlink()
            return result
        monkeypatch.setattr(ctx.audit, "append", disappear)
    monkeypatch.setattr(fake_adapter, "rollback", lambda *args: pytest.fail("restore ran after inventory disappeared"))
    before = sshd(ctx)
    with pytest.raises(ScopeViolation, match="persisted inventory"):
        ctx.engine.rollback(p.id, actor=SAILOR)
    assert sshd(ctx) == before and ctx.gate.get(p.id).state is ProposalState.VERIFIED
    assert snapshot.load_result(ctx.store.snapshots_dir / p.id, "rollback") is None
    assert ctx.engine.rollback_status(p.id)["status"] == "blocked"


def test_removal_during_capture_stops_apply(make_ctx, fake_adapter, monkeypatch):
    ctx, p = prepare(make_ctx, fake_adapter, monkeypatch, "execute")
    capture = fake_adapter.capture_before_state
    def disappear(*args):
        before = capture(*args)
        ctx.inventory.path.unlink()
        return before
    monkeypatch.setattr(fake_adapter, "capture_before_state", disappear)
    monkeypatch.setattr(fake_adapter, "apply", lambda *args: pytest.fail("apply ran without persisted scope"))
    before = sshd(ctx)
    with pytest.raises(ScopeViolation):
        ctx.engine.execute(p.id, actor=SAILOR)
    assert sshd(ctx) == before and ctx.gate.get(p.id).state is ProposalState.FAILED


def test_removal_during_connect_stops_verify(make_ctx, fake_adapter, monkeypatch):
    ctx, p = prepare(make_ctx, fake_adapter, monkeypatch, "verify")
    connect = ctx.transport_for
    def disappear(target):
        transport = connect(target)
        ctx.inventory.path.unlink()
        return transport
    monkeypatch.setattr(ctx, "transport_for", disappear)
    monkeypatch.setattr(fake_adapter, "verify", lambda *args: pytest.fail("verify ran without persisted scope"))
    with pytest.raises(ScopeViolation):
        ctx.engine.verify(p.id, actor=SAILOR)
    assert ctx.gate.get(p.id).state is ProposalState.APPLIED


def test_immediate_recovery_still_requires_persisted_scope(make_ctx, fake_adapter, monkeypatch):
    ctx, p = prepare(make_ctx, fake_adapter, monkeypatch, "execute")
    def fail(*args):
        ctx.inventory.path.unlink()
        return ApplyResult(ok=False, output="failed apply")
    monkeypatch.setattr(fake_adapter, "apply", fail)
    monkeypatch.setattr(fake_adapter, "rollback", lambda *args: pytest.fail("recovery ignored revoked persisted scope"))
    assert ctx.engine.execute(p.id, actor=SAILOR).state is ProposalState.FAILED
    assert snapshot.load_result(ctx.store.snapshots_dir / p.id, "rollback") is None


def test_explicit_memory_inventory_is_supported(make_ctx):
    ctx = make_ctx(auto_propose=False)
    ctx.inventory = Inventory(targets=[copy.deepcopy(t) for t in ctx.inventory.all()])
    assert ctx.inventory.path is None
    p = root_login_proposal(ctx)
    assert ctx.engine.execute(p.id, actor=SAILOR).state is ProposalState.VERIFIED
    assert ctx.engine.rollback(p.id, actor=SAILOR).state is ProposalState.ROLLED_BACK


def test_scope_reader_never_hashes_or_resolves_credentials(make_ctx, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    target = ctx.inventory.get(HOST)
    target.options.update(password="test-private-value", password_env="DO_NOT_RESOLVE_THIS_ENV")
    ctx.inventory.save()
    monkeypatch.setenv("DO_NOT_RESOLVE_THIS_ENV", "resolved-private-value")
    monkeypatch.setattr(rollback_guard, "digest", lambda *args: pytest.fail("scope proof hashed credential data"))
    assert rollback_guard.inventory_target(ctx, HOST).id == HOST


def test_inventory_disappears_during_cached_scope_check(make_ctx, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    read = rollback_guard._inventory_text
    def disappear(path):
        text = read(path)
        path.unlink()
        return text
    monkeypatch.setattr(rollback_guard, "_inventory_text", disappear)
    with pytest.raises(ScopeViolation, match="persisted inventory"):
        rollback_guard.inventory_target(ctx, HOST)


def test_nonregular_inventory_is_rejected_before_stream_read(make_ctx, monkeypatch):
    import stat
    ctx = make_ctx(auto_propose=False)
    original = os.fstat
    expected = ctx.inventory.path.stat()
    def nonregular(fd):
        info = original(fd)
        if (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino):
            return SimpleNamespace(st_mode=stat.S_IFIFO)
        return info
    monkeypatch.setattr(rollback_scope.os, "fstat", nonregular)
    with pytest.raises(ScopeViolation, match="persisted inventory"):
        rollback_guard.inventory_target(ctx, HOST)


def test_scope_proof_never_uses_production_cache_file_reader(make_ctx, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    monkeypatch.setattr(ctx.inventory, "assert_in_scope", lambda *args: pytest.fail("implicit inventory read"))
    assert rollback_guard.inventory_target(ctx, HOST).id == HOST


def scope_context(tmp_path, suffix=".json"):
    path = tmp_path / ("inventory" + suffix)
    target = Target("scope-test", "Scope fixture", "linux", transport="simulated")
    path.write_text(json.dumps({"targets": [target.to_dict()]}), encoding="utf-8")
    return SimpleNamespace(inventory=Inventory(path, targets=[target])), target


@pytest.mark.parametrize("suffix", [".json", ".yaml"])
@pytest.mark.parametrize("damage", ["duplicate_key", "duplicate_id", "missing_scope", "deep", "wide", "nan"])
def test_ambiguous_or_complex_inventory_is_unverifiable(tmp_path, suffix, damage):
    ctx, target = scope_context(tmp_path, suffix)
    row = target.to_dict()
    doc = {"targets": [row]}
    if damage == "duplicate_key":
        text = '{"targets":[],"targets":[' + json.dumps(row) + ']}'
    elif damage == "deep":
        text = '[' * (rollback_scope.MAX_DEPTH + 1) + ']' * (rollback_scope.MAX_DEPTH + 1)
    elif damage == "wide":
        row["options"] = {"data": [0] * (rollback_scope.MAX_PARSE_ITEMS + 1)}
        text = json.dumps(doc)
    else:
        if damage == "duplicate_id":
            doc["targets"].append(copy.deepcopy(row))
        elif damage == "missing_scope":
            row.pop("in_scope")
        else:
            row["port"] = float("nan")
        text = json.dumps(doc)
    ctx.inventory.path.write_text(text, encoding="utf-8")
    with pytest.raises(ScopeViolation, match="persisted inventory"):
        rollback_guard.inventory_target(ctx, target.id)


def test_yaml_aliases_and_duplicate_option_keys_are_rejected(tmp_path):
    ctx, target = scope_context(tmp_path, ".yaml")
    for text in ("targets: &items [*items]\n", "targets: []\ntargets: []\n"):
        ctx.inventory.path.write_text(text, encoding="utf-8")
        with pytest.raises(ScopeViolation):
            rollback_guard.inventory_target(ctx, target.id)


@pytest.mark.parametrize("kind", ["directory", "symlink", "oversized"])
def test_inventory_type_and_size_rejected_before_open(tmp_path, monkeypatch, kind):
    ctx, target = scope_context(tmp_path)
    path = ctx.inventory.path
    if kind == "directory":
        path.unlink()
        path.mkdir()
    elif kind == "symlink":
        real = tmp_path / "regular.json"
        path.rename(real)
        try:
            path.symlink_to(real)
        except OSError:
            if os.name != "nt":
                raise
            # A restricted Windows runner cannot create links. Exercise the
            # same lstat rejection; real replacement races run on POSIX.
            original_lstat = Path.lstat
            monkeypatch.setattr(Path, "lstat", lambda p: SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0)
                                if p == path else original_lstat(p))
    else:
        path.write_bytes(b" " * (rollback_scope.MAX_INVENTORY_BYTES + 1))
    monkeypatch.setattr(rollback_scope.os, "open", lambda *args: pytest.fail("invalid file opened"))
    with pytest.raises(ScopeViolation):
        rollback_guard.inventory_target(ctx, target.id)


def test_inventory_read_growth_is_bounded_and_descriptor_closes(tmp_path, monkeypatch):
    path = tmp_path / "inventory.json"
    path.write_bytes(b"{}")
    monkeypatch.setattr(rollback_scope, "MAX_INVENTORY_BYTES", 100)
    original_read, original_open = os.read, os.open
    opened, lengths = [], []
    def track_open(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        opened.append(fd)
        return fd
    def grow(fd, size):
        if not lengths:
            path.write_bytes(b" " * 10000)
        data = original_read(fd, size)
        lengths.append(len(data))
        return data
    monkeypatch.setattr(rollback_scope.os, "open", track_open)
    monkeypatch.setattr(rollback_scope.os, "read", grow)
    with pytest.raises(ValueError, match="size limit"):
        rollback_guard._inventory_text(path)
    assert sum(lengths) <= 101
    with pytest.raises(OSError):
        os.fstat(opened[0])


def test_private_cache_disk_difference_fails_without_hashing(tmp_path, monkeypatch):
    ctx, target = scope_context(tmp_path)
    target.options["password"] = "synthetic-private-cache"
    monkeypatch.setattr(rollback_guard, "digest", lambda *_: pytest.fail("scope values hashed"))
    with pytest.raises(ScopeViolation, match="without matching persisted inventory") as error:
        rollback_guard.inventory_target(ctx, target.id)
    assert "synthetic-private-cache" not in str(error.value)


def test_persisted_incarnation_difference_is_not_hidden_by_cache(tmp_path):
    ctx, target = scope_context(tmp_path)
    row = target.to_dict()
    row["added_at"] = "2000-01-01T00:00:00Z"
    ctx.inventory.path.write_text(json.dumps({"targets": [row]}), encoding="utf-8")
    with pytest.raises(ScopeViolation, match="without matching persisted inventory"):
        rollback_guard.inventory_target(ctx, target.id)


def test_json_quoted_delimiters_do_not_count_as_nesting(tmp_path):
    ctx, target = scope_context(tmp_path)
    target.options["declaration"] = '["{' * 30
    ctx.inventory.path.write_text(json.dumps({"targets": [target.to_dict()]}), encoding="utf-8")
    assert rollback_guard.inventory_target(ctx, target.id).id == target.id


@pytest.mark.skipif(os.name == "nt", reason="POSIX FIFO and O_NOFOLLOW semantics")
@pytest.mark.parametrize("replacement", ["existing_fifo", "fifo_at_open", "symlink_at_open"])
def test_fifo_or_link_replacement_refuses_promptly_and_releases_target_lock(tmp_path, replacement):
    # A subprocess watchdog makes a blocking-open regression fail without
    # hanging the test runner or retaining the target lock in this process.
    root = Path(__file__).resolve().parents[2]
    script = r'''
import json, os, sys
from pathlib import Path
from types import SimpleNamespace
from cyberthunder.inventory.targets import Inventory, ScopeViolation, Target
from cyberthunder.remediation import rollback_guard, rollback_scope
private, mode = Path(sys.argv[1]), sys.argv[2]
path = private / "inventory.json"
target = Target("fifo-test", "Fixture", "linux", transport="simulated")
path.write_text(json.dumps({"targets": [target.to_dict()]}))
ctx = SimpleNamespace(inventory=Inventory(path, targets=[target]))
if mode == "existing_fifo":
    path.unlink()
    os.mkfifo(path, 0o600)
else:
    original = os.open
    def replaced(value, flags, *args, **kwargs):
        if Path(value) == path:
            path.unlink()
            if mode == "fifo_at_open":
                os.mkfifo(path, 0o600)
            else:
                real = private / "regular.json"
                real.write_text("{}")
                path.symlink_to(real)
        return original(value, flags, *args, **kwargs)
    rollback_scope.os.open = replaced
try:
    with rollback_guard.target_operation(private, target.id):
        rollback_guard.inventory_target(ctx, target.id)
except ScopeViolation:
    pass
else:
    raise AssertionError("invalid inventory accepted")
with rollback_guard.target_operation(private, target.id):
    pass
print("scope-refused-lock-released")
'''
    result = subprocess.run([sys.executable, "-B", "-c", script, str(tmp_path), replacement],
                            cwd=root, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=8)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "scope-refused-lock-released"
