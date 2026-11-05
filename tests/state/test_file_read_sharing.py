"""Readers of replaced files retry sharing faults without trusting unreadable state."""
import errno
import json
import os
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from cyberthunder.api.routes.proposals import deny
from cyberthunder.audit.chain import AuditLog, head_path
from cyberthunder.control.approvals import ApprovalGate, ProposalState
from cyberthunder.control.killswitch import KillSwitch
from cyberthunder.inventory import targets
from cyberthunder.inventory.targets import Inventory, ScopeViolation, Target
from cyberthunder.state import json_files
from tests.test_approval_io import delete_handle, propose


@pytest.fixture
def inventory(state_dir):
    inv = Inventory(state_dir / "targets.yaml", [Target(id="fixture-host", name="Fixture host",
                    asset_type="linux", transport="fixture", in_scope=True)])
    inv.save()
    return inv


def revoke_elsewhere(inventory):
    other = Inventory.load(inventory.path)
    other.update("fixture-host", in_scope=False)
    other.save()


def fail_reads(monkeypatch, path, *, transient=False, error_number=errno.EACCES):
    original = Path.read_text
    attempts = []

    def read(p, *args, **kwargs):
        if p == path:
            attempts.append(p)
            if not transient or len(attempts) == 1:
                raise OSError(error_number, "read denied", str(p))
        return original(p, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    return attempts


def release_on_retry(monkeypatch, close):
    waits = []

    def release(delay):
        waits.append(delay)
        close()

    monkeypatch.setattr(json_files.time, "sleep", release)
    return waits


@pytest.mark.skipif(os.name != "nt", reason="requires Windows file sharing semantics")
def test_deny_response_survives_windows_inventory_sharing(inventory, monkeypatch):
    root = inventory.path.parent
    audit = AuditLog(root / "audit.jsonl", node="test")
    gate = ApprovalGate(root / "proposals.json", audit, KillSwitch(root, audit))
    proposal = propose(gate)
    ctx = SimpleNamespace(gate=gate, inventory=inventory,
                          library=SimpleNamespace(get=lambda _: None),
                          store=SimpleNamespace(get_finding=lambda _: None))
    other = Inventory.load(inventory.path)
    other.update("fixture-host", name="Updated fixture name")
    other.save()

    with delete_handle(inventory.path) as close:
        with pytest.raises(PermissionError):
            inventory.path.read_text(encoding="utf-8")
        waits = release_on_retry(monkeypatch, close)
        response = deny(proposal.id, ctx=ctx, actor="ITC Rivera")

    assert waits == [0.05]
    assert response["state"] == "denied"
    assert response["decided_by"] == "ITC Rivera"
    assert response["target"]["name"] == "Updated fixture name"
    assert gate.get(proposal.id).state is ProposalState.DENIED
    decisions = [r for r in audit.records() if r["action"] == "proposal.denied"]
    assert len(decisions) == 1 and decisions[0]["actor"] == "ITC Rivera"
    assert audit.verify().ok


@pytest.mark.skipif(os.name != "nt", reason="requires Windows file sharing semantics")
def test_windows_scope_retry_observes_revocation(inventory, monkeypatch):
    cached = inventory.get("fixture-host")
    revoke_elsewhere(inventory)
    assert cached.in_scope
    with delete_handle(inventory.path) as close:
        waits = release_on_retry(monkeypatch, close)
        with pytest.raises(ScopeViolation, match="out of scope"):
            inventory.assert_in_scope(cached.id)
    assert waits == [0.05]
    assert not cached.in_scope


@pytest.mark.parametrize("operation", ["in_scope", "assert_in_scope"])
def test_persistent_inventory_read_error_never_returns_cached_scope(inventory, monkeypatch, operation):
    cached = inventory.get("fixture-host")
    revoke_elsewhere(inventory)
    before = inventory.path.read_bytes()
    waits = []
    with monkeypatch.context() as patch:
        attempts = fail_reads(patch, inventory.path)
        patch.setattr(json_files.time, "sleep", waits.append)
        with pytest.raises(PermissionError):
            getattr(inventory, operation)(cached.id)
    assert len(attempts) == 20 and waits == [0.05] * 19
    assert cached.in_scope  # A stale object exists, but neither scope API returned it as authorization.
    assert inventory.path.read_bytes() == before
    with pytest.raises(ScopeViolation, match="out of scope"):
        inventory.assert_in_scope(cached.id)
    assert not cached.in_scope


@pytest.mark.parametrize("transient", [True, False])
def test_inventory_save_keeps_lock_and_external_scope_change(inventory, monkeypatch, transient):
    inventory.update("fixture-host", name="Local operator name")
    revoke_elsewhere(inventory)
    before = inventory.path.read_bytes()
    original_lock = targets.file_lock
    held = []
    entries = []
    waits = []

    @contextmanager
    def lock(path):
        with original_lock(path):
            held.append(path)
            entries.append(path)
            try:
                yield
            finally:
                held.pop()

    def wait(delay):
        assert held == [inventory.path.with_name("targets.yaml.lock")]
        waits.append(delay)

    with monkeypatch.context() as patch:
        attempts = fail_reads(patch, inventory.path, transient=transient)
        patch.setattr(targets, "file_lock", lock)
        patch.setattr(json_files.time, "sleep", wait)
        if transient:
            inventory.save()
        else:
            with pytest.raises(PermissionError):
                inventory.save()
    assert len(entries) == 1 and not held
    assert len(attempts) == (2 if transient else 20)
    assert waits == [0.05] * (1 if transient else 19)
    if not transient:
        assert inventory.path.read_bytes() == before
        inventory.save()  # The failed read released the lock and did not overwrite the revocation.
    persisted = Inventory.load(inventory.path).get("fixture-host")
    assert not persisted.in_scope
    assert persisted.name == "Local operator name"


@pytest.mark.skipif(os.name != "nt", reason="requires Windows file sharing semantics")
def test_json_run_read_survives_windows_sharing(tmp_path, monkeypatch):
    backend = json_files.JsonFilesBackend(tmp_path)
    backend.put("scans/fixture/run.json", {"status": "done"})
    path = tmp_path / "scans/fixture/run.json"
    with delete_handle(path) as close:
        with pytest.raises(PermissionError):
            path.read_text(encoding="utf-8")
        waits = release_on_retry(monkeypatch, close)
        assert backend.get("scans/fixture/run.json") == {"status": "done"}
    assert waits == [0.05]


def test_persistent_json_read_error_does_not_return_default(tmp_path, monkeypatch):
    path = tmp_path / "run.json"
    json_files.write_json_file(path, {"status": "done"})
    before = path.read_bytes()
    waits = []
    attempts = fail_reads(monkeypatch, path)
    monkeypatch.setattr(json_files.time, "sleep", waits.append)
    with pytest.raises(PermissionError):
        json_files.read_json_file(path, default={"status": "missing"})
    assert len(attempts) == 20 and waits == [0.05] * 19
    assert path.read_bytes() == before


@pytest.mark.parametrize("error_number", [errno.EIO, errno.ENOENT])
def test_nonsharing_read_errors_are_not_retried(tmp_path, monkeypatch, error_number):
    path = tmp_path / "run.json"
    json_files.write_json_file(path, {"status": "done"})
    attempts = fail_reads(monkeypatch, path, error_number=error_number)
    waits = []
    monkeypatch.setattr(json_files.time, "sleep", waits.append)
    with pytest.raises(OSError) as fault:
        json_files.read_json_file(path, default={"status": "missing"})
    assert fault.value.errno == error_number
    assert len(attempts) == 1 and not waits


def test_json_parse_error_is_not_retried(tmp_path, monkeypatch):
    path = tmp_path / "run.json"
    path.write_text("{broken", encoding="utf-8")
    waits = []
    monkeypatch.setattr(json_files.time, "sleep", waits.append)
    with pytest.raises(json.JSONDecodeError):
        json_files.read_json_file(path, default={"status": "missing"})
    assert not waits


@pytest.mark.skipif(os.name != "nt", reason="requires Windows file sharing semantics")
def test_audit_checkpoint_survives_windows_sharing(tmp_path, monkeypatch):
    audit = AuditLog(tmp_path / "audit.jsonl", node="test")
    event = audit.append("fixture", "ITC Rivera")
    checkpoint = head_path(audit.path)
    with delete_handle(checkpoint) as close:
        with pytest.raises(PermissionError):
            checkpoint.read_text(encoding="utf-8")
        waits = release_on_retry(monkeypatch, close)
        result = audit.verify()
    assert result.ok, str(result)
    assert result.checkpoint == "matches"
    assert result.head == event["hash"] and result.count == 1
    assert waits == [0.05]


def test_persistent_audit_checkpoint_read_error_fails_verification(tmp_path, monkeypatch):
    audit = AuditLog(tmp_path / "audit.jsonl", node="test")
    audit.append("fixture", "ITC Rivera")
    checkpoint = head_path(audit.path)
    before = (audit.path.read_bytes(), checkpoint.read_bytes())
    waits = []
    with monkeypatch.context() as patch:
        attempts = fail_reads(patch, checkpoint)
        patch.setattr(json_files.time, "sleep", waits.append)
        result = audit.verify()
    assert not result.ok and result.reason == "head checkpoint unreadable"
    assert result.checkpoint == "truncated"
    assert len(attempts) == 20 and waits == [0.05] * 19
    assert (audit.path.read_bytes(), checkpoint.read_bytes()) == before
    assert audit.verify().ok


@pytest.mark.parametrize("fault", ["sharing", "malformed"])
def test_unreadable_checkpoint_with_missing_log_cannot_verify_as_empty(tmp_path, monkeypatch, fault):
    audit = AuditLog(tmp_path / "audit.jsonl", node="test")
    audit.append("fixture", "ITC Rivera")
    audit.path.unlink()
    checkpoint = head_path(audit.path)
    waits = []
    if fault == "sharing":
        attempts = fail_reads(monkeypatch, checkpoint)
    else:
        checkpoint.write_text("{broken", encoding="utf-8")
    before = checkpoint.read_bytes()
    monkeypatch.setattr(json_files.time, "sleep", waits.append)
    result = audit.verify()
    assert not result.ok and result.reason == "head checkpoint unreadable"
    assert result.checkpoint == "truncated" and result.count == 0
    assert not audit.path.exists() and checkpoint.read_bytes() == before
    if fault == "sharing":
        assert len(attempts) == 20 and waits == [0.05] * 19
    else:
        assert not waits
