"""Proposal reads must survive transient sharing faults without accepting stale decisions."""
import errno
import os
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from cyberthunder.api.routes.proposals import _decide
from cyberthunder.audit.chain import AuditLog
from cyberthunder.control import approvals
from cyberthunder.control.approvals import ApprovalGate, IllegalTransition, ProposalState
from cyberthunder.control.killswitch import KillSwitch


@pytest.fixture
def gate(state_dir):
    audit = AuditLog(state_dir / "audit.jsonl", node="test")
    return ApprovalGate(state_dir / "proposals.json", audit, KillSwitch(state_dir, audit))


def propose(gate, finding_id="finding-1"):
    return gate.propose(finding_id=finding_id, host="fixture-host", title="Fixture fix",
                        fix_ref="test:fix", fix_preview="fixture only", rollback_plan="restore fixture",
                        risk="test risk")


def peer(gate):
    return ApprovalGate(gate.store, gate.audit, gate.ks)


def sharing_error(path):
    return PermissionError(errno.EACCES, "Permission denied", str(path))


@contextmanager
def delete_handle(path):
    """Hold the DELETE access used by Windows replacement, without deleting the file."""
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    # DELETE access, share read/write/delete, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL.
    handle = kernel.CreateFileW(str(path), 0x10000, 7, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())

    def close():
        nonlocal handle
        if handle is not None:
            if not kernel.CloseHandle(handle):
                raise ctypes.WinError(ctypes.get_last_error())
            handle = None

    try:
        yield close
    finally:
        close()


@pytest.mark.skipif(os.name != "nt", reason="requires Windows file sharing semantics")
def test_deny_survives_windows_delete_handle(gate, monkeypatch):
    proposal = propose(gate)
    # A second writer changes the file, so the API's initial get must refresh its cached view.
    other = propose(peer(gate), "finding-2")
    waits = []
    with delete_handle(gate.store) as close:
        assert gate.store.stat().st_size > 0
        with pytest.raises(PermissionError) as fault:
            gate.store.read_text(encoding="utf-8")
        assert fault.value.errno == errno.EACCES

        def release_handle(delay):
            waits.append(delay)
            close()

        monkeypatch.setattr(approvals, "sleep", release_handle, raising=False)
        result = _decide(SimpleNamespace(gate=gate), proposal.id, "deny", "ITC Rivera", "not approved")

    assert waits == [0.05]
    assert result is proposal
    assert result.state is ProposalState.DENIED
    assert result.decided_by == "ITC Rivera"
    assert peer(gate).get(other.id).state is ProposalState.PROPOSED
    decisions = [r for r in gate.audit.records() if r["action"] == "proposal.denied"]
    assert len(decisions) == 1
    assert decisions[0]["actor"] == "ITC Rivera"
    assert gate.audit.verify().ok


@pytest.mark.parametrize("operation", ["get", "list", "reopen"])
def test_read_retry_refreshes_state_from_another_writer(gate, monkeypatch, operation):
    proposal = propose(gate)
    peer(gate).deny(proposal.id, "ITC Rivera")
    assert proposal.state is ProposalState.PROPOSED
    original = Path.read_text
    attempts = []
    waits = []

    def read(path, *args, **kwargs):
        if path == gate.store:
            attempts.append(path)
            if len(attempts) == 1:
                raise sharing_error(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(approvals, "sleep", waits.append, raising=False)
    if operation == "get":
        result = gate.get(proposal.id)
    elif operation == "list":
        result, = gate.list()
    else:
        result = peer(gate).get(proposal.id)
    assert len(attempts) == 2
    assert waits == [0.05]
    assert result.state is ProposalState.DENIED
    assert result.decided_by == "ITC Rivera"
    if operation != "reopen":
        assert result is proposal


@pytest.mark.parametrize("action", ["approve", "deny"])
def test_decision_read_retry_keeps_the_process_lock(gate, monkeypatch, action):
    proposal = propose(gate)
    original_read = Path.read_text
    original_lock = approvals.file_lock
    active_locks = []
    lock_entries = []
    attempts = []
    waits = []
    before_audit = list(gate.audit.records())

    @contextmanager
    def lock(path):
        with original_lock(path):
            active_locks.append(path)
            lock_entries.append(path)
            try:
                yield
            finally:
                active_locks.pop()

    def read(path, *args, **kwargs):
        if path == gate.store:
            assert active_locks == [gate.store.with_name("proposals.json.lock")]
            attempts.append(path)
            if len(attempts) == 1:
                raise sharing_error(path)
        return original_read(path, *args, **kwargs)

    def wait(delay):
        assert active_locks
        assert list(gate.audit.records()) == before_audit
        waits.append(delay)

    with monkeypatch.context() as patch:
        patch.setattr(approvals, "file_lock", lock)
        patch.setattr(Path, "read_text", read)
        patch.setattr(approvals, "sleep", wait, raising=False)
        result = getattr(gate, action)(proposal.id, "ITC Rivera")
    assert len(attempts) == 2
    assert waits == [0.05]
    assert len(lock_entries) == 1
    assert not active_locks
    assert result is proposal
    assert result.state is (ProposalState.APPROVED if action == "approve" else ProposalState.DENIED)
    assert peer(gate).get(proposal.id).state is result.state
    records = list(gate.audit.records())
    assert len(records) == len(before_audit) + 1
    assert records[-1]["actor"] == "ITC Rivera"
    assert gate.audit.verify().ok


@pytest.mark.parametrize("failure_point", ["stat", "read_text"])
def test_persistent_read_fault_cannot_apply_a_stale_approval(gate, monkeypatch, failure_point):
    proposal = propose(gate)
    gate.approve(proposal.id, "ITC Rivera")
    peer(gate).cancel(proposal.id, "ITC Rivera", "authorization withdrawn")
    assert proposal.state is ProposalState.APPROVED
    before_file = gate.store.read_bytes()
    before_audit = list(gate.audit.records())
    original = getattr(Path, failure_point)
    attempts = []
    waits = []

    def inaccessible(path, *args, **kwargs):
        if path == gate.store:
            attempts.append(path)
            raise sharing_error(path)
        return original(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, failure_point, inaccessible)
        patch.setattr(approvals, "sleep", waits.append, raising=False)
        with pytest.raises(PermissionError):
            gate.start_apply(proposal.id, "ITC Rivera")
    assert len(attempts) == 20
    assert waits == [0.05] * 19
    assert gate.store.read_bytes() == before_file
    assert list(gate.audit.records()) == before_audit
    # Failure released the locks; the next attempt must use the persisted cancellation.
    with pytest.raises(IllegalTransition, match="cancelled -> applying"):
        gate.start_apply(proposal.id, "ITC Rivera")
    assert proposal.state is ProposalState.CANCELLED
    assert gate.audit.verify().ok


def test_nonsharing_read_error_is_not_retried(gate, monkeypatch):
    proposal = propose(gate)
    before_audit = list(gate.audit.records())
    original = Path.read_text
    attempts = []
    waits = []

    def read(path, *args, **kwargs):
        if path == gate.store:
            attempts.append(path)
            raise OSError(errno.EIO, "read failed", str(path))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(approvals, "sleep", waits.append, raising=False)
    with pytest.raises(OSError, match="read failed"):
        gate.approve(proposal.id, "ITC Rivera")
    assert len(attempts) == 1
    assert not waits
    assert proposal.state is ProposalState.PROPOSED
    assert list(gate.audit.records()) == before_audit
