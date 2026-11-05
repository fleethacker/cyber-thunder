"""The engine enforces Linux file drift checks using the real adapter on a simulated host."""
from dataclasses import replace

import pytest

from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.control.approvals import ProposalState
from cyberthunder.remediation import rollback_guard, snapshot
from .conftest import collect_and_detect
from .test_remediate import _by_check

ACTOR = "it1.jones"
SSHD = "/etc/ssh/sshd_config"


@pytest.fixture
def applied(state_dir, adapter, sim_target, sim_transport, tmp_path):
    ctx = AppContext(Settings.from_env(state_dir=state_dir, auto_propose=False, explain_precompute=False,
                                       llm_backend="template"))
    ctx.inventory.add(sim_target)
    ctx.inventory.save()
    _, findings = collect_and_detect(adapter, sim_target, sim_transport, tmp_path / "initial")
    finding = _by_check(findings)["RHEL-09-255045"]
    ctx.store.save_scan_run({"id": "scan", "started_at": finding.collected_at, "status": "done", "targets": [sim_target.id]})
    ctx.store.save_findings("scan", [finding])
    p = ctx.engine.propose(finding)
    ctx.gate.approve(p.id, ACTOR)
    assert ctx.engine.execute(p.id, actor=ACTOR).state is ProposalState.VERIFIED
    transport = adapter.make_transport(sim_target, ctx.settings)
    return ctx, p, transport


def test_unchanged_files_allow_restore_without_rewriting_evidence(applied):
    ctx, p, transport = applied
    snap = ctx.store.snapshot_dir(p.id)
    originals = {path: path.read_bytes() for path in snap.rglob("*") if path.is_file()}
    post = snapshot.load_result(snap, "post_apply")
    assert post["resources"][SSHD]["owner"] == "root"
    assert post["resources"][SSHD]["sha256"]
    assert ctx.engine.rollback(p.id, actor=ACTOR).state is ProposalState.ROLLED_BACK
    for path, content in originals.items():
        assert path.read_bytes() == content
    status = ctx.engine.rollback_status(p.id)["last_preflight"]
    assert status["status"] == "checked_files" and status["live_checked"]
    assert status["coverage"] == "partial"  # SSH reload is outside file comparison


@pytest.mark.parametrize("change", ["content", "mode", "owner", "group", "uid", "gid", "missing", "symlink"])
def test_out_of_band_change_blocks_before_restore(applied, change):
    ctx, p, transport = applied
    item = transport.state["files"][SSHD]
    if change == "content":
        item["content"] += "# later administrator edit\n"
    elif change == "mode":
        item["mode"] = 0o777
    elif change in {"owner", "group"}:
        item[change] = "different-owner"
    elif change in {"uid", "gid"}:
        item[change] = 23123  # numeric ownership changes must be detected even when names are unchanged
    elif change == "missing":
        del transport.state["files"][SSHD]
    else:
        item["type"] = "symbolic link"
    transport._save()
    before = transport.path.read_bytes()
    with pytest.raises(rollback_guard.RollbackBlocked):
        ctx.engine.rollback(p.id, actor=ACTOR)
    assert transport.path.read_bytes() == before
    assert ctx.gate.get(p.id).state is ProposalState.VERIFIED
    diff = ctx.engine.diff(p.id)
    assert diff["rollback"] is None
    assert diff["rollback_guard"]["last_preflight"]["status"] == "blocked"


@pytest.mark.parametrize("evidence", ["post_apply", "execution", "before_state"])
def test_corrupted_or_missing_baseline_fails_closed(applied, evidence):
    ctx, p, transport = applied
    path = ctx.store.snapshots_dir / p.id / f"{evidence}.json"
    if evidence == "post_apply":
        path.unlink()
    else:
        doc = snapshot.load_result(path.parent, evidence)
        doc["target" if evidence == "execution" else "target_id"] = "different"
        snapshot.save_result(path.parent, evidence, doc)
    before = transport.path.read_bytes()
    with pytest.raises(rollback_guard.RollbackBlocked):
        ctx.engine.rollback(p.id, actor=ACTOR)
    assert transport.path.read_bytes() == before


def test_unreadable_file_blocks_without_changing_host(applied, monkeypatch):
    ctx, p, transport = applied
    factory = ctx.transport_for
    def unreadable(target):
        tr = factory(target)
        read = tr.read_file
        def file(path):
            if path == SSHD:
                raise OSError("permission denied")
            return read(path)
        tr.read_file = file
        return tr
    monkeypatch.setattr(ctx, "transport_for", unreadable)
    before = transport.path.read_bytes()
    with pytest.raises(rollback_guard.RollbackBlocked, match="permission denied"):
        ctx.engine.rollback(p.id, actor=ACTOR)
    assert transport.path.read_bytes() == before


def test_dynamic_script_gets_partial_not_full_coverage(applied, adapter):
    ctx, p, transport = applied
    before = snapshot.load_before_state(ctx.store.snapshot_dir(p.id))
    fix = replace(ctx.engine._applied_fix(p), payload="# unknown dynamic effects\ntrue", restarts_services=[])
    result = adapter.rollback_file_state(ctx.inventory.get(p.host), transport, fix, before)
    assert result["coverage"] == "partial"
    assert any("script" in note for note in result["limitations"])


def test_post_state_is_immutable_and_capture_integrity_is_checked(applied):
    ctx, p, transport = applied
    snap = ctx.store.snapshot_dir(p.id)
    with pytest.raises(FileExistsError):
        snapshot.save_once(snap, "post_apply", {})
    before = snapshot.load_before_state(snap)
    local = snap / "files" / before.extra["files"][SSHD]["local"]
    local.write_bytes(b"tampered")
    with pytest.raises(rollback_guard.RollbackBlocked, match="integrity"):
        ctx.engine.rollback(p.id, actor=ACTOR)


def test_post_apply_probe_failure_does_not_undo_success_but_blocks_manual_restore(state_dir, adapter, sim_target,
                                                                               sim_transport, tmp_path, monkeypatch):
    from cyberthunder.adapters.linux.adapter import LinuxAdapter
    monkeypatch.setattr(LinuxAdapter, "rollback_file_state", lambda *args: (_ for _ in ()).throw(OSError("probe unreadable")))
    ctx = AppContext(Settings.from_env(state_dir=state_dir, auto_propose=False, explain_precompute=False, llm_backend="template"))
    ctx.inventory.add(sim_target)
    ctx.inventory.save()
    _, findings = collect_and_detect(adapter, sim_target, sim_transport, tmp_path / "initial")
    finding = _by_check(findings)["RHEL-09-255045"]
    p = ctx.engine.propose(finding)
    ctx.gate.approve(p.id, ACTOR)
    assert ctx.engine.execute(p.id, actor=ACTOR).state is ProposalState.VERIFIED
    assert ctx.engine.rollback_status(p.id)["coverage"] == "unavailable"
    with pytest.raises(rollback_guard.RollbackBlocked, match="baseline"):
        ctx.engine.rollback(p.id, actor=ACTOR)
