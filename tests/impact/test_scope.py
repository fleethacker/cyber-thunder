from contextlib import contextmanager
from pathlib import Path

import pytest

from cyberthunder.control.assessment import bind_assessment
from cyberthunder.inventory.targets import ScopeViolation
from cyberthunder.remediation import dependencies_binding as binding
from cyberthunder.remediation.engine import EngineError


@pytest.mark.parametrize("phase", ["initial", "collection", "model", "publication", "readiness"])
@pytest.mark.parametrize("problem", ["missing", "unreadable", "invalid"])
def test_strict_persisted_scope_at_all_service_boundaries(rig, monkeypatch, phase, problem):
    rig.ctx.impact = rig.service
    path = rig.ctx.inventory.path
    original_open = binding.os.open

    def invalidate():
        if problem == "missing":
            path.unlink()
        elif problem == "invalid":
            path.write_text('{"targets":"invalid"}', encoding="utf-8")
        else:
            def denied(value, *args, **kwargs):
                if Path(value) == path:
                    raise PermissionError("private-scope-diagnostic")
                return original_open(value, *args, **kwargs)
            monkeypatch.setattr(binding.os, "open", denied)

    if phase == "readiness":
        receipt = rig.service.assess(rig.proposal.id, actor="Joshua")
        audit_before = rig.ctx.store.audit_log.read_bytes()
        invalidate()
        result = rig.service.readiness(rig.proposal.id, receipt["id"])
        assert result["stale"] and not result["ready"] and "binding_unavailable" in result["reasons"]
        with pytest.raises(EngineError, match="stale"):
            bind_assessment(rig.ctx, rig.proposal.id, receipt["id"], "I reviewed unresolved dependencies.")
        assert rig.ctx.store.audit_log.read_bytes() == audit_before
        return
    if phase == "initial":
        invalidate()
    elif phase == "collection":
        def collect(*args, **kwargs):
            packet = rig.collect(*args, **kwargs)
            invalidate()
            return packet
        monkeypatch.setattr("cyberthunder.impact.service.collect_dependencies", collect)
    elif phase == "model":
        rig.backend.on_generate = invalidate
    else:
        real_lock = rig.ctx.store.lock

        @contextmanager
        def publication(name):
            invalidate()
            with real_lock(name):
                yield
        monkeypatch.setattr(rig.ctx.store, "lock", publication)
    with pytest.raises(ScopeViolation):
        rig.service.assess(rig.proposal.id, actor="Joshua")
    assert not rig.ctx.store.list_json(rig.service.directory)
    if phase in {"initial", "collection"}:
        assert not rig.backend.calls
    assert "private-scope-diagnostic" not in rig.ctx.store.audit_log.read_text(encoding="utf-8")


def test_readiness_refuses_unreadable_required_file_without_creating_binding_state(rig, monkeypatch, tmp_path):
    config = tmp_path / "required-config"
    config.write_text("synthetic", encoding="utf-8")
    rig.target.options["key_file"] = str(config)
    rig.ctx.inventory.save()
    rig.packet["target_binding_sha256"] = binding.target_binding_sha256(rig.target)
    receipt = rig.service.assess(rig.proposal.id, actor="Joshua")
    audit_before = rig.ctx.store.audit_log.read_bytes()
    paths_before = sorted(str(p) for p in rig.ctx.store.root.rglob("*"))
    original_open = binding.os.open

    def denied(value, *args, **kwargs):
        if Path(value) == config:
            raise PermissionError("private-file-diagnostic")
        return original_open(value, *args, **kwargs)

    monkeypatch.setattr(binding.os, "open", denied)
    result = rig.service.readiness(rig.proposal.id, receipt["id"])
    assert not result["ready"] and result["stale"]
    assert rig.ctx.store.audit_log.read_bytes() == audit_before
    assert sorted(str(p) for p in rig.ctx.store.root.rglob("*")) == paths_before


def test_in_memory_only_inventory_is_not_an_exception_for_service_tests(rig):
    rig.ctx.inventory.path = None
    with pytest.raises(ScopeViolation):
        rig.service.assess(rig.proposal.id, actor="Joshua")
    assert not rig.calls and not rig.backend.calls
