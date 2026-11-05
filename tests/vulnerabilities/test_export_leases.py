from contextlib import contextmanager
from pathlib import Path
import subprocess
import sys

import pytest

from cyberthunder.vulnerabilities.errors import VulnerabilityConflict
from cyberthunder.vulnerabilities.service import MAX_EXPORTS, VulnerabilityService
from cyberthunder.vulnerabilities.storage import Lease


def test_export_reader_survives_retention_from_other_service(svc, offline_bundle):
    svc.import_bundle(offline_bundle, actor="joshua")
    other = VulnerabilityService(svc.ctx)
    bundle = svc.export_lease(actor="joshua")
    try:
        expected = bundle.path.read_bytes()
        for _ in range(MAX_EXPORTS + 2):
            other.export_bundle(actor="joshua")
        assert bundle.path.read_bytes() == expected
        assert len(list(svc.exports.glob("*.zip"))) == MAX_EXPORTS
    finally:
        bundle.close()
        bundle.close()
    other.export_bundle(actor="joshua")
    assert not bundle.path.exists()
    assert not bundle.path.with_suffix(".lock").exists()


def test_all_pinned_exports_conflict_then_released_slot_is_reclaimed(svc, offline_bundle):
    svc.import_bundle(offline_bundle, actor="joshua")
    with svc.export_lease(actor="joshua") as first:
        with svc.export_lease(actor="joshua") as second:
            with pytest.raises(VulnerabilityConflict, match="exports are still in use"):
                svc.export_lease(actor="joshua")
            assert first.is_file() and second.is_file()
            assert len(list(svc.exports.glob("*.zip"))) == MAX_EXPORTS
            assert not list(svc.exports.glob("*.partial"))
        with svc.export_lease(actor="joshua") as third:
            assert first.is_file() and third.is_file() and not second.exists()


def test_failed_export_context_exit_releases_new_lease(svc, offline_bundle, monkeypatch):
    svc.import_bundle(offline_bundle, actor="joshua")
    original = svc._selected

    @contextmanager
    def fail_after_publication():
        with original() as selected:
            yield selected
        raise OSError("metadata cleanup failed")

    monkeypatch.setattr(svc, "_selected", fail_after_publication)
    with pytest.raises(OSError) as failure:
        svc.export_lease(actor="joshua")
    assert "cleanup failed" in str(failure.value)
    path, = svc.exports.glob("*.zip")
    with Lease(path.with_suffix(".lock")):
        pass
    assert not list(svc.exports.glob("*.partial"))


def test_export_leases_survive_other_process_and_reclaim_after_crash(svc, offline_bundle):
    svc.import_bundle(offline_bundle, actor="joshua")
    code = "\n".join([
        "import sys", "from types import SimpleNamespace", "from cyberthunder.store import StateStore",
        "from cyberthunder.audit.chain import AuditLog",
        "from cyberthunder.control.killswitch import KillSwitch",
        "from cyberthunder.vulnerabilities.service import VulnerabilityService",
        "store = StateStore(sys.argv[1])", "audit = AuditLog(store.audit_log, node='fixture')",
        "settings = SimpleNamespace(vulnerability_max_bundle_bytes=1048576)",
        "ctx = SimpleNamespace(store=store, audit=audit, settings=settings,",
        "                      killswitch=KillSwitch(store.root, audit))",
        "service = VulnerabilityService(ctx)", "bundle = service.export_lease(actor='joshua')",
        "print(bundle.path, flush=True)", "sys.stdin.readline()", "bundle.close()"])
    process = subprocess.Popen([sys.executable, "-c", code, str(svc.store.root)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = process.stdout.readline().strip()
        assert line, process.stderr.read()
        path = Path(line)
        assert path.parent == svc.exports and path.is_file()
        with svc.export_lease(actor="joshua"):
            with pytest.raises(VulnerabilityConflict):
                svc.export_lease(actor="joshua")
            process.terminate()
            process.communicate(timeout=5)
            with svc.export_lease(actor="joshua") as replacement:
                assert replacement.is_file() and not path.exists()
                assert not path.with_suffix(".lock").exists()
    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=5)


def test_orphaned_unpublished_export_lock_is_reclaimed(svc, offline_bundle):
    svc.import_bundle(offline_bundle, actor="joshua")
    orphan = svc.exports / ("a" * 32 + ".lock")
    with Lease(orphan):
        pass
    with svc.export_lease(actor="joshua") as path:
        assert path.is_file() and not orphan.exists()


def test_capacity_fallbacks_are_independent(svc):
    for name in ("bundle", "unpacked", "staging"):
        delattr(svc.ctx.settings, f"vulnerability_max_{name}_bytes")
    assert svc.max_bundle_bytes == 4 * 1024 ** 3
    assert svc.max_unpacked_bytes == 8 * 1024 ** 3
    assert svc.max_staging_bytes == 12 * 1024 ** 3
