from cyberthunder.scan import ScanRun
from tests.engine.conftest import HOST


def test_real_scanner_persists_partial_coverage_without_rewriting_observations(ctx):
    run = ctx.scanner.start([HOST], background=False, requested_by="IT1 Rivera")
    loaded = ctx.scanner.get(run.id)
    assert loaded.coverage_incomplete is True
    coverage = loaded.results[HOST].coverage
    assert coverage["phase"] == "observed"
    assert not coverage["complete"]
    findings = ctx.store.load_findings(run.id)
    assert len(findings) == coverage["findings_observed"]
    assert all(f.scan_id == run.id for f in findings)
    collected = ctx.store.read_json(ctx.store.scans_dir / run.id / "raw" / HOST / "collected.json")
    assert collected["raw"]["coverage"] == coverage
    assert ScanRun.from_dict(loaded.to_dict()).results[HOST].coverage == coverage
