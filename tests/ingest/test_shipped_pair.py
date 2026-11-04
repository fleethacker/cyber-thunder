"""The repository ships an old/new benchmark pair so the slow-link demo works without any download."""
from pathlib import Path

from cyberthunder.ingest.delta import diff, load_benchmark

ROOT = Path(__file__).resolve().parents[2]
OLD = ROOT / "tests/fixtures/windows/w11_subset-xccdf.xml"
NEW = ROOT / "tests/fixtures/ingest/w11_subset_new-xccdf.xml"


def test_shipped_pair_has_a_real_delta():
    old = load_benchmark(OLD)
    new = load_benchmark(NEW)
    rep = diff(old, new)
    d = rep.to_dict() if hasattr(rep, "to_dict") else dict(rep)
    counts = d.get("counts") or {k: len(d.get(k, [])) for k in ("rules_added", "rules_removed", "rules_changed")}
    added = counts.get("added", counts.get("rules_added", 0))
    removed = counts.get("removed", counts.get("rules_removed", 0))
    changed = counts.get("changed", counts.get("rules_changed", 0))
    assert added >= 1 and removed >= 1 and changed >= 2, counts
    assert d.get("rescan_rule_ids"), "a delta must name the rules to rescan"
