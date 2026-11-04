"""Detection rate on the simulated host: every seeded item in the answer key must be found.

This is measure of success #1 (share of seeded misconfigurations and vulnerabilities found).
"""
from __future__ import annotations

from cyberthunder.findings.schema import Status

from .conftest import collect_and_detect


def _open_ids(findings):
    """Every identifier an open finding can be scored against: rule_id, STIG ID, and the check id
    hunt:linux:<check> without the subject suffix."""
    ids = set()
    for f in findings:
        if f.status != Status.OPEN:
            continue
        ids.add(f.rule_id)
        if f.rule_version:
            ids.add(f.rule_version)
        if f.rule_id.startswith("hunt:linux:"):
            ids.add(":".join(f.rule_id.split(":")[:3]))
    return ids


def test_every_answer_key_item_detected(adapter, sim_target, sim_transport, answer_key, tmp_path):
    _, findings = collect_and_detect(adapter, sim_target, sim_transport, tmp_path)
    found = _open_ids(findings)
    missing = [item["id"] for item in answer_key["items"] if item["check_id"] not in found]
    assert not missing, f"undetected seeded items: {missing}; detected ids: {sorted(found)}"


def test_also_seeded_items_detected(adapter, sim_target, sim_transport, answer_key, tmp_path):
    _, findings = collect_and_detect(adapter, sim_target, sim_transport, tmp_path)
    found = _open_ids(findings)
    missing = [i["check_id"] for i in answer_key.get("also_seeded", []) if i["check_id"] not in found]
    assert not missing, f"undetected bonus items: {missing}"


def test_detection_is_deterministic(adapter, sim_target, sim_transport, tmp_path):
    _, a = collect_and_detect(adapter, sim_target, sim_transport, tmp_path / "a")
    _, b = collect_and_detect(adapter, sim_target, sim_transport, tmp_path / "b")
    assert sorted(f.id for f in a) == sorted(f.id for f in b)


def test_clean_rules_pass(adapter, sim_target, sim_transport, tmp_path):
    """Rules the seed does not break must come back as not-a-finding, not as false positives."""
    collected = adapter.collect(sim_target, sim_transport, tmp_path / "c")
    checks = {f.rule_version or f.rule_id: f for f in adapter.check(sim_target, collected)}
    for rid in ("RHEL-09-255050", "RHEL-09-232075", "RHEL-09-653015", "RHEL-09-431010", "RHEL-09-214025"):
        assert checks[rid].status == Status.NOT_A_FINDING, f"{rid} false positive: {checks[rid].evidence}"


def test_no_finding_without_citations(adapter, sim_target, sim_transport, tmp_path):
    _, findings = collect_and_detect(adapter, sim_target, sim_transport, tmp_path)
    assert findings
    for f in findings:
        assert f.citations, f"{f.rule_id} has no citations"
        assert f.references, f"{f.rule_id} has no typed references"


def test_hunt_findings_cite_attack(adapter, sim_target, sim_transport, tmp_path):
    collected = adapter.collect(sim_target, sim_transport, tmp_path / "h")
    hunt = adapter.hunt(sim_target, collected)
    assert hunt
    for f in hunt:
        assert f.ref_ids("attack"), f"hunt finding {f.rule_id} does not cite an ATT&CK technique"


def test_every_finding_resolves_to_a_fix(adapter, sim_target, sim_transport, tmp_path):
    _, findings = collect_and_detect(adapter, sim_target, sim_transport, tmp_path)
    lib = {e.fix_ref: e for e in adapter.fixes()}
    for f in findings:
        if f.status == Status.OPEN:
            assert f.fix_ref in lib, f"{f.rule_id} points at unknown fix {f.fix_ref}"
