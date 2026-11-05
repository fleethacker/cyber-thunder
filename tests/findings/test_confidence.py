"""Evidence grading uses fixed clocks, local fixtures, and temporary state only."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from cyberthunder.findings.confidence import (
    DIRECT_SOURCES, MAX_EVIDENCE_AGE, RULES_VERSION, SCANNER_SOURCES, assess, assess_for_context,
)
from cyberthunder.findings.schema import Finding, Severity, Status, findings_from_doc
from cyberthunder.adapters.base import Collected
from cyberthunder.adapters.linux.checks import native_findings, merge as merge_linux
from cyberthunder.adapters.windows.cklb_merge import merge as merge_cklb
from cyberthunder.adapters.windows.scap_merge import merge as merge_scap
from cyberthunder.inventory.targets import Inventory, Target
from cyberthunder.parsers.cklb import parse_cklb
from cyberthunder.parsers.nessus import parse_nessus
from cyberthunder.parsers.xccdf import parse_xccdf
from cyberthunder.store import StateStore

NOW = datetime(2026, 11, 5, 15, tzinfo=timezone.utc)
OBSERVED = "2026-11-05T14:00:00+00:00"
FIXTURES = Path(__file__).parents[1] / "fixtures"


def finding(**changes):
    return Finding(**dict({
        "host": "range-01", "source": "native", "rule_id": "RHEL-09-255045",
        "title": "Disable direct root login", "severity": "high", "status": "open",
        "evidence": "sshd -T: permitrootlogin yes", "collected_at": OBSERVED,
    }, **changes))


def provenance(**changes):
    return dict({
        "method": "command", "authenticated": True, "privilege": "root",
        "privilege_sufficient": True, "complete": True, "applicable": True,
        "simulated": False, "observed_at": OBSERVED,
        "detector": {"name": "native-sshd", "version": "1"},
        "content": {"id": "RHEL_9_STIG", "version": "V2R3"},
    }, **changes)


def test_exact_contract_deterministic_no_mutation_and_no_approval_fields():
    f = finding(collection_provenance=provenance())
    original = f.to_dict()
    result = assess(f, now=NOW)
    assert result == assess(f, now=NOW.isoformat()) == assess(f.to_dict(), now=NOW)
    assert set(result) == {"grade", "reason", "reasons", "version", "assessed_at", "observed_at", "evidence"}
    assert result["grade"] == "high"
    assert result["version"] == RULES_VERSION
    assert result["reason"] == result["reasons"][0]
    assert result["observed_at"] == OBSERVED
    assert not result["evidence"]["unknowns"]
    assert not result["evidence"]["high_requirements_unmet"]
    assert f.to_dict() == original
    json.dumps(result)
    result["evidence"]["collection_provenance"]["detector"]["version"] = "changed"
    assert f.to_dict() == original


@pytest.mark.parametrize("source", sorted(DIRECT_SOURCES))
def test_existing_direct_producers_are_useful_but_never_high_by_name(source):
    result = assess(finding(source=source), now=NOW)
    assert result["grade"] == "medium"
    assert result["evidence"]["authenticated"] is None
    assert result["evidence"]["privilege"] is None
    assert result["evidence"]["content"] == {"id": None, "version": None}
    assert {"authenticated", "privilege", "detector.version", "content.version", "simulated"} <= set(
        result["evidence"]["unknowns"])
    assert assess(finding(source=source, evidence=None), now=NOW)["grade"] == "unknown"


@pytest.mark.parametrize("field", list(provenance()))
def test_every_explicit_high_requirement_is_required(field):
    p = provenance()
    p.pop(field)
    assert assess(finding(collection_provenance=p), now=NOW)["grade"] == "medium"


@pytest.mark.parametrize("section,key", [("detector", "name"), ("detector", "version"),
                                        ("content", "id"), ("content", "version")])
def test_metadata_identity_and_versions_cannot_be_invented(section, key):
    p = provenance()
    p[section].pop(key)
    result = assess(finding(collection_provenance=p), now=NOW)
    assert result["grade"] == "medium"
    assert f"{section}.{key}" in result["evidence"]["unknowns"]


def test_existing_benchmark_release_is_actual_content_not_detector_version():
    p = provenance()
    p.pop("content")
    f = finding(benchmark="RHEL_9_STIG", benchmark_release="V2R3", collection_provenance=p)
    assert assess(f, now=NOW)["grade"] == "high"
    p["detector"].pop("version")
    assert assess(f, now=NOW)["grade"] == "medium"


@pytest.mark.parametrize("status", list(Status))
@pytest.mark.parametrize("severity", list(Severity))
def test_severity_never_affects_grade_or_changes_original_status(status, severity):
    f = finding(status=status, severity=severity, collection_provenance=provenance())
    expected = "unknown" if status in {Status.ERROR, Status.NOT_REVIEWED} else "high"
    assert assess(f, now=NOW)["grade"] == expected
    assert f.status == status


@pytest.mark.parametrize("status", ["unknown", "incomplete", "notchecked", "unexpected", None])
def test_unresolved_serialized_status_never_becomes_a_completed_result(status):
    data = finding(collection_provenance=provenance()).to_dict()
    data["status"] = status
    assert assess(data, now=NOW)["grade"] == "unknown"
    assert data["status"] == status


@pytest.mark.parametrize("update", [{"complete": False}, {"collection_status": "incomplete"},
                                    {"collection_status": "error"}, {"errors": ["permission denied"]}])
def test_incomplete_collection_overrides_an_otherwise_strong_result(update):
    result = assess(finding(collection_provenance=provenance(**update)), now=NOW)
    assert result["grade"] == "unknown"
    assert "incomplete" in result["reason"]


@pytest.mark.parametrize("value", [None, "", "  ", "unknown", "not collected", "PASS", "[22/tcp]"])
def test_missing_placeholder_or_result_label_is_not_evidence(value):
    assert assess(finding(evidence=value, collection_provenance=provenance()), now=NOW)["grade"] == "unknown"


def test_structured_observation_can_supply_evidence():
    f = finding(evidence=None, collection_provenance=provenance(observations={"PermitRootLogin": "yes"}))
    assert assess(f, now=NOW)["grade"] == "high"


@pytest.mark.parametrize("observations", [{}, [], {"values": []}, [None, ""], {"result": "PASS"},
                                         {"value": float("nan")}, {"value": float("inf")}])
def test_empty_structured_values_do_not_manufacture_observations(observations):
    f = finding(evidence=None, collection_provenance=provenance(observations=observations))
    assert assess(f, now=NOW)["grade"] == "unknown"


@pytest.mark.parametrize("value", [False, 0, 0.0])
def test_false_and_zero_are_valid_structured_measurements(value):
    f = finding(evidence=None, collection_provenance=provenance(observations={"enabled": value}))
    assert assess(f, now=NOW)["grade"] == "high"


@pytest.mark.parametrize("field", ["host", "rule_id"])
@pytest.mark.parametrize("value", ["", "unknown", None])
def test_missing_scope_is_unknown(field, value):
    data = finding(collection_provenance=provenance()).to_dict()
    data[field] = value
    assert assess(data, now=NOW)["grade"] == "unknown"


@pytest.mark.parametrize("value,state", [
    (None, "missing"), ("", "missing"), ("bad-date", "invalid"), (123, "invalid"),
    ("2026-11-05T14:00:00", "timezone_missing"), ("2026-11-05", "timezone_missing"),
    ("2026-11-05T14:00:00+25:00", "invalid"),
    ("2026-11-05T15:00:00.000001Z", "future"),
    ("2026-10-29T14:59:59Z", "stale"),
])
@pytest.mark.parametrize("explicit", [False, True])
def test_timestamp_failures_are_conservative(value, state, explicit):
    p = provenance()
    if explicit:
        p["observed_at"] = value
        f = finding(collection_provenance=p)
    else:
        p.pop("observed_at")
        f = finding(collected_at=value, collection_provenance=p)
    result = assess(f, now=NOW)
    assert result["grade"] == "low"
    assert result["evidence"]["timestamp_status"] == state
    if state in {"missing", "invalid", "timezone_missing"}:
        assert result["observed_at"] is None
    else:
        assert result["observed_at"] is not None


@pytest.mark.parametrize("value", ["2026-11-05T09:00:00-05:00", "2026-11-05T14:00:00Z"])
def test_timezone_offsets_normalize_to_same_instant(value):
    result = assess(finding(collection_provenance=provenance(observed_at=value)), now=NOW)
    assert result["grade"] == "high"
    assert result["observed_at"] == OBSERVED
    assert result["evidence"]["age_seconds"] == 3600


def test_freshness_exact_boundary_and_observation_time_precedence():
    at_limit = (NOW - MAX_EVIDENCE_AGE).isoformat()
    f = finding(collection_provenance=provenance(observed_at=at_limit))
    assert assess(f, now=NOW)["grade"] == "high"
    assert assess(f, now=NOW + timedelta(microseconds=1))["grade"] == "low"
    f.collected_at = "2026-01-01T00:00:00Z"
    assert assess(f, now=NOW)["grade"] == "high"


@pytest.mark.parametrize("now", ["invalid", "2026-11-05T15:00:00", datetime(2026, 11, 5), 1])
def test_invalid_assessment_clock_fails_explicitly(now):
    with pytest.raises(ValueError, match="timezone-aware"):
        assess(finding(), now=now)


def test_default_clock_produces_an_aware_assessment():
    before = datetime.now(timezone.utc)
    result = assess(finding())
    assert before <= datetime.fromisoformat(result["assessed_at"]) <= datetime.now(timezone.utc)


@pytest.mark.parametrize("changes,phrase", [
    ({"simulated": True}, "Simulated"), ({"transport": "fixture"}, "Simulated"),
    ({"transport": "simulated"}, "Simulated"), ({"version_only": True}, "Version-only"),
    ({"method": "package_version"}, "Version-only"), ({"method": "banner"}, "Version-only"),
    ({"conflicts": ["scanner pass differs from configuration"]}, "Conflicting"),
    ({"conflicting": True}, "Conflicting"), ({"partial": True}, "partial"),
    ({"collection_status": "partial"}, "partial"), ({"applicable": False}, "inapplicable"),
    ({"privilege_sufficient": False}, "insufficient"),
])
def test_downgrades_override_complete_metadata(changes, phrase):
    result = assess(finding(collection_provenance=provenance(**changes)), now=NOW)
    assert result["grade"] == "low"
    assert phrase in " ".join(result["reasons"])


@pytest.mark.parametrize("source", ["trivy", "cve", "iavm", "discovery", "nmap", "hunt"])
def test_version_and_discovery_sources_cannot_be_upgraded_by_claiming_direct(source):
    assert assess(finding(source=source, collection_provenance=provenance()), now=NOW)["grade"] == "low"


@pytest.mark.parametrize("tag", ["simulated", "demo", "fixture", "version-only", "conflicting", "partial"])
def test_explicit_legacy_tags_downgrade(tag):
    assert assess(finding(tags=[tag], collection_provenance=provenance()), now=NOW)["grade"] == "low"


def test_unknown_source_requires_a_recorded_direct_method():
    assert assess(finding(source="custom"), now=NOW)["grade"] == "low"
    assert assess(finding(source="custom", collection_provenance=provenance()), now=NOW)["grade"] == "high"


@pytest.mark.parametrize("field", ["authenticated", "privilege_sufficient", "complete", "applicable", "simulated"])
@pytest.mark.parametrize("value", ["true", "false", 1, 0, None])
def test_nonboolean_metadata_is_unknown_not_truthy(field, value):
    result = assess(finding(collection_provenance=provenance(**{field: value})), now=NOW)
    assert result["grade"] == "medium"
    assert field in result["evidence"]["unknowns"]


def test_malformed_provenance_is_low_and_preserved():
    result = assess(finding(collection_provenance=["not a mapping"]), now=NOW)
    assert result["grade"] == "low"
    assert result["evidence"]["collection_provenance"] == ["not a mapping"]


@pytest.mark.parametrize("key,value", [("partial", "true"), ("version_only", 1),
                                      ("conflicting", "false"), ("conflicts", None)])
def test_invalid_restriction_markers_cannot_qualify_for_high(key, value):
    result = assess(finding(collection_provenance=provenance(**{key: value})), now=NOW)
    assert result["grade"] == "low"
    assert key in result["evidence"]["invalid_markers"]


def test_unrelated_collector_errors_are_recorded_without_invalidating_check():
    p = provenance(collector_errors=["optional package inventory unavailable"])
    result = assess(finding(collection_provenance=p), now=NOW)
    assert result["grade"] == "high"
    assert result["evidence"]["collection_provenance"]["collector_errors"] == p["collector_errors"]


def test_multiple_restrictions_survive_unknown_status():
    f = finding(status="error", collection_provenance=provenance(simulated=True, conflicts=["mismatch"], partial=True))
    result = assess(f, now=NOW)
    assert result["grade"] == "unknown"
    assert "Simulated" in result["reason"]
    assert all(word in " ".join(result["reasons"]) for word in ("Simulated", "Conflicting", "partial"))


def test_native_checks_from_recorded_command_output_and_missing_collection():
    target = Target(id="range-01", name="Range", asset_type="linux")
    collected = Collected(target_id=target.id, asset_type="linux", workdir="unused",
                          collected_at=OBSERVED, rule_filter=["RHEL-09-255045"],
                          raw={"cmd": {"sshd_t": {"exit": 0, "out": "permitrootlogin yes\n"}}})
    actual = native_findings(target, collected)
    assert len(actual) == 1
    assert actual[0].status == Status.OPEN
    assert assess(actual[0], now=NOW)["grade"] == "medium"
    collected.raw = {}
    incomplete = native_findings(target, collected)[0]
    assert incomplete.status == Status.NOT_REVIEWED
    assert assess(incomplete, now=NOW)["grade"] == "unknown"


@pytest.mark.parametrize("merge", [merge_linux, merge_cklb, merge_scap])
@pytest.mark.parametrize("disagrees", [False, True])
def test_existing_merge_producers_expose_disagreements(merge, disagrees):
    native = finding(rule_version="RHEL-09-255045")
    scanner = finding(source="openscap", rule_version=native.rule_version,
                      status="not_a_finding" if disagrees else "open", evidence="scanner observation")
    if merge is merge_linux:
        merged = merge([native], [scanner])[0]
    else:
        target = Target(id="range-01", name="Range", asset_type="windows")
        merged = merge(target, [native], [scanner])[0]
    result = assess(merged, now=NOW)
    assert result["grade"] == ("low" if disagrees else "medium")
    assert result["evidence"]["conflicting"] is disagrees


def test_real_fixture_parsers_have_conservative_useful_grades():
    xccdf = parse_xccdf(FIXTURES / "sample_results.xccdf.xml").findings
    cklb = parse_cklb(FIXTURES / "sample.cklb")
    nessus = parse_nessus(FIXTURES / "parsers" / "sample.nessus")
    # This parser records import time; stabilize that clock for this fixture test.
    for f in nessus:
        f.collected_at = OBSERVED
    for findings in (xccdf, cklb, nessus):
        results = [assess(f, now=NOW) for f in findings]
        assert any(r["grade"] == "medium" for r in results)
        assert all(r["grade"] != "high" for r in results)
        assert all(r["evidence"]["authenticated"] is None for r in results)


@pytest.mark.parametrize("source", sorted(SCANNER_SOURCES))
def test_actual_nessus_version_fixture_is_low_and_deterministic(source):
    f = next(f for f in parse_nessus(FIXTURES / "parsers" / "sample.nessus", source=source)
             if f.rule_id == "nessus:187315")
    # Stabilize import time only; use the actual parser's evidence and provenance.
    f.collected_at = OBSERVED
    assert f.evidence == "Installed version : 8.7p1 Fixed version : 9.6p1 [22/tcp]"
    assert f.collection_provenance is None
    before = f.to_dict()
    legacy = deepcopy(before)
    legacy.pop("collection_provenance")
    result = assess(f, now=NOW)
    assert result == assess(f, now=NOW) == assess(Finding.from_dict(legacy), now=NOW)
    assert result["grade"] == "low"
    assert result["evidence"]["source_kind"] == "version_match"
    assert result["evidence"]["version_only"] is True
    assert result["evidence"]["inference_markers"] == ["version_field"]
    assert result["evidence"]["authenticated"] is None
    assert "Version-only" in result["reason"]
    assert f.to_dict() == before


@pytest.mark.parametrize("source", ["acas", "nessus", "custom-scanner"])
@pytest.mark.parametrize("observation,marker", [
    ("Installed version : 8.7p1\n Fixed version : 9.6p1", "version_field"),
    ("INSTALLED VERSION=8.7p1 FIXED VERSION=9.6p1 [22/tcp]", "version_field"),
    ("Remote software version : 2.4.49 Fixed version : 2.4.51", "version_field"),
    ("Detected version: 1.2", "version_field"),
    ("Version : 8.7p1", "version_field"),
    ("Banner: SSH-2.0-OpenSSH_8.7 [22/tcp]", "banner"),
    ("SSH-2.0-OpenSSH_8.7", "banner"),
    ("Server: Apache/2.4.49 [443/tcp]", "banner"),
    ("X-Powered-By: PHP/8.0.1", "banner"),
    ("22/tcp open ssh", "port_only"),
    ("Port 22 is open", "port_only"),
    ("tcp port 443 open", "port_only"),
    ("Open ports: 22/tcp, 443/tcp", "port_only"),
])
def test_legacy_inference_uses_observations_not_plugin_identity(source, observation, marker):
    f = finding(source=source, rule_id="arbitrary-plugin-id", title="Credentialed direct check",
                evidence=observation, collection_provenance=provenance(version_only=False))
    result = assess(f, now=NOW)
    assert result["grade"] == "low"
    assert marker in result["evidence"]["inference_markers"]
    assert result["evidence"]["source_kind"] != "direct"


@pytest.mark.parametrize("source", sorted(SCANNER_SOURCES))
def test_scanner_origin_never_asserts_direct_or_authenticated_collection(source):
    f = finding(source=source, title="Credentialed scanner check", evidence="Encryption level not enforced. [3389/tcp]")
    result = assess(f, now=NOW)
    assert result["grade"] == "medium"
    assert result["evidence"]["source_kind"] == "scanner"
    assert result["evidence"]["authenticated"] is None
    assert not result["evidence"]["version_only"]
    assert result["evidence"]["inference_markers"] == []
    assert "Direct observation" not in result["reason"]
    assert assess(finding(source=source, evidence="[22/tcp]"), now=NOW)["grade"] == "unknown"


def test_substantive_fixture_observations_are_not_downgraded_by_port_suffixes():
    fs = parse_nessus(FIXTURES / "parsers" / "sample.nessus")
    for f in fs:
        if f.rule_id == "nessus:187315":
            continue
        f.collected_at = OBSERVED
        result = assess(f, now=NOW)
        assert result["grade"] == "medium", f.rule_id
        assert result["evidence"]["source_kind"] == "scanner"
        assert result["evidence"]["inference_markers"] == []


def test_stored_nessus_version_match_withholds_matching_policy_both_backends(state_dir):
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext
    from cyberthunder.control.policy import AutomationPolicy, PolicyRule, evaluate, evaluate_for_context
    from cyberthunder.remediation.library import FixEntry

    f = next(f for f in parse_nessus(FIXTURES / "parsers" / "sample.nessus") if f.rule_id == "nessus:187315")
    target = Target(id=f.host, name="Isolated fixture target", asset_type="linux")
    policy = AutomationPolicy(enabled=True, signed_by="Joshua Ott",
                              rules=[PolicyRule(name="fixture patch rule", allow_patch=True)])
    fix = FixEntry(fix_ref=f.fix_ref, title="Fixture patch", asset_type="linux",
                   applies_to=[f.rule_id], patch=True)
    ctx = AppContext(Settings.from_env(state_dir=state_dir, llm_backend="template",
                                      explain_precompute=False, auto_propose=False))
    store = ctx.store
    try:
        # Exercise a pre-provenance stored document, not only a new in-memory finding.
        legacy = f.to_dict()
        legacy.pop("collection_provenance")
        store.write_json(store.scan_dir("legacy-version") / "findings.json",
                         {"schema_version": "1.0", "findings": [legacy]})
        restored = store.load_findings("legacy-version")[0]
        ctx.policy = policy
        ctx.inventory = Inventory(targets=[target])
        assert evaluate(policy, fix, restored, target).auto_eligible
        decision = evaluate_for_context(ctx, fix, restored, target)
        assert not decision.auto_eligible
        assert "low confidence" in decision.reasons[0]
        assert "Version-only" in decision.reasons[0]
        assert restored.status == Status.OPEN
    finally:
        store.close()


def test_provenance_and_old_schema_roundtrip_both_backends(state_dir):
    f = finding(collection_provenance=provenance(package={"name": "openssh", "version": "9.0"}))
    legacy = finding().to_dict()
    legacy.pop("collection_provenance")
    old_doc = {"schema_version": "1.0", "findings": [legacy]}
    assert findings_from_doc(old_doc)[0].collection_provenance is None
    store = StateStore(state_dir)
    try:
        store.save_findings("new", [f])
        restored = store.load_findings("new")[0]
        assert restored.to_dict() == f.to_dict()
        assert assess(restored, now=NOW) == assess(f, now=NOW)
        store.write_json(store.scan_dir("legacy") / "findings.json", old_doc)
        assert assess(store.load_findings("legacy")[0], now=NOW)["grade"] == "medium"
    finally:
        store.close()


@pytest.mark.parametrize("simulated,expected", [(True, "low"), (False, "medium")])
def test_context_lookup_is_explicit_and_never_mutates_finding(simulated, expected):
    target = Target(id="range-01", name="Range", asset_type="linux", simulated=simulated)
    ctx = SimpleNamespace(inventory=Inventory(targets=[target]))
    f = finding()
    before = deepcopy(f.to_dict())
    result = assess_for_context(ctx, f, now=NOW)
    assert result["grade"] == expected
    assert "inventory context" in result["reason"]
    assert result["evidence"]["simulation_context"] == {"source": "inventory", "simulated": simulated}
    assert result["evidence"]["collection_provenance"] is None
    assert "simulation_at_collection" in result["evidence"]["unknowns"]
    assert f.to_dict() == before
    assert assess(f, now=NOW)["grade"] == "medium"


@pytest.mark.parametrize("value", [True, False, None, "false"])
def test_explicit_simulation_field_always_precedes_inventory(value):
    class NoLookup:
        def get(self, host):
            pytest.fail("explicit provenance must not read inventory")
    f = finding(collection_provenance=provenance(simulated=value))
    assert assess_for_context(SimpleNamespace(inventory=NoLookup()), f, now=NOW) == assess(f, now=NOW)


def test_current_inventory_cannot_supply_historical_high_requirement():
    p = provenance()
    p.pop("simulated")
    f = finding(collection_provenance=p)
    ctx = SimpleNamespace(inventory=Inventory(targets=[Target(id=f.host, name="Range", asset_type="linux")]))
    assert assess_for_context(ctx, f, now=NOW)["grade"] == "medium"


@pytest.mark.parametrize("error", [KeyError("absent"), OSError("unavailable"), ValueError("invalid")])
def test_missing_or_unreadable_inventory_preserves_pure_assessment(error):
    class Unavailable:
        def get(self, host):
            raise error
    f = finding()
    assert assess_for_context(SimpleNamespace(inventory=Unavailable()), f, now=NOW) == assess(f, now=NOW)
