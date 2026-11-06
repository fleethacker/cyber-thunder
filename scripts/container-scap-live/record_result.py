"""Record declared profile scope and actual output availability, without importing."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

X = "{http://checklists.nist.gov/xccdf/1.2}"
PROFILE = "xccdf_mil.disa.stig_profile_MAC-1_Public"


def declared_scope(path):
    benchmarks = list(ET.parse(path).getroot().iter(X + "Benchmark"))
    assert len(benchmarks) == 1
    benchmark = benchmarks[0]
    profiles = [p for p in benchmark.findall(X + "Profile") if p.get("id") == PROFILE]
    assert len(profiles) == 1
    profile = profiles[0]
    # This bounded resolver recognizes the exact uploaded all-groups profile.
    # Unsupported tailoring must remain unknown rather than use returned rows.
    assert not profile.get("extends")
    assert all(e.tag in {X + "title", X + "description", X + "select"} for e in profile)
    groups = {g.get("id"): g for g in benchmark.iter(X + "Group")}
    selected = profile.findall(X + "select")
    assert len(selected) == len(groups)
    assert {s.get("idref") for s in selected} == set(groups)
    assert all(s.get("selected") == "true" for s in selected)
    assert all(len(g.findall(X + "Rule")) == 1 and not g.findall(X + "Group") for g in groups.values())
    rules = sorted(g.find(X + "Rule").get("id") for g in groups.values())
    assert len(rules) == len(set(rules)) == len(list(benchmark.iter(X + "Rule")))
    return {"benchmark_id": benchmark.get("id"), "profile_id": PROFILE,
        "expected_rule_ids": rules,
        "scope_source": "Explicit selected=true group references in original profile; one rule per group; no inheritance"}


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main(repo, receipts):
    repo, receipts = Path(repo), Path(receipts)
    benchmark = repo / "STIG/U_RHEL_9_V2R10_STIG_SCAP_1-3_Benchmark.xml"
    scope = declared_scope(benchmark)
    save(receipts / "declared-scope.json", scope)
    engine = json.loads((receipts / "engine-state.json").read_text())
    xml = receipts / "image-xccdf.xml"
    summary = {"engine_state": engine, "evaluation_attempts": 1,
        "expected_rule_count": len(scope["expected_rule_ids"]),
        "benchmark_sha256": hashlib.sha256(benchmark.read_bytes()).hexdigest(),
        "xccdf_available": xml.is_file(), "raw_status_counts": None,
        "security_coverage_established": False, "platform_applicability": "unverified", "compliance_claim": False}
    if (receipts / "harness-config.json").exists():
        summary["harness"] = json.loads((receipts / "harness-config.json").read_text())
    if xml.is_file():
        result = list(ET.parse(xml).getroot().iter(X + "TestResult"))
        assert len(result) == 1
        summary["raw_status_counts"] = dict(Counter(r.findtext(X + "result")
            for r in result[0].findall(X + "rule-result")))
        summary["test_result_id"] = result[0].get("id")
        summary["test_result_attributes"] = result[0].attrib
        observed = {r.get("idref") for r in result[0].findall(X + "rule-result")}
        summary["missing_expected_rule_ids"] = sorted(set(scope["expected_rule_ids"]) - observed)
        summary["unexpected_rule_ids"] = sorted(observed - set(scope["expected_rule_ids"]))
        summary["declared_results_present"] = not summary["missing_expected_rule_ids"]
        if (receipts / "acceptance-summary.json").exists():
            summary["import_acceptance"] = json.loads((receipts / "acceptance-summary.json").read_text())["backends"]
        else:
            summary["import_acceptance"] = "not performed by this evidence recorder"
    else:
        summary["reason"] = "Engine aborted without XCCDF; no valid TestResult or import manifest can be supplied"
        summary["import_acceptance"] = {backend: {"import": "not attempted", "findings": "unverified",
            "reports": "unverified", "restart_persistence": "unverified"} for backend in ("json", "sqlite")}
    save(receipts / "result-summary.json", summary)
    hashes = {p.name: {"bytes": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
              for p in receipts.iterdir() if p.is_file() and p.name != "receipt-sha256.json"}
    save(receipts / "receipt-sha256.json", hashes)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main(*sys.argv[1:])
