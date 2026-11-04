"""Loading the trimmed DISA Windows 11 datastream: counts, profiles, check-ref resolution, rule support, the
bare XCCDF + OVAL form, subsetting, collection plans and benchmark evaluation from collected data."""
import json
import xml.etree.ElementTree as ET

import pytest

from cyberthunder.scap.benchmark import BenchmarkEvaluator, evaluate, to_findings
from cyberthunder.scap.datastream import load, load_cached, rules_for, short_rule_id
from cyberthunder.scap.oval.windows_probes import SUPPORTED
from cyberthunder.scap.subset import subset
from cyberthunder.scap.windows_plan import (SCRIPT_MARKER, build_plan, collect_benchmark, merge_data, script_for,
                                            script_template, supported_rules)

OVAL_COMP = "scap_mil.disa.stig_comp_U_MS_Windows_11_V2R11_STIG_SCAP_1-3_Benchmark-oval.xml"


@pytest.fixture(scope="module")
def ds(request):
    from pathlib import Path
    return load(Path(__file__).resolve().parents[1] / "fixtures" / "scap" / "w11_subset-ds.xml")


def test_counts_and_benchmark(ds):
    b = ds.benchmark
    assert ds.kind == "datastream"
    assert b.id == "xccdf_mil.disa.stig_benchmark_Microsoft_Windows_11_STIG"
    assert b.release.startswith("Version 2 Release 11")
    c = ds.counts()
    assert (c["rules"], c["profiles"]) == (25, 11)
    assert (c["definitions"], c["tests"], c["objects"], c["states"], c["variables"]) == (52, 40, 32, 45, 4)
    assert set(ds.oval) == {OVAL_COMP, OVAL_COMP.replace("-oval.xml", "-cpe-oval.xml")}
    assert all(r.version.startswith("WN11-") and r.group_id.startswith("V-") for r in b.rules.values())


def test_check_ref_resolves_through_catalog(ds):
    r = ds.benchmark.rule("WN11-SO-000205")
    chk = r.oval_check
    assert chk.href == "U_MS_Windows_11_V2R11_STIG_SCAP_1-3_Benchmark-oval.xml"
    assert chk.component == OVAL_COMP
    assert chk.name == "oval:mil.disa.stig.windows11:def:253462"
    assert chk.name in ds.oval_for(chk).definitions
    assert r.short_id.startswith("SV-253462r") and r.short_id == short_rule_id(r.id)
    assert "CCI-000366" in r.ccis and r.severity.value == "high"
    # platforms resolve the same way
    pl = ds.benchmark.platforms["xccdf_mil.disa.stig_platform_Windows_MemberWorkstation"]
    assert pl.facts[0].component == OVAL_COMP


def test_profiles(ds):
    b = ds.benchmark
    assert len(b.selected_rules()) == 25
    assert len(b.selected_rules("xccdf_mil.disa.stig_profile_MAC-1_Classified")) == 25
    cat1 = b.selected_rules("xccdf_mil.disa.stig_profile_CAT_I_Only")
    assert cat1 and all(r.severity.value == "high" for r in cat1)
    assert len(b.selected_rules("xccdf_mil.disa.stig_profile_Disable_Slow_Rules")) < 25
    with pytest.raises(KeyError):
        b.selected_rules("xccdf_nope")
    assert {r.version for r in rules_for(ds, None, ["WN11-SO-000205", "V-253433"])} == {"WN11-SO-000205",
                                                                                         "WN11-SO-000010"}


def test_rule_support(ds):
    b = ds.benchmark
    sup = {r.version: ds.support(r, SUPPORTED) for r in b.rules.values()}
    assert not sup["WN11-AU-000515"].supported
    assert sup["WN11-AU-000515"].unsupported == {"fileeffectiverights53"}
    assert "fileeffectiverights53_test" in sup["WN11-AU-000515"].reason
    assert sum(s.supported for s in sup.values()) == 24
    assert sup["WN11-00-000165"].probes == {"registry", "wmi57"}
    assert not ds.oval[OVAL_COMP].missing([r.oval_check.name for r in b.rules.values()])


def test_bare_xccdf_and_oval_pair(ds, tmp_path):
    root = ET.parse(ds.path).getroot()
    loc = lambda t: t.rsplit("}", 1)[-1]  # noqa: E731
    comps = {c.get("id"): c for c in root if loc(c.tag) == "component"}
    bench = next(iter(comps[OVAL_COMP.replace("-oval.xml", "-xccdf.xml")]))
    oval_el = next(iter(comps[OVAL_COMP]))
    (tmp_path / "bench-xccdf.xml").write_bytes(ET.tostring(bench))
    (tmp_path / "U_MS_Windows_11_V2R11_STIG_SCAP_1-3_Benchmark-oval.xml").write_bytes(ET.tostring(oval_el))
    pair = load(tmp_path / "bench-xccdf.xml")
    assert pair.kind == "xccdf" and len(pair.benchmark.rules) == 25
    r = pair.benchmark.rule("WN11-SO-000205")
    assert r.oval_check.name in pair.oval_for(r.oval_check).definitions
    explicit = load(tmp_path / "bench-xccdf.xml", tmp_path / "U_MS_Windows_11_V2R11_STIG_SCAP_1-3_Benchmark-oval.xml")
    assert explicit.counts()["definitions"] == 51   # the CPE OVAL is not part of the pair


def test_load_rejects_other_xml(tmp_path):
    p = tmp_path / "x.xml"
    p.write_text("<html/>", encoding="utf-8")
    with pytest.raises(ValueError):
        load(p)


def test_load_cached_reuses_parse(ds):
    assert load_cached(ds.path) is load_cached(ds.path)


def test_subset_keeps_exactly_what_rules_reference(ds, tmp_path):
    out = tmp_path / "two.xml"
    counts = subset(ds.path, ["WN11-SO-000205", "WN11-SO-000010"], out)
    small = load(out)
    assert counts["rules"] == 2 and len(small.benchmark.rules) == 2
    doc = small.oval[OVAL_COMP]
    defs = [r.oval_check.name for r in small.benchmark.rules.values()]
    closure = doc.closure(defs)
    for kind in ("definitions", "tests", "objects", "states", "variables"):
        assert set(getattr(doc, kind)) == closure[kind], kind
    assert not doc.missing(defs)
    prof = small.benchmark.profiles["xccdf_mil.disa.stig_profile_MAC-1_Classified"]
    assert {i for i, _ in prof.selects} <= set(small.benchmark.rules) | {g for r in small.benchmark.rules.values()
                                                                          for g in r.groups}
    with pytest.raises(KeyError):
        subset(ds.path, ["WN11-XX-999999"], tmp_path / "bad.xml")


def test_plan_for_fixture(ds):
    rules = supported_rules(ds, ds.benchmark.selected_rules())
    plan = build_plan(ds, rules)
    p = plan.to_params()
    assert p["secedit"] and p["auditpol"] and p["accounts"]
    keys = {e["key"].lower(): e for e in p["registry"]}
    lsa = keys[r"system\currentcontrolset\control\lsa"]
    assert sorted(n.lower() for n in lsa["names"]) == ["lmcompatibilitylevel", "nolmhash"]
    assert any("win32_tpm" in q["wql"].lower() for q in p["wmi"])
    assert not plan.unplanned
    assert json.loads(json.dumps(p)) == p
    one = build_plan(ds, rules_for(ds, None, ["WN11-SO-000205"])).to_params()
    assert set(one) == {"schema", "registry"} and len(one["registry"]) == 1


def test_collection_script_template(ds):
    text = script_template()
    assert text.startswith(SCRIPT_MARKER)
    for section in ("registry", "secedit", "auditpol", "accounts", "files", "services", "wmi"):
        assert f"$plan.{section}" in text
    s = script_for({"schema": 1, "registry": []})
    assert s.splitlines()[0] == SCRIPT_MARKER and s.splitlines()[1].startswith("$CtParams = '")


def test_follow_up_round_for_variable_located_objects():
    """A key named by a local variable built from another key is collected in a second run."""
    from tests.scap.helpers import definition, oval, reg_object, reg_state, reg_test
    from cyberthunder.scap.datastream import Benchmark, CheckRef, Datastream, Rule
    from cyberthunder.findings.schema import Severity
    objects = (reg_object("o:tenant", r"(?i)SOFTWARE\\Tenants\\[0-9a-f]+", None, key_op="pattern match") +
               '<win:registry_object id="o:pin" version="1"><win:hive>HKEY_LOCAL_MACHINE</win:hive>'
               '<win:key var_ref="v"/><win:name>MinimumPINLength</win:name></win:registry_object>')
    var = ('<local_variable id="v" version="1" datatype="string" comment="c"><concat>'
           '<literal_component>SOFTWARE\\Policies\\PassportForWork\\</literal_component>'
           '<regex_capture pattern="\\\\([0-9a-f]+)$"><object_component object_ref="o:tenant" item_field="key"/>'
           '</regex_capture></concat></local_variable>')
    doc = oval(definition("d", '<criteria><criterion test_ref="t"/></criteria>'), reg_test("t", "o:pin", ["s"]),
               objects, reg_state("s", "6", op="greater than or equal"), var)
    rule = Rule(id="r1", version="WN11-XX-000001", title="PIN length", severity=Severity.MEDIUM,
                checks=[CheckRef("http://oval.mitre.org/XMLSchema/oval-definitions-5", "x.xml", "d", "c")])
    ds = Datastream(path="mem", kind="xccdf", benchmarks=[Benchmark(id="b", title="b", rules={"r1": rule})],
                    oval={"c": doc})
    host = {r"software\tenants\abc1": {}, r"software\policies\passportforwork\abc1": {"MinimumPINLength": 8}}
    plans = []

    def runner(params):
        plans.append(params)
        out = []
        for r in params.get("registry", []):
            base = r["key"].lower()
            for k, vals in host.items():
                if k == base or (r["depth"] and k.startswith(base + "\\")):
                    out.append({"hive": "HKLM", "key": k, "values": [
                        {"name": n, "kind": "DWord", "value": v} for n, v in vals.items()
                        if "*" in r["names"] or n.lower() in [x.lower() for x in r["names"]]]})
        return {"schema": 1, "registry": out}

    data, rounds = collect_benchmark(ds, [rule], runner)
    assert len(plans) == 2 and len(rounds) == 2
    assert plans[0]["registry"][0]["depth"] == 1
    assert plans[1]["registry"][0]["key"] == r"SOFTWARE\Policies\PassportForWork\abc1"
    assert evaluate(ds, [rule], data)[0].result == "pass"


def test_merge_data():
    a = {"registry": [1], "accounts": {"users": []}}
    merge_data(a, {"schema": 1, "registry": [2], "audit": [3], "accounts": {"groups": []}})
    assert a == {"registry": [1, 2], "audit": [3], "accounts": {"users": [], "groups": []}}


def test_benchmark_results_from_collected_data(ds):
    """Evaluate the fixture from a hand-written collection: two registry failures, the rest passes."""
    from cyberthunder.adapters.windows.scap_sim import answer
    from cyberthunder.adapters.windows.simhost import seed_state
    state = seed_state()
    rules = ds.benchmark.selected_rules()
    data, _ = collect_benchmark(ds, supported_rules(ds, rules), lambda p: answer(state, p))
    results = {r.rule.version: r for r in evaluate(ds, rules, data)}
    assert results["WN11-SO-000205"].result == "fail"
    assert any("LmCompatibilityLevel = 2" in e for e in results["WN11-SO-000205"].evidence)
    assert results["WN11-SO-000195"].result == "pass"
    assert results["WN11-AU-000515"].result == "notchecked"
    assert results["WN11-AU-000515"].unsupported == ["fileeffectiverights53_test"]
    assert results["WN11-UR-000075"].result == "notapplicable"
    assert "Domain Member" in results["WN11-UR-000075"].evidence[0]

    from cyberthunder.inventory.targets import Target
    t = Target(id="w", name="w", asset_type="windows", transport="simulated")
    findings = to_findings(t, ds, list(results.values()))
    assert len(findings) == 25
    assert all(f.references for f in findings)
    by = {f.rule_version: f for f in findings}
    assert by["WN11-SO-000205"].status.value == "open" and by["WN11-SO-000195"].status.value == "not_a_finding"
    assert by["WN11-AU-000515"].status.value == "not_reviewed"
    assert by["WN11-UR-000075"].status.value == "not_applicable"
    assert by["WN11-SO-000205"].benchmark_release.startswith("Version 2 Release 11")
    assert {"cci", "stig_id"} <= {r.system for r in by["WN11-SO-000205"].references}


def test_platform_undetermined_still_evaluates(ds):
    """Without WMI data the platform cannot be decided; the rule is evaluated and the evidence says so."""
    rule = ds.benchmark.rule("WN11-UR-000075")
    ev = BenchmarkEvaluator(ds, {"rights": {}})
    rr = ev.rule(rule)
    assert rr.result in ("pass", "fail")
    assert "could not be determined" in rr.evidence[0]
