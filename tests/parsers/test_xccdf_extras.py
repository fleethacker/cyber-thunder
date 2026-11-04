from pathlib import Path

from cyberthunder.parsers.xccdf import parse_xccdf

SAMPLE = Path(__file__).resolve().parent.parent / "fixtures" / "sample_results.xccdf.xml"
SSH = "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"


def test_fix_attributes_in_rulemeta_and_tags():
    res = parse_xccdf(SAMPLE)
    assert res.rules[SSH].fix_attrs == {"complexity": "low", "disruption": "low", "reboot": "false",
                                        "strategy": "restrict"}
    f = next(x for x in res.findings if x.rule_id == SSH)
    for t in ("fix:complexity=low", "fix:disruption=low", "fix:reboot=false", "fix:strategy=restrict"):
        assert t in f.tags


def test_srg_from_group_title():
    res = parse_xccdf(SAMPLE)
    assert res.rules["SV-257777r925318_rule"].srg == "SRG-OS-000480-GPOS-00227"
    f = next(x for x in res.findings if x.rule_id == "SV-257777r925318_rule")
    assert "srg:SRG-OS-000480-GPOS-00227" in f.tags


def test_no_attrs_no_tags():
    res = parse_xccdf(SAMPLE)
    meta = res.rules["SV-257777r925318_rule"]
    assert meta.fix_attrs == {}
    f = next(x for x in res.findings if x.rule_id == "SV-257777r925318_rule")
    assert not [t for t in f.tags if t.startswith("fix:")]
    na = next(x for x in res.findings if x.rule_id.endswith("na_thing"))
    assert na.tags == []


def test_ssg_group_is_not_a_group_id():
    # SSG Groups are categories (content_group_ssh); only a V-id may become group_id.
    res = parse_xccdf(SAMPLE)
    f = next(x for x in res.findings if x.rule_id == SSH)
    assert f.group_id is None or f.group_id.startswith("V-")
    assert res.rules[SSH].group_id is None


def test_xccdf12_disa_group_id_reduced_to_vid(tmp_path):
    p = tmp_path / "disa12.xml"
    p.write_text(
        '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_mil.disa.stig_benchmark_X">'
        '<Group id="xccdf_mil.disa.stig_group_V-257985"><title>SRG-OS-000109-GPOS-00056</title>'
        '<Rule id="xccdf_mil.disa.stig_rule_SV-257985r925942_rule" severity="medium"><title>t</title>'
        '<version>RHEL-09-255045</version></Rule></Group>'
        '<TestResult id="r"><target>h1</target>'
        '<rule-result idref="xccdf_mil.disa.stig_rule_SV-257985r925942_rule"><result>fail</result></rule-result>'
        '</TestResult></Benchmark>', encoding="utf-8")
    res = parse_xccdf(p)
    assert res.findings[0].group_id == "V-257985"
