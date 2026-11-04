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
