import json
import tempfile
import unittest
from pathlib import Path

from cyberthunder.findings.schema import (Finding, Severity, Status, dump_findings,
                                 extract_references, load_findings, summarize)
from cyberthunder.parsers.cklb import parse_cklb
from cyberthunder.parsers.xccdf import parse_xccdf

FIX = Path(__file__).parent / "fixtures"


class TestSchema(unittest.TestCase):
    def test_severity_parse(self):
        self.assertEqual(Severity.parse("HIGH"), Severity.HIGH)
        self.assertEqual(Severity.parse("CAT II"), Severity.MEDIUM)
        self.assertEqual(Severity.parse("3"), Severity.LOW)
        self.assertEqual(Severity.parse(None), Severity.UNKNOWN)
        self.assertEqual(Severity.HIGH.cat, "CAT I")
        self.assertGreater(Severity.HIGH.rank, Severity.LOW.rank)

    def test_status_maps(self):
        self.assertEqual(Status.from_xccdf("fail"), Status.OPEN)
        self.assertEqual(Status.from_xccdf("pass"), Status.NOT_A_FINDING)
        self.assertEqual(Status.from_xccdf("notapplicable"), Status.NOT_APPLICABLE)
        self.assertIsNone(Status.from_xccdf("notselected"))
        self.assertEqual(Status.from_cklb("Not_A_Finding"), Status.NOT_A_FINDING)
        self.assertEqual(Status.from_cklb("Open"), Status.OPEN)
        self.assertEqual(Status.from_cklb(None), Status.NOT_REVIEWED)

    def test_finding_id_stable_and_roundtrip(self):
        a = Finding(host="h1", source="openscap", rule_id="r1", title="t", severity="high", status="open")
        b = Finding(host="h1", source="openscap", rule_id="r1", title="other", severity="low", status="open")
        self.assertEqual(a.id, b.id)
        self.assertNotEqual(a.id, Finding(host="h2", source="openscap", rule_id="r1", title="t",
                                          severity="high", status="open").id)
        d = a.to_dict()
        self.assertEqual(d["severity"], "high")
        self.assertEqual(Finding.from_dict(json.loads(json.dumps(d))), a)

    def test_extract_references(self):
        refs = extract_references(["SV-257777r925318_rule V-257777 RHEL-09-211010 CCI-000366 CCE-90592-1 CVE-2024-6387",
                                   "SV-257777r925318_rule"])  # duplicate must dedupe
        systems = {(r.system, r.id) for r in refs}
        self.assertIn(("stig_rule", "SV-257777r925318_rule"), systems)
        self.assertIn(("group", "V-257777"), systems)
        self.assertIn(("stig_id", "RHEL-09-211010"), systems)
        self.assertIn(("cci", "CCI-000366"), systems)
        self.assertIn(("cce", "CCE-90592-1"), systems)
        self.assertIn(("cve", "CVE-2024-6387"), systems)
        self.assertEqual(len(refs), 6)

    def test_dump_load_summarize(self):
        f1 = Finding(host="h1", source="x", rule_id="a", title="t", severity="high", status="open")
        f2 = Finding(host="h2", source="x", rule_id="b", title="t", severity="low", status="not_a_finding")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "f.json"
            dump_findings([f1, f2], p, meta={"k": 1})
            back = load_findings(p)
        self.assertEqual(back, [f1, f2])
        s = summarize(back)
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["hosts"], ["h1", "h2"])
        self.assertEqual(s["open_by_severity"]["high"], 1)
        self.assertEqual(s["by_status"]["not_a_finding"], 1)


class TestXccdf(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = parse_xccdf(FIX / "sample_results.xccdf.xml")
        cls.by_rule = {f.rule_id: f for f in cls.res.findings}

    def test_benchmark_and_catalog(self):
        self.assertEqual(self.res.benchmark_id, "xccdf_org.ssgproject.content_benchmark_RHEL-9")
        self.assertTrue(self.res.benchmark_title.startswith("Guide to the Secure Configuration"))
        self.assertEqual(self.res.benchmark_release, "0.1.76")
        self.assertEqual(len(self.res.rules), 4)
        self.assertEqual(self.res.profile, "xccdf_org.ssgproject.content_profile_stig")
        self.assertEqual(self.res.targets, ["acd-target-01.range.local"])

    def test_results_counts(self):
        # 6 rule-results, notselected skipped -> 5 findings, 3 open
        self.assertEqual(len(self.res.findings), 5)
        self.assertEqual(len(self.res.open_findings), 3)
        self.assertNotIn("xccdf_org.ssgproject.content_rule_unselected", self.by_rule)

    def test_ssg_rule_with_fix_script(self):
        f = self.by_rule["xccdf_org.ssgproject.content_rule_sshd_disable_root_login"]
        self.assertEqual(f.host, "acd-target-01.range.local")
        self.assertEqual(f.status, Status.OPEN)
        self.assertEqual(f.severity, Severity.MEDIUM)
        self.assertEqual(f.rule_version, "RHEL-09-255045")
        self.assertIn("PermitRootLogin no", f.fix_script)
        self.assertIn("lineinfile", f.fix_ansible)
        self.assertIn("CCI-000366", f.ref_ids("cci"))
        self.assertIn("CCE-90592-1", f.ref_ids("cce"))
        self.assertIn("SV-257985r925942_rule", f.ref_ids("stig_rule"))
        self.assertIn("RHEL-09-255045", f.citations)
        self.assertIn("/etc/ssh/sshd_config", f.description)
        self.assertEqual(f.collected_at, "2026-11-04T14:03:40+00:00")

    def test_disa_style_rule(self):
        f = self.by_rule["SV-257777r925318_rule"]
        self.assertEqual(f.group_id, "V-257777")
        self.assertEqual(f.rule_version, "RHEL-09-211010")
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertTrue(f.description.startswith("An operating system release"))
        self.assertNotIn("VulnDiscussion", f.description)
        self.assertIn("cat /etc/redhat-release", f.check_text)
        self.assertIn("Found release", f.evidence)
        self.assertEqual(f.fix_text, "Upgrade to a supported version of RHEL 9.")

    def test_unknown_rule_and_na(self):
        self.assertEqual(self.by_rule["xccdf_org.ssgproject.content_rule_na_thing"].status, Status.NOT_APPLICABLE)
        u = self.by_rule["xccdf_org.ssgproject.content_rule_not_in_catalog"]
        self.assertEqual(u.status, Status.OPEN)
        self.assertEqual(u.title, u.rule_id)
        self.assertEqual(u.severity, Severity.LOW)

    def test_host_override(self):
        res = parse_xccdf(FIX / "sample_results.xccdf.xml", host="override.local", source="scc")
        self.assertTrue(all(f.host == "override.local" and f.source == "scc" for f in res.findings))


class TestCklb(unittest.TestCase):
    def test_parse(self):
        fl = parse_cklb(FIX / "sample.cklb")
        self.assertEqual(len(fl), 4)
        self.assertTrue(all(f.host == "acd-target-02" for f in fl))
        self.assertEqual([f.status for f in fl],
                         [Status.OPEN, Status.NOT_A_FINDING, Status.NOT_APPLICABLE, Status.NOT_REVIEWED])
        f = fl[0]
        self.assertEqual(f.rule_id, "SV-254239r848540_rule")
        self.assertEqual(f.group_id, "V-254239")
        self.assertEqual(f.rule_version, "WN22-00-000010")
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertEqual(f.benchmark, "Microsoft Windows Server 2022")
        self.assertEqual(f.benchmark_release, "Release: 2 Benchmark Date: 24 Jan 2026")
        self.assertIn("CCI-000366", f.ref_ids("cci"))
        self.assertIn("svc_backup", f.evidence)
        self.assertEqual(f.source, "evaluate-stig")
        self.assertEqual(f.collected_at, "2026-11-04T14:12:30.000Z")


if __name__ == "__main__":
    unittest.main()
