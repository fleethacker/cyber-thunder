from pathlib import Path

from cyberthunder.findings.schema import Severity, Status
from cyberthunder.parsers.nessus import parse_nessus, parse_nessus_hosts

SAMPLE = Path(__file__).resolve().parent.parent / "fixtures" / "parsers" / "sample.nessus"


def by_key(findings):
    return {(f.host, f.rule_id): f for f in findings}


def test_counts_skip_info_and_merge_ports():
    fs = parse_nessus(SAMPLE)
    # 7 report items: 1 info skipped, plugin 51192 on two ports merges into one finding
    assert len(fs) == 5
    assert {f.host for f in fs} == {"ws-014.enclave.example", "10.20.1.30"}
    assert all(f.source == "acas" and f.status == Status.OPEN for f in fs)
    assert len({f.id for f in fs}) == len(fs)


def test_include_info():
    fs = parse_nessus(SAMPLE, include_info=True)
    assert len(fs) == 6
    info = by_key(fs)[("ws-014.enclave.example", "nessus:19506")]
    assert info.severity == Severity.INFO
    assert info.status != Status.OPEN


def test_severity_mapping():
    m = by_key(parse_nessus(SAMPLE))
    assert m[("ws-014.enclave.example", "nessus:97833")].severity == Severity.HIGH      # stig_severity I
    assert m[("ws-014.enclave.example", "nessus:18405")].severity == Severity.MEDIUM    # nessus 2
    assert m[("10.20.1.30", "nessus:187315")].severity == Severity.HIGH                 # nessus 3
    assert m[("10.20.1.30", "nessus:51192")].severity == Severity.LOW                   # stig III beats nessus 2
    assert m[("10.20.1.30", "nessus:71049")].severity == Severity.LOW                   # nessus 1


def test_references_cve_iavm_cwe():
    m = by_key(parse_nessus(SAMPLE))
    smb = m[("ws-014.enclave.example", "nessus:97833")]
    assert smb.ref_ids("cve") == ["CVE-2017-0143", "CVE-2017-0144"]
    assert smb.ref_ids("iavm") == ["2017-A-0065"]
    assert "MS17-010" in smb.ref_ids("other")
    ssh = m[("10.20.1.30", "nessus:187315")]
    assert ssh.ref_ids("iavm") == ["2024-B-0003"]
    assert "CWE-327" in m[("10.20.1.30", "nessus:71049")].ref_ids("other")


def test_fields_tags_and_fix():
    smb = by_key(parse_nessus(SAMPLE))[("ws-014.enclave.example", "nessus:97833")]
    assert smb.title.startswith("MS17-010")
    assert smb.fix_ref == "patch:97833"
    assert "SMBv1" in smb.fix_text
    assert smb.description.startswith("The remote Windows host is affected by multiple vulnerabilities.")
    assert smb.evidence == "KB4012212 is not installed. [445/tcp]"
    assert smb.benchmark == "ACAS (Nessus) Enclave-B Weekly"
    assert smb.asset_type == "windows"
    for t in ("family:Windows : Microsoft Bulletins", "port:445/tcp", "cvss3:8.1", "exploit_available"):
        assert t in smb.tags
    assert by_key(parse_nessus(SAMPLE))[("10.20.1.30", "nessus:187315")].asset_type == "linux"
    assert "exploit_available" not in by_key(parse_nessus(SAMPLE))[("10.20.1.30", "nessus:187315")].tags


def test_multi_port_plugin_merged():
    f = by_key(parse_nessus(SAMPLE))[("10.20.1.30", "nessus:51192")]
    assert "port:443/tcp" in f.tags and "port:8443/tcp" in f.tags
    assert "[443/tcp]" in f.evidence and "[8443/tcp]" in f.evidence


def test_host_override_and_source():
    fs = parse_nessus(SAMPLE, host="range-1", source="acas-test")
    assert {f.host for f in fs} == {"range-1"}
    assert {f.source for f in fs} == {"acas-test"}
    assert len({f.id for f in fs}) == len(fs)


def test_every_finding_cites_something():
    for f in parse_nessus(SAMPLE, include_info=True):
        assert f.references, f.rule_id
        assert f.citations


def test_long_text_trimmed(tmp_path):
    big = "x" * 5000
    p = tmp_path / "big.nessus"
    p.write_text(
        '<NessusClientData_v2><Report name="r"><ReportHost name="h"><HostProperties/>'
        f'<ReportItem port="1" protocol="tcp" severity="3" pluginID="9" pluginName="n" pluginFamily="f">'
        f'<description>{big}</description><plugin_output>{big}</plugin_output></ReportItem>'
        '</ReportHost></Report></NessusClientData_v2>', encoding="utf-8")
    (f,) = parse_nessus(p)
    assert len(f.description) <= 1500
    assert len(f.evidence) < 1100
    assert f.ref_ids("nessus") == ["nessus:9"]       # no CVE or advisory: cites the plugin id


def test_hosts_listing():
    hosts = parse_nessus_hosts(SAMPLE)
    assert hosts == [
        {"name": "ws-014.enclave.example", "ip": "10.20.1.14", "os": "Microsoft Windows 10 Enterprise",
         "fqdn": "ws-014.enclave.example"},
        {"name": "10.20.1.30", "ip": "10.20.1.30", "os": "Linux Kernel 5.14 on Red Hat Enterprise Linux 9",
         "fqdn": "app-30.enclave.example"},
    ]


def test_unknown_xref_keeps_its_kind(tmp_path):
    p = tmp_path / "x.nessus"
    p.write_text(
        '<NessusClientData_v2><Report name="r"><ReportHost name="h"><HostProperties/>'
        '<ReportItem port="1" protocol="tcp" severity="2" pluginID="9" pluginName="n" pluginFamily="f">'
        '<xref>CERT:123456</xref><xref>MSFT:MS17-010</xref></ReportItem>'
        '</ReportHost></Report></NessusClientData_v2>', encoding="utf-8")
    (f,) = parse_nessus(p)
    assert f.ref_ids("other") == ["CERT:123456", "MS17-010"]


_CM = "http://www.nessus.org/cm"


def _compliance_export(tmp_path, items):
    body = "".join(
        f'<ReportItem port="0" svc_name="general" protocol="tcp" severity="{sev}" pluginID="21156" '
        f'pluginName="Windows Compliance Checks" pluginFamily="Policy Compliance">'
        f'<cm:compliance-check-name>{name}</cm:compliance-check-name>'
        f'<cm:compliance-check-id>{cid}</cm:compliance-check-id>'
        f'<cm:compliance-result>{result}</cm:compliance-result>'
        f'<cm:compliance-reference>800-53|CM-6b.,CAT|II,CCI|CCI-000366,STIG-ID|{stig},Vuln-ID|{vid}'
        f'</cm:compliance-reference></ReportItem>'
        for sev, name, cid, result, stig, vid in items)
    p = tmp_path / "audit.nessus"
    p.write_text(f'<NessusClientData_v2 xmlns:cm="{_CM}"><Report name="Audit">'
                 f'<ReportHost name="ws-1"><HostProperties><tag name="operating-system">Windows 11</tag>'
                 f'</HostProperties>{body}</ReportHost></Report></NessusClientData_v2>', encoding="utf-8")
    return p


def test_compliance_items_one_finding_per_check(tmp_path):
    p = _compliance_export(tmp_path, [
        ("3", "WN11-SO-000010 - Guest account disabled", "aaa1", "FAILED", "WN11-SO-000010", "V-253434"),
        ("3", "WN11-AC-000035 - Minimum password length", "bbb2", "FAILED", "WN11-AC-000035", "V-253302"),
        ("0", "WN11-AC-000040 - Complexity", "ccc3", "PASSED", "WN11-AC-000040", "V-253303"),
    ])
    fs = by_key(parse_nessus(p, include_info=True))
    assert set(fs) == {("ws-1", "WN11-SO-000010"), ("ws-1", "WN11-AC-000035"), ("ws-1", "WN11-AC-000040")}
    guest = fs[("ws-1", "WN11-SO-000010")]
    assert guest.status == Status.OPEN
    assert guest.severity == Severity.MEDIUM
    assert guest.group_id == "V-253434"
    assert guest.title.startswith("WN11-SO-000010")
    assert "WN11-SO-000010" in [r.id for r in guest.references]
    assert "nessus:21156" not in [r.id for r in guest.references]
    assert "CCI-000366" in guest.ref_ids("cci")
    assert fs[("ws-1", "WN11-AC-000040")].status == Status.NOT_A_FINDING
    # without include_info the passed (severity 0) check is skipped as before
    assert len(parse_nessus(p)) == 2


def test_out_of_range_severity_is_unknown_not_open(tmp_path):
    p = tmp_path / "bad.nessus"
    p.write_text('<NessusClientData_v2><Report name="r"><ReportHost name="h">'
                 '<ReportItem port="22" protocol="tcp" severity="99" pluginID="1" pluginName="odd"/>'
                 '</ReportHost></Report></NessusClientData_v2>', encoding="utf-8")
    (f,) = parse_nessus(p)
    assert f.severity == Severity.UNKNOWN
    assert f.status != Status.OPEN
