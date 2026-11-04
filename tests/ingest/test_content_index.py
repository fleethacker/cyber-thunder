from __future__ import annotations

import json

import pytest

from cyberthunder.ingest.content import index as ix
from cyberthunder.ingest.content.http import ContentClient, HostNotAllowed
from tests.ingest.content_helpers import (SNAPSHOT, FakeOpener, FakeResponse, apex_answer, record,
                                          snapshot_records)

KINDS = set(ix.KINDS)


def test_parse_filename_on_every_name_in_the_snapshot():
    entries = ix.load_snapshot(SNAPSHOT)
    assert len(entries) == 417
    for e in entries:
        info = ix.parse_filename(e.filename)
        assert info["kind"] in KINDS
        if e.filename.lower().endswith(".zip") and e.filename.startswith("U_") and info["kind"] in (
                "manual_stig", "scap_benchmark", "srg"):
            assert info["product_key"], e.filename
    hosts = {e.host for e in entries}
    assert sum(e.host == "dl.dod.cyber.mil" for e in entries) == 412
    assert "dl.cyber.mil" in hosts                           # one stray host the allow-list does not cover
    assert sum(e.filename.lower().endswith(".zip") for e in entries) >= 384
    assert all("​" not in e.title and "�" not in e.title for e in entries)


@pytest.mark.parametrize("name,kind,product,version", [
    ("U_RHEL_9_V2R10_STIG.zip", "manual_stig", "RHEL_9", (2, 10)),
    ("U_RHEL_9_V2R10_STIG_SCAP_1-3_Benchmark.zip", "scap_benchmark", "RHEL_9", (2, 10)),
    ("U_MS_Windows_11_V2R11_STIG.zip", "manual_stig", "MS_Windows_11", (2, 11)),
    ("U_MS_Windows_11_V2R11_STIG_SCAP_1-3_Benchmark.zip", "scap_benchmark", "MS_Windows_11", (2, 11)),
    ("U_MS_Windows_Server_2022_V2R11_STIG.zip", "manual_stig", "MS_Windows_Server_2022", (2, 11)),
    ("U_MS_Windows_Server_2022_V2R11_STIG_SCAP_1-3_Benchmark.zip", "scap_benchmark", "MS_Windows_Server_2022", (2, 11)),
    ("U_Cisco_IOS_Switch_Y26M10_STIG.zip", "manual_stig", "Cisco_IOS_Switch", (26, 10)),
    ("U_Cisco_IOS-XE_Switch_Y26M01_STIG.zip", "manual_stig", "Cisco_IOS-XE_Switch", (26, 1)),
    ("U_Cisco_IOS-XE_Router_Y26M04_STIG.zip", "manual_stig", "Cisco_IOS-XE_Router", (26, 4)),
    ("U_Kubernetes_V2R6_STIG.zip", "manual_stig", "Kubernetes", (2, 6)),
    ("U_Kubernetes_V2R5_STIG_SCAP_1-3_Benchmark.zip", "scap_benchmark", "Kubernetes", (2, 5)),
    ("U_Container_Platform_V2R5_SRG.zip", "srg", "Container_Platform", (2, 5)),
    ("U_Active_Directory_Domain_V3R8_STIG.zip", "manual_stig", "Active_Directory_Domain", (3, 8)),
    ("U_Active_Directory_Forest_V3R2_STIG.zip", "manual_stig", "Active_Directory_Forest", (3, 2)),
    ("U_CAN_Ubuntu_22-04_LTS_V2R10_STIG.zip", "manual_stig", "CAN_Ubuntu_22-04", (2, 10)),
    ("U_SRG-STIG_Library_October_2026.zip", "compilation", "SRG-STIG_Library", None),
    ("U_RHEL_9_V2R10_STIG_Ansible.zip", "automation", "RHEL_9", (2, 10)),
    ("U_MS_Windows_11_V1R3_STIG_Chef.zip", "automation", "MS_Windows_11", (1, 3)),
    ("scc-5.15_Windows_bundle.zip", "tool", "SCC", None),
    ("U_STIG_Viewer_3-x_User_Guide_V1R8.pdf", "document", "STIG_Viewer_3-x_User_Guide", (1, 8)),
])
def test_parse_filename_examples(name, kind, product, version):
    info = ix.parse_filename(name)
    assert (info["kind"], info["product_key"], info["version"]) == (kind, product, version)


def test_year_month_releases_compare_newer_than_version_release():
    assert ix.parse_filename("U_Cisco_IOS_Switch_Y26M10_STIG.zip")["version"] > (3, 9)
    assert ix.parse_filename("U_X_Y26M10_STIG.zip")["version"] > ix.parse_filename("U_X_Y26M04_STIG.zip")["version"]


def test_snapshot_examples_and_sunset_flag():
    by = {e.filename: e for e in ix.load_snapshot(SNAPSHOT)}
    rhel = by["U_RHEL_9_V2R10_STIG.zip"]
    assert rhel.upload_date == "2026-10-05" and not rhel.sunset and rhel.allowed
    assert rhel.url == "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R10_STIG.zip"
    assert by["U_RHEL_8_V2R9_STIG.zip"].sunset
    assert by["U_SRG-STIG_Library_October_2026.zip"].kind == "compilation"


def test_titles_are_cleaned():
    recs = [record("U_A_V1R1_STIG.zip", "https://dl.dod.cyber.mil/x/U_A_V1R1_STIG.zip", title="A​ STIG �")]
    assert ix.entries_from_records(recs)[0].title == "A STIG"


def _client(routes):
    return ContentClient(opener=FakeOpener(routes))


def test_fetch_index_with_the_known_class_and_gzip():
    seen = {}

    def apex(req):
        seen["body"] = json.loads(req.data)
        seen["headers"] = {k.lower(): v for k, v in req.header_items()}
        return apex_answer(snapshot_records(), gzip_it=True)

    res = ix.fetch_index_result(_client({("POST", ix.APEX_URL): apex}))
    assert len(res.entries) == 417 and res.gzip and res.wire_bytes < res.bytes
    assert res.classname == ix.KNOWN_CLASSNAME and not res.rediscovered
    assert seen["body"]["classname"] == ix.KNOWN_CLASSNAME and seen["body"]["params"] == {"documentLibrary": "STIGs"}
    assert seen["headers"]["content-type"] == "application/json"
    assert seen["headers"]["accept-encoding"] == "gzip"
    assert seen["headers"]["user-agent"].startswith("cyber-thunder/")


PAGE = (b'<html><script src="/webruntime/view/0a1b2c3d4e5f/prod/en-US/sTIGs_Document_Library_view?asGuest=true">'
        b'</script></html>')
BUNDLE = (b'define("x",function(){const a=getApexInvoker("", "@udd/01pNEWCLASS00", '
          b'"getCyberDocumentCatalogByDocumentLibrary", false);})')


def test_self_heal_rediscovers_the_class_id():
    calls = []

    def apex(req):
        cls = json.loads(req.data)["classname"]
        calls.append(cls)
        if cls == "@udd/01pNEWCLASS00":
            return apex_answer(snapshot_records()[:5])
        return FakeResponse(200, b"<html>Sorry</html>", {"Content-Type": "text/html"})

    routes = {("POST", ix.APEX_URL): apex,
              ("GET", ix.DOWNLOADS_PAGE): lambda r: FakeResponse(200, PAGE, {"Content-Type": "text/html"}),
              ("GET", "https://www.cyber.mil/webruntime/view/0a1b2c3d4e5f/"):
                  lambda r: FakeResponse(200, BUNDLE, {"Content-Type": "application/javascript"})}
    found = []
    res = ix.fetch_index_result(_client(routes), on_discover=found.append)
    assert calls == [ix.KNOWN_CLASSNAME, "@udd/01pNEWCLASS00"]
    assert res.rediscovered and res.classname == "@udd/01pNEWCLASS00" and len(res.entries) == 5
    assert found == ["@udd/01pNEWCLASS00"]


def test_self_heal_gives_up_with_a_reason():
    routes = {("POST", ix.APEX_URL): lambda r: FakeResponse(500, b"", {}),
              ("GET", ix.DOWNLOADS_PAGE): lambda r: FakeResponse(200, b"<html></html>", {"Content-Type": "text/html"})}
    with pytest.raises(ix.IndexFetchError, match="view bundle"):
        ix.fetch_index(_client(routes))


def test_client_refuses_hosts_and_plain_http():
    c = ContentClient(opener=FakeOpener({}))
    for url in ("https://example.com/x.zip", "http://dl.dod.cyber.mil/x.zip", "https://dl.cyber.mil/x.zip",
                "https://user:pw@dl.dod.cyber.mil/x.zip"):
        with pytest.raises(HostNotAllowed):
            c.request("GET", url)
    assert c.allowed_hosts == {"www.cyber.mil", "dl.dod.cyber.mil"}


def test_redirect_off_the_allow_list_is_refused():
    c = ContentClient(opener=FakeOpener({}))
    red = [h for h in c.build_opener().handlers if h.__class__.__name__ == "_AllowListRedirects"][0]
    import urllib.request
    req = urllib.request.Request("https://dl.dod.cyber.mil/a.zip")
    with pytest.raises(HostNotAllowed):
        red.redirect_request(req, None, 302, "Found", {}, "https://evil.example/a.zip")
    assert red.redirect_request(req, None, 302, "Found", {}, "https://dl.dod.cyber.mil/b.zip") is not None
