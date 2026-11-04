from __future__ import annotations

import json
import os

import pytest

from cyberthunder.ingest.content import fetch as fx
from cyberthunder.ingest.content.http import ContentClient, HostNotAllowed
from cyberthunder.ingest.content.index import Entry, parse_filename
from cyberthunder.ingest.link import LinkState
from tests.ingest.content_helpers import loopback_client, scap_zip, stig_zip

NAME = "U_MS_Windows_11_V2R11_STIG.zip"


def entry(url, name=NAME):
    info = parse_filename(name)
    return Entry(filename=name, url=url, host="127.0.0.1", title=name, kind=info["kind"],
                 product_key=info["product_key"], version=info["version"], version_label=info["version_label"])


@pytest.fixture
def stig_bytes(tmp_path):
    # pad with an uncompressed member so the file is large enough to cut part way through
    p = stig_zip(tmp_path / NAME)
    import zipfile
    with zipfile.ZipFile(p, "a", zipfile.ZIP_STORED) as zf:
        zf.writestr("U_MS_Windows_11_V2R11_STIG/padding.bin", os.urandom(300_000))
    return p.read_bytes()


def no_sleep(_s):
    pass


def test_full_download_with_estimate_and_progress(tmp_path, file_server, stig_bytes):
    url = file_server.add(NAME, stig_bytes)
    seen = []
    link = LinkState(kbps=56.0, latency_ms=500)
    res = fx.download(loopback_client(), entry(url), tmp_path / "out", link=link, progress=seen.append, sleep=no_sleep)
    out = tmp_path / "out" / NAME
    assert out.read_bytes() == stig_bytes and res.bytes == len(stig_bytes)
    import hashlib
    assert res.sha256 == hashlib.sha256(stig_bytes).hexdigest() and res.etag == '"v1"'
    assert seen[0]["state"] == "starting" and seen[0]["total"] == len(stig_bytes)
    assert seen[0]["estimate_seconds"] == pytest.approx(len(stig_bytes) * 8 / 56000 + 0.5, abs=1e-3)
    assert seen[-1]["state"] == "done"
    assert not (tmp_path / "out" / (NAME + ".part")).exists()
    heads = [r for r in file_server.requests if r["method"] == "HEAD"]
    assert len(heads) == 1 and heads[0]["headers"]["User-Agent"].startswith("cyber-thunder/")


def test_resume_after_cut_at_40_percent(tmp_path, file_server, stig_bytes):
    url = file_server.add(NAME, stig_bytes, cuts=1, cut_at=0.4)
    with pytest.raises(fx.ContentError) as ei:
        fx.download(loopback_client(), entry(url), tmp_path / "out", retries=0, sleep=no_sleep)
    assert ei.value.resumable
    part = tmp_path / "out" / (NAME + ".part")
    assert 0 < part.stat().st_size < len(stig_bytes)
    have = part.stat().st_size
    res = fx.download(loopback_client(), entry(url), tmp_path / "out", sleep=no_sleep)
    assert res.resumed and not res.restarted
    assert (tmp_path / "out" / NAME).read_bytes() == stig_bytes
    second = file_server.gets(NAME)[-1]["headers"]
    assert second["Range"] == f"bytes={have}-" and second["If-Range"] == '"v1"'


def test_cut_connection_is_retried_inside_one_call(tmp_path, file_server, stig_bytes):
    url = file_server.add(NAME, stig_bytes, cuts=1, cut_at=0.4)
    res = fx.download(loopback_client(), entry(url), tmp_path / "out", sleep=no_sleep)
    assert res.resumed and (tmp_path / "out" / NAME).read_bytes() == stig_bytes
    assert len(file_server.gets(NAME)) == 2


def test_restart_when_the_etag_changes(tmp_path, file_server, stig_bytes):
    url = file_server.add(NAME, stig_bytes, cuts=1, cut_at=0.4)
    with pytest.raises(fx.ContentError):
        fx.download(loopback_client(), entry(url), tmp_path / "out", retries=0, sleep=no_sleep)
    file_server.files[NAME]["etag"] = '"v2"'              # DISA republished the file in between
    res = fx.download(loopback_client(), entry(url), tmp_path / "out", sleep=no_sleep)
    assert res.restarted and not res.resumed and res.etag == '"v2"'
    assert "Range" not in file_server.gets(NAME)[-1]["headers"]
    assert (tmp_path / "out" / NAME).read_bytes() == stig_bytes


def test_restart_when_the_server_ignores_the_range(tmp_path, file_server, stig_bytes):
    url = file_server.add(NAME, stig_bytes, cuts=1, cut_at=0.4)
    with pytest.raises(fx.ContentError):
        fx.download(loopback_client(), entry(url), tmp_path / "out", retries=0, sleep=no_sleep)
    file_server.files[NAME]["ignore_range"] = True
    res = fx.download(loopback_client(), entry(url), tmp_path / "out", sleep=no_sleep)
    assert res.restarted and (tmp_path / "out" / NAME).read_bytes() == stig_bytes


def test_size_cap_on_content_length(tmp_path, file_server, stig_bytes):
    url = file_server.add(NAME, stig_bytes)
    with pytest.raises(fx.SizeCapExceeded):
        fx.download(loopback_client(), entry(url), tmp_path / "out", max_bytes=1000)
    assert file_server.gets(NAME) == []                   # refused on the HEAD, before the first byte
    assert not (tmp_path / "out" / NAME).exists()


def test_size_cap_on_bytes_read(tmp_path, stig_bytes):
    """A server that understates Content-Length on HEAD and sends more on GET is still stopped."""
    from tests.ingest.content_helpers import FakeOpener, FakeResponse
    big = stig_bytes
    routes = {("HEAD", "https://dl.dod.cyber.mil/"): lambda r: FakeResponse(200, b"", {"ETag": '"e"'}),
              ("GET", "https://dl.dod.cyber.mil/"): lambda r: FakeResponse(200, big, {"ETag": '"e"'})}
    client = ContentClient(opener=FakeOpener(routes))
    e = entry("https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/" + NAME)
    e.host = "dl.dod.cyber.mil"
    with pytest.raises(fx.SizeCapExceeded):
        fx.download(client, e, tmp_path / "out", max_bytes=100_000, quarantine_dir=tmp_path / "q")
    assert not (tmp_path / "out" / NAME).exists() and list((tmp_path / "q").glob("*.why.json"))


def test_non_allow_listed_host_is_refused(tmp_path, file_server, stig_bytes):
    url = file_server.add(NAME, stig_bytes)
    with pytest.raises(HostNotAllowed):
        fx.download(ContentClient(proxies={}), entry(url), tmp_path)        # production allow-list
    with pytest.raises(HostNotAllowed):
        fx.download(ContentClient(proxies={}), entry("https://example.com/" + NAME), tmp_path)
    assert file_server.requests == []


def test_bad_zip_is_quarantined(tmp_path, file_server):
    url = file_server.add(NAME, b"PK\x03\x04 this is not really a zip" * 50)
    with pytest.raises(fx.Quarantined) as ei:
        fx.download(loopback_client(), entry(url), tmp_path / "out", quarantine_dir=tmp_path / "q")
    assert not (tmp_path / "out" / NAME).exists()
    note = json.loads(next((tmp_path / "q").glob("*.why.json")).read_text(encoding="utf-8"))
    assert "zip" in note["reason"] and note["filename"] == NAME
    assert ei.value.path.exists()


def test_xccdf_parse_failure_is_quarantined(tmp_path, file_server):
    bad = tmp_path / "bad.xml"
    bad.write_text("<Benchmark><Rule id='x'>unterminated", encoding="utf-8")
    url = file_server.add(NAME, stig_zip(tmp_path / NAME, xccdf=bad).read_bytes())
    with pytest.raises(fx.Quarantined, match="XML does not parse"):
        fx.download(loopback_client(), entry(url), tmp_path / "out", quarantine_dir=tmp_path / "q")
    assert len(list((tmp_path / "q").glob("*.why.json"))) == 1


def test_scap_benchmark_checked_for_a_datastream(tmp_path, file_server):
    name = "U_MS_Windows_11_V2R11_STIG_SCAP_1-3_Benchmark.zip"
    url = file_server.add(name, scap_zip(tmp_path / name).read_bytes())
    res = fx.download(loopback_client(), entry(url, name), tmp_path / "out")
    assert res.bytes > 0
    name2 = "U_MS_Windows_11_V2R12_STIG_SCAP_1-3_Benchmark.zip"
    url2 = file_server.add(name2, scap_zip(tmp_path / name2, data=b"<html>not scap</html>").read_bytes())
    with pytest.raises(fx.Quarantined, match="not a SCAP datastream"):
        fx.download(loopback_client(), entry(url2, name2), tmp_path / "out", quarantine_dir=tmp_path / "q")


def test_pace_sleeps_to_the_link_rate(tmp_path, file_server, stig_bytes):
    url = file_server.add(NAME, stig_bytes)
    slept = []
    fx.download(loopback_client(), entry(url), tmp_path / "out", link=LinkState(kbps=8000.0, latency_ms=0), pace=True,
                sleep=slept.append)
    # 8000 kbps = 1 MB/s; the whole file should be held to roughly its size in seconds
    assert sum(slept) == pytest.approx(len(stig_bytes) / 1_000_000, rel=0.5)


def test_disk_name_is_safe():
    assert fx.disk_name("U_Splunk_Enterprise_8-x_for Linux_V2R3_STIG.zip") == "U_Splunk_Enterprise_8-x_for_Linux_V2R3_STIG.zip"
    assert fx.disk_name("../../etc/passwd") == "passwd"
    assert fx.disk_name("..\\..\\x.zip") == "x.zip"
