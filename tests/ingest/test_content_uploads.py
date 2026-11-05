"""Local content upload contracts; synthetic inputs, both state backends, no requests or scans."""
from __future__ import annotations

import hashlib
import io
import json
import socket
import stat
import struct
import subprocess
import zipfile
from pathlib import Path

import pytest

from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.ingest.content import fetch as fx
from cyberthunder.ingest.content import uploads as up
from cyberthunder.ingest.content.http import ContentClient
from cyberthunder.ingest.content.index import Entry
from cyberthunder.ingest.content.library import ContentLibrary
from cyberthunder.ingest.content.select import select
from tests.ingest.content_helpers import W11_XCCDF

ACTOR = "IT2 Smith"
OFFICIAL = "U_MS_Windows_11_V2R11_STIG.zip"


def benchmark(*, bid="Microsoft_Windows_11_STIG", version="2", release="11", srg=False, automatic=False):
    title = "Local Security Requirements Guide" if srg else "Local Security Technical Implementation Guide"
    metadata = f'<version time="2025-01-01">{version}</version>' if version is not None else ""
    if release is not None:
        metadata += f'<plain-text id="release-info">Release: {release} Benchmark Date: 01 Jan 2025</plain-text>'
    check = '<check-content-ref href="oval.xml"/>' if automatic else '<check-content>Inspect the setting.</check-content>'
    system = "http://oval.mitre.org/XMLSchema/oval-definitions-5" if automatic else "C-100001r1_chk"
    return (f'<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="{bid}">'
            f'<status date="2025-01-01">accepted</status><title>{title}</title>{metadata}'
            '<reference href="https://example.invalid/publisher"><publisher>Local publisher</publisher></reference>'
            '<Group id="V-100001"><Rule id="SV-100001r1_rule" severity="medium">'
            '<version>TEST-000001</version><title>Check the setting</title>'
            f'<check system="{system}">{check}</check>'
            '<fix system="urn:xccdf:fix:script:sh">this must never execute</fix>'
            '</Rule></Group></Benchmark>').encode()


def datastream(**kwargs):
    return (b'<data-stream-collection xmlns="http://scap.nist.gov/schema/scap/source/1.2" id="test">'
            b'<component id="benchmark">' + benchmark(**kwargs) + b'</component></data-stream-collection>')


def archive(*members, compression=zipfile.ZIP_DEFLATED):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=compression) as zf:
        for name, data in members:
            zf.writestr(name, data)
    return out.getvalue()


@pytest.fixture(autouse=True)
def no_network_or_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("content upload attempted network access or process execution")
    monkeypatch.setattr(ContentClient, "request", forbidden)
    monkeypatch.setattr(ContentClient, "download_to", forbidden, raising=False)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.fixture
def svc(ctx, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("content upload attempted a target scan")
    monkeypatch.setattr(ctx.scanner, "start", forbidden)
    # Keep the authoritative catalog synthetic as well as the uploaded files.
    entries = [Entry(filename=OFFICIAL, url="https://dl.dod.cyber.mil/stigs/" + OFFICIAL,
                     host="dl.dod.cyber.mil", title="Windows 11", kind="manual_stig", product_key="MS_Windows_11",
                     version=(2, 11), version_label="V2R11", upload_date="2026-09-30")]
    monkeypatch.setattr(ctx.ingest.content, "catalog_entries", lambda: (entries, "snapshot"))
    return ctx.ingest.content


def upload(svc, data=None, name="custom.xml", actor=ACTOR):
    return up.import_content(svc, benchmark() if data is None else data, name, actor)


def test_raw_manual_indexes_delta_and_original_metadata_offline(svc):
    svc.ingest.set_link(actor=ACTOR, connected=False)
    result = upload(svc, actor="  IT2 Smith  ")
    record, delta = result["record"], result["delta"]
    assert record["source"] == "uploaded"
    assert record["kind"] == "manual_stig"
    assert record["product_key"] == "MS_Windows_11"
    assert record["version"] == [2, 11] and record["version_label"] == "V2R11"
    assert record["benchmark_id"] == "Microsoft_Windows_11_STIG"
    assert record["benchmark_release"] == "Release: 11 Benchmark Date: 01 Jan 2025"
    assert record["title"] == "Local Security Technical Implementation Guide"
    assert record["upload_date"] is None and record["fetched_at"] is None and record["fetched_by"] is None
    assert record["url"] == "" and record["etag"] is None
    provenance = record["ingest"]["upload"]
    assert provenance["imported_by"] == ACTOR and provenance["imported_at"]
    assert provenance["authenticity_verified"] is False
    assert provenance["benchmarks"][0]["status"] == [{"value": "accepted", "date": "2025-01-01"}]
    assert provenance["benchmarks"][0]["version_time"] == "2025-01-01"
    assert provenance["benchmarks"][0]["references"][0]["href"] == "https://example.invalid/publisher"
    assert delta["counts"]["added"] == 1 and delta["full_import"]
    assert svc.ingest.get_delta(delta["id"])["benchmark_id"] == record["benchmark_id"]
    assert (svc.store.files_dir / record["disk_name"]).read_bytes() == benchmark()
    assert svc.store.get(record["filename"]) == record
    assert not list((svc.store.root / "incoming").iterdir())
    assert svc.audit.verify().ok


@pytest.mark.parametrize("srg", [False, True])
def test_manual_and_srg_zip_acceptance(svc, srg):
    data = archive(("folder/guide-xccdf.xml", benchmark(bid="Local_SRG" if srg else "Custom_STIG", srg=srg)),
                   ("folder/readme.txt", b"reference material"), ("folder/style.xsl", b"<stylesheet/>"))
    result = upload(svc, data, "unfamiliar.zip")
    assert result["record"]["kind"] == ("srg" if srg else "manual_stig")
    assert result["delta"]["counts"]["total"] == 1
    assert result["record"]["sha256"] == hashlib.sha256(data).hexdigest()
    assert result["record"]["ingest"]["upload"]["member"] == "folder/guide-xccdf.xml"


@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("zipped", [False, True])
def test_scap_xml_and_zip(svc, wrapped, zipped):
    xml = datastream() if wrapped else benchmark(automatic=True)
    data = archive(("benchmark.xml", xml), ("oval.xml", b"<oval_definitions/>")) if zipped else xml
    result = upload(svc, data, "local.zip" if zipped else "local.xml")
    assert result["record"]["kind"] == "scap_benchmark"
    assert result["delta"] is None
    assert Path(result["record"]["ingest"]["datastream_path"]).read_bytes() == xml


def test_raw_srg_has_delta(svc):
    result = upload(svc, benchmark(bid="Custom_SRG", srg=True))
    assert result["record"]["kind"] == "srg"
    assert result["delta"]["benchmark_id"] == "Custom_SRG"


@pytest.mark.parametrize("zipped", [False, True])
def test_real_w11_manual_references_produce_manual_delta(svc, zipped):
    xml = W11_XCCDF.read_bytes()
    assert b"check-content-ref" in xml
    data = archive(("guide-xccdf.xml", xml)) if zipped else xml
    result = upload(svc, data, "local.zip" if zipped else "local.xml")
    assert result["record"]["kind"] == "manual_stig"
    assert result["record"]["version"] == [2, 11]
    assert result["delta"]["benchmark_id"] == "Microsoft_Windows_11_STIG"
    assert result["delta"]["counts"]["added"] == 19
    assert result["record"]["ingest"]["catalog_path"]
    assert "datastream_path" not in result["record"]["ingest"]


@pytest.mark.parametrize("system", ["C-56717r1259976_chk", "urn:custom:manual-check", "http://scap.nist.gov/schema/ocil/2"])
def test_manual_check_reference_is_not_automated(svc, system):
    xml = benchmark(automatic=True).replace(b"http://oval.mitre.org/XMLSchema/oval-definitions-5", system.encode())
    result = upload(svc, xml)
    assert result["record"]["kind"] == "manual_stig"
    assert result["delta"]["counts"]["added"] == 1


def test_inline_automated_check_is_stored_without_execution(svc):
    xml = benchmark().replace(b"C-100001r1_chk", b"http://open-scap.org/page/SCE")
    result = upload(svc, xml)
    assert result["record"]["kind"] == "scap_benchmark"
    assert result["delta"] is None
    assert Path(result["record"]["ingest"]["datastream_path"]).read_bytes() == xml


def test_xml_version_wins_over_official_filename(svc):
    result = upload(svc, archive(("guide-xccdf.xml", benchmark(version="1", release="3"))), OFFICIAL)
    rec = result["record"]
    assert rec["version"] == [1, 3]
    assert rec["filename"] != OFFICIAL
    selection = select(svc.catalog_entries()[0], [], {}, svc.store.records(), extra_products=["MS_Windows_11"])
    assert [r["filename"] for r in selection.updates] == [OFFICIAL]
    assert not selection.current


@pytest.mark.parametrize("kwargs", [{"version": None, "release": None}, {"version": "0.1.76", "release": None},
                                   {"bid": "custom", "version": None, "release": None}])
def test_unknown_metadata_does_not_satisfy_official_version(svc, kwargs):
    rec = upload(svc, archive(("guide-xccdf.xml", benchmark(**kwargs))), OFFICIAL)["record"]
    assert rec["version"] is None and rec["version_label"] is None
    if kwargs.get("bid") == "custom":
        assert rec["product_key"] is None
    selection = select(svc.catalog_entries()[0], [], {}, svc.store.records(), extra_products=["MS_Windows_11"])
    assert len(selection.updates) == 1 and not selection.current


def test_other_xml_identity_cannot_borrow_filename_product(svc):
    rec = upload(svc, archive(("guide-xccdf.xml", benchmark(bid="Some_Other_STIG", version="999"))), OFFICIAL)["record"]
    assert rec["product_key"] is None
    assert not select(svc.catalog_entries()[0], [], {}, svc.store.records(), extra_products=["MS_Windows_11"]).current


@pytest.mark.parametrize("version", ["2", "999"])
def test_unverified_claimed_release_cannot_suppress_official_update(svc, version):
    upload(svc, benchmark(version=version))
    selection = select(svc.catalog_entries()[0], [], {}, svc.store.records(), extra_products=["MS_Windows_11"])
    assert not selection.current
    assert [r["filename"] for r in selection.updates] == [OFFICIAL]


def test_identical_bytes_reuse_record_even_when_renamed(svc, monkeypatch):
    first = upload(svc)
    sync_before = ContentLibrary(svc).sync_status(svc.store.records())
    def unexpected(*args, **kwargs):
        pytest.fail("duplicate upload must not ingest again")
    monkeypatch.setattr(svc, "_accept", unexpected)
    second = upload(svc, name="renamed.xml", actor="IT1 Jones")
    assert second == {"record": first["record"], "delta": None}
    assert len(svc.store.records()) == 1
    assert ContentLibrary(svc).sync_status(svc.store.records()) == sync_before
    assert list(svc.audit.records())[-1]["details"]["identical"]


def test_changed_content_produces_delta_and_retains_previous_file(svc):
    old = upload(svc)["record"]
    changed = benchmark(release="12").replace(b"Check the setting", b"Check the revised setting")
    result = upload(svc, changed)
    assert result["delta"]["counts"]["changed"] == 1
    assert result["delta"]["old_release"] == old["benchmark_release"]
    assert len(svc.store.records()) == 2
    assert (svc.store.files_dir / old["disk_name"]).read_bytes() == benchmark()


def test_import_preserves_live_sync_history(svc):
    library = ContentLibrary(svc)
    live = "2025-10-01T10:20:30+00:00"
    library.record_transfer("pulled", live)
    before = library.sync_status([])
    upload(svc)
    after = library.sync_status(svc.store.records())
    assert after["last_download_at"] == live
    assert after["last_successful_check_at"] == before["last_successful_check_at"]
    assert after["last_attempt_at"] == before["last_attempt_at"]
    assert after["last_import_at"]


@pytest.mark.parametrize("actor", ["", "  ", "agent", "system:import", "llm-1", "policy:IT1", "operator", "OPERATOR",
                                  "name\nforged", "a" * 129])
def test_named_human_required_before_staging(svc, actor):
    with pytest.raises(PermissionError):
        upload(svc, actor=actor)
    assert not (svc.store.root / "incoming").exists()
    assert not svc.store.records()
    assert list(svc.audit.records())[-1]["outcome"] == "blocked"


def test_kill_switch_blocks_before_staging(svc):
    svc.ctx.killswitch.engage(ACTOR)
    with pytest.raises(KillSwitchEngaged):
        upload(svc)
    assert not (svc.store.root / "incoming").exists()
    assert not svc.store.records()


def test_kill_switch_rechecked_after_validation(svc, monkeypatch):
    validate = up._validate
    def stop(*args):
        result = validate(*args)
        svc.ctx.killswitch.engage(ACTOR)
        return result
    monkeypatch.setattr(up, "_validate", stop)
    with pytest.raises(KillSwitchEngaged):
        upload(svc)
    assert not svc.store.records()
    assert not list((svc.store.root / "incoming").iterdir())


def test_running_pull_blocks_acceptance(svc):
    svc._running = "pull-running"
    with pytest.raises(up.ContentUploadError, match="pull is running"):
        upload(svc)
    assert not svc.store.records()
    assert not list((svc.store.root / "incoming").iterdir())


@pytest.mark.parametrize("name", ["../../CON.xml", r"C:\temp\NUL.XML", "COM1.xml", "LPT¹.xml", "a<b>c.xml",
                                 "CONIN$.xml", "abc" * 200 + ".xml"])
def test_filename_sanitization(svc, name):
    record = upload(svc, name=name)["record"]
    assert (svc.store.files_dir / record["disk_name"]).is_file()
    assert len(record["disk_name"]) <= 200
    assert record["disk_name"] == fx.disk_name(record["disk_name"])
    assert record["ingest"]["upload"]["filename"].split(".")[0].casefold() not in up._DEVICES


@pytest.mark.parametrize("bid", ["CON", "nul", "LPT1", "a/b", "a:b", "a" * 181])
def test_unsafe_catalog_identity_is_refused_before_acceptance(svc, bid):
    with pytest.raises(up.ContentUploadError, match="stored safely"):
        upload(svc, benchmark(bid=bid))
    assert not svc.store.records()
    assert not svc.store.files_dir.exists()


@pytest.mark.parametrize("data,name", [(b"", "empty.xml"), ("xml", "bad.xml"), (benchmark(), "script.ps1"),
                                      (benchmark(), ""), (benchmark(), "wrong.zip"), (b"PKbroken", "wrong.xml")])
def test_unsupported_input(svc, data, name):
    with pytest.raises(up.ContentUploadError):
        upload(svc, data, name)
    assert not svc.store.records()


def test_32_mib_limit_before_staging(svc):
    assert up.MAX_UPLOAD_BYTES == 32 * 1024 * 1024
    with pytest.raises(up.ContentUploadError, match="32 MiB"):
        upload(svc, b" " * (up.MAX_UPLOAD_BYTES + 1))
    assert not (svc.store.root / "incoming").exists()


def test_exact_limit_is_allowed(svc, monkeypatch):
    data = benchmark()
    monkeypatch.setattr(up, "MAX_UPLOAD_BYTES", len(data))
    assert upload(svc, data)["record"]["bytes"] == len(data)


@pytest.mark.parametrize("xml", [b"<anything/>", b"<TestResult/>", b"<Benchmark id='x'/>",
                                b"<Benchmark><Rule id='x'/></Benchmark>",
                                b"<Benchmark id='x'><Rule/></Benchmark>",
                                b"<Benchmark id='x'><Rule id='x'/><Rule id='x'/></Benchmark>",
                                b"<data-stream-collection/>", b"<Benchmark id='x'>",
                                b"<Benchmark xmlns='urn:not-xccdf' id='x'><Rule id='x'/></Benchmark>"])
def test_nonbenchmark_and_malformed_xml_are_quarantined(svc, xml):
    with pytest.raises(up.ContentUploadError):
        upload(svc, xml)
    assert not svc.store.records()
    notes = list(svc.store.quarantine_dir.glob("*.why.json"))
    assert len(notes) == 1
    assert json.loads(notes[0].read_text())["bytes"] == len(xml)
    assert "content.quarantine" in [r["action"] for r in svc.audit.records()]
    assert not list((svc.store.root / "incoming").iterdir())


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-be"])
@pytest.mark.parametrize("declaration", ['<!DOCTYPE Benchmark SYSTEM "https://example.invalid/external.dtd">',
                                        '<!DOCTYPE Benchmark [<!ENTITY unsafe "expanded">]>'])
def test_dtd_entities_rejected_in_xml_and_zip(svc, encoding, declaration):
    text = f'<?xml version="1.0" encoding="{encoding}"?>' + declaration + benchmark().decode()
    for data, name in [(text.encode(encoding), "test.xml"),
                       (archive(("guide-xccdf.xml", text.encode(encoding))), "test.zip")]:
        with pytest.raises(up.ContentUploadError):
            upload(svc, data, name)
    assert not svc.store.records()


def test_dtd_in_ancillary_xml_is_rejected(svc):
    data = archive(("guide-xccdf.xml", benchmark()), ("extras.xml", b'<!DOCTYPE x [<!ENTITY x "y">]><x/>'))
    with pytest.raises(up.ContentUploadError, match="DTD"):
        upload(svc, data, "test.zip")


@pytest.mark.parametrize("member", ["../bad", "/absolute", r"C:\file.xml", r"a\..\bad", "safe/CON.xml",
                                   "a:stream", "a//b", "folder./bad", "LPT¹.xml", "a\x00b"])
def test_zip_unsafe_paths(svc, member):
    if "\x00" in member:
        # zipfile's writer strips NULs; patch equal-sized names in both ZIP headers.
        data = archive(("guide-xccdf.xml", benchmark()), ("a_b", b"data")).replace(b"a_b", b"a\x00b")
    else:
        data = archive(("guide-xccdf.xml", benchmark()), (member, b"data"))
    with pytest.raises(up.ContentUploadError, match="unsafe path"):
        upload(svc, data, "test.zip")


def test_zip_symlink_rejected(svc):
    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(up.ContentUploadError, match="links"):
        upload(svc, archive(("guide-xccdf.xml", benchmark()), (info, b"outside")), "test.zip")


def test_zip_duplicate_and_ambiguous_members(svc):
    for members in [(('guide-xccdf.xml', benchmark()), ('GUIDE-XCCDF.XML', benchmark())),
                    (('a-xccdf.xml', benchmark()), ('b-xccdf.xml', benchmark(bid="Other")))]:
        with pytest.raises(up.ContentUploadError):
            upload(svc, archive(*members), "test.zip")


def test_zip_selected_member_must_be_the_validated_benchmark(svc):
    data = archive(("guide-xccdf.xml", datastream()), ("wrong-benchmark.xml", b"<not-a-benchmark/>"))
    with pytest.raises(up.ContentUploadError, match="ambiguous"):
        upload(svc, data, "test.zip")


@pytest.mark.parametrize("limit", ["MAX_MEMBERS", "MAX_UPLOAD_BYTES", "MAX_EXPANDED_BYTES"])
def test_archive_limits(svc, monkeypatch, limit):
    data = archive(("guide-xccdf.xml", benchmark()), ("padding.txt", b"0" * 10000))
    monkeypatch.setattr(up, limit, 1 if limit == "MAX_MEMBERS" else 2000)
    with pytest.raises(up.ContentUploadError, match="limit"):
        upload(svc, data, "test.zip")


def test_crc_failure_in_non_xml_member(svc):
    data = archive(("guide-xccdf.xml", benchmark()), ("notes.txt", b"uniquepayload"), compression=zipfile.ZIP_STORED)
    data = data.replace(b"uniquepayload", b"uniquecorrupt")
    with pytest.raises(up.ContentUploadError, match="corrupt"):
        upload(svc, data, "test.zip")


def test_corrupt_zip_member_offsets(svc):
    data = archive(("guide-xccdf.xml", benchmark()), ("notes.txt", b"uniquepayload"), compression=zipfile.ZIP_STORED)
    data = data.replace(b"uniquepayload", b"short")
    with pytest.raises(up.ContentUploadError):
        upload(svc, data, "test.zip")


def test_encrypted_member_rejected(svc):
    data = bytearray(archive(("guide-xccdf.xml", benchmark())))
    offset = data.index(b"PK\x01\x02")
    flags = struct.unpack_from("<H", data, offset + 8)[0]
    struct.pack_into("<H", data, offset + 8, flags | 1)
    with pytest.raises(up.ContentUploadError, match="encrypted"):
        upload(svc, bytes(data), "test.zip")


@pytest.mark.parametrize("limit", ["MAX_ELEMENTS", "MAX_DEPTH"])
def test_xml_structure_limits(svc, monkeypatch, limit):
    monkeypatch.setattr(up, limit, 2)
    with pytest.raises(up.ContentUploadError, match="structure"):
        upload(svc)


def test_validation_failure_preserves_good_content_and_catalog(svc):
    record = upload(svc)["record"]
    catalog = Path(record["ingest"]["catalog_path"])
    before = catalog.read_bytes()
    with pytest.raises(up.ContentUploadError):
        upload(svc, b"<not-a-benchmark/>")
    assert svc.store.records() == [record]
    assert catalog.read_bytes() == before
    assert (svc.store.files_dir / record["disk_name"]).read_bytes() == benchmark()


def test_accept_storage_error_is_audited_and_staging_is_cleaned(svc, monkeypatch):
    before = upload(svc)["record"]
    def fail(*args, **kwargs):
        raise OSError("storage unavailable")
    monkeypatch.setattr(svc, "_accept", fail)
    with pytest.raises(OSError):
        upload(svc, benchmark(release="12"))
    assert svc.store.records() == [before]
    assert not list((svc.store.root / "incoming").iterdir())
    assert list(svc.audit.records())[-1]["action"] == "content.import_failed"


@pytest.mark.parametrize("kind", ["manual_stig", "srg", "scap_benchmark", "other"])
def test_fetch_check_file_accepts_raw_xml(tmp_path, kind):
    path = tmp_path / "content.xml"
    path.write_bytes(benchmark())
    assert "xccdf" in fx.check_file(path, kind)["checked"]
    path.write_bytes(b"<not-a-benchmark/>")
    with pytest.raises(ValueError):
        fx.check_file(path, kind)


def test_fetch_rejects_dtd_before_entity_expansion(tmp_path):
    path = tmp_path / "content.xml"
    path.write_bytes(('<!DOCTYPE Benchmark [<!ENTITY x "unsafe">]>' + benchmark().decode()).encode("utf-16"))
    with pytest.raises(ValueError, match="DTD"):
        fx.check_file(path, "manual_stig")
