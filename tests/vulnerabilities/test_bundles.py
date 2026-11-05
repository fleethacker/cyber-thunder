from __future__ import annotations

import json
import stat
import struct
import warnings
import zipfile

import pytest

from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.vulnerabilities.errors import VulnerabilityError
from .conftest import bundle, payloads


def rewrite(path, change):
    with zipfile.ZipFile(path) as archive:
        members = [(info, archive.read(info)) for info in archive.infolist()]
    members = change(members)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for info, raw in members:
                archive.writestr(info, raw)


@pytest.mark.parametrize("name", ["../outside", "/absolute", "C:/absolute", "db\\trivy.db",
                                  "db/../trivy.db", "DB/trivy.db", "db/trivy.db:stream", "db/trivy.db/child"])
def test_archive_member_allowlist_rejects_paths(svc, offline_bundle, name):
    if "\\" in name:
        # ZipInfo normalizes separators when constructing an archive on Windows;
        # patch the raw headers to model a foreign, actually malformed archive.
        offline_bundle.write_bytes(offline_bundle.read_bytes().replace(b"db/trivy.db", name.encode()))
    else:
        rewrite(offline_bundle, lambda members: [(name if info.filename == "db/trivy.db" else info, raw)
                                                 for info, raw in members])
    with pytest.raises(VulnerabilityError):
        svc.import_bundle(offline_bundle, actor="joshua")
    assert svc.status()["state"] == "missing" and not list(svc.staging.iterdir())


@pytest.mark.parametrize("problem", ["duplicate", "extra", "missing-main", "half-java", "directory", "symlink", "fifo"])
def test_bad_zip_members_preserve_selected(svc, offline_bundle, problem):
    old = svc.import_bundle(offline_bundle, actor="joshua")["generation"]
    def change(members):
        if problem == "duplicate":
            return members + [members[0]]
        if problem == "extra":
            return members + [("extra.txt", b"x")]
        if problem == "missing-main":
            return [(i, r) for i, r in members if i.filename != "db/trivy.db"]
        if problem == "half-java":
            return [(i, r) for i, r in members if i.filename != "java-db/trivy-java.db"]
        kind = {"directory": stat.S_IFDIR, "symlink": stat.S_IFLNK, "fifo": stat.S_IFIFO}[problem]
        members[1][0].create_system = 3
        members[1][0].external_attr = (kind | 0o644) << 16
        return members
    rewrite(offline_bundle, change)
    with pytest.raises(VulnerabilityError):
        svc.import_bundle(offline_bundle, actor="joshua")
    assert svc.status()["generation"] == old


@pytest.mark.parametrize("change", [
    lambda m: m.update(version=2), lambda m: m.update(version=True), lambda m: m.update(format="other"),
    lambda m: m.update(source="https://untrusted.invalid/db"), lambda m: m.update(provenance="signed"),
    lambda m: m.update(unexpected="value"), lambda m: m.update(created_at="not-a-date"),
    lambda m: m["files"]["db/trivy.db"].update(sha256="0" * 64),
    lambda m: m["files"]["db/trivy.db"].update(sha256="X" * 64),
    lambda m: m["files"]["db/trivy.db"].update(bytes=True),
    lambda m: m["files"]["db/trivy.db"].update(bytes=42),
    lambda m: m["files"].pop("db/trivy.db"),
])
def test_manifest_validation(svc, tmp_path, change):
    path = bundle(tmp_path / "bad.zip", mutate=change)
    with pytest.raises(VulnerabilityError):
        svc.import_bundle(path, actor="joshua")
    assert svc.status()["state"] == "missing"


@pytest.mark.parametrize("change", [lambda m: m.update(Version=3), lambda m: m.update(Version=True),
    lambda m: m.update(UpdatedAt="2035-01-01T00:00:00Z"), lambda m: m.update(DownloadedAt="bad"),
    lambda m: m.update(NextUpdate=m["UpdatedAt"]), lambda m: m.pop("UpdatedAt"),
    lambda m: m.update(NextUpdate="2026-11-05T00:00:00"),
])
def test_database_schema_and_timestamp_validation(svc, tmp_path, change):
    files = payloads()
    metadata = json.loads(files["db/metadata.json"])
    change(metadata)
    files["db/metadata.json"] = json.dumps(metadata).encode()
    with pytest.raises(VulnerabilityError):
        svc.import_bundle(bundle(tmp_path / "schema.zip", files), actor="joshua")


@pytest.mark.parametrize("target", ["db/trivy.db", "java-db/trivy-java.db", "db/metadata.json"])
def test_empty_or_corrupt_database_files(svc, tmp_path, target):
    files = payloads()
    files[target] = b"invalid file format"
    with pytest.raises(VulnerabilityError):
        svc.import_bundle(bundle(tmp_path / "corrupt.zip", files), actor="joshua")


def test_duplicate_json_fields_rejected(svc, offline_bundle):
    def change(members):
        return [(i, b'{"version":1,' + raw[1:] if i.filename == "manifest.json" else raw) for i, raw in members]
    rewrite(offline_bundle, change)
    with pytest.raises(VulnerabilityError):
        svc.import_bundle(offline_bundle, actor="joshua")


def test_payload_hash_failure_preserves_generation(svc, offline_bundle):
    old = svc.import_bundle(offline_bundle, actor="joshua")["generation"]
    rewrite(offline_bundle, lambda members: [(i, raw[:-1] + b"x" if i.filename == "db/trivy.db" else raw)
                                             for i, raw in members])
    with pytest.raises(VulnerabilityError, match="integrity"):
        svc.import_bundle(offline_bundle, actor="joshua")
    assert svc.status()["generation"] == old


def test_separate_compressed_and_unpacked_limits(svc, offline_bundle):
    svc.ctx.settings.vulnerability_max_bundle_bytes = offline_bundle.stat().st_size - 1
    with pytest.raises(VulnerabilityError, match="Compressed"):
        svc.import_bundle(offline_bundle, actor="joshua")
    svc.ctx.settings.vulnerability_max_bundle_bytes = 1024 * 1024
    svc.ctx.settings.vulnerability_max_unpacked_bytes = 1000
    with pytest.raises(VulnerabilityError, match="size limit"):
        svc.import_bundle(offline_bundle, actor="joshua")
    assert not list(svc.staging.iterdir())


def test_export_cap_removes_partial(svc, offline_bundle):
    svc.import_bundle(offline_bundle, actor="joshua")
    svc.ctx.settings.vulnerability_max_bundle_bytes = 50
    with pytest.raises(VulnerabilityError):
        svc.export_bundle(actor="joshua")
    assert not list(svc.exports.iterdir())


def test_bad_crc_and_truncation(svc, offline_bundle):
    raw = bytearray(offline_bundle.read_bytes())
    offset = raw.find(b"PK\x01\x02")
    assert offset >= 0
    struct.pack_into("<I", raw, offset + 16, 0)
    offline_bundle.write_bytes(raw)
    with pytest.raises(VulnerabilityError):
        svc.import_bundle(offline_bundle, actor="joshua")
    offline_bundle.write_bytes(raw[:80])
    with pytest.raises(VulnerabilityError):
        svc.import_bundle(offline_bundle, actor="joshua")


def test_central_directory_size_and_entry_count_checked_before_zipfile(svc, offline_bundle, monkeypatch):
    raw = bytearray(offline_bundle.read_bytes())
    offset = raw.rfind(b"PK\x05\x06")
    struct.pack_into("<HH", raw, offset + 8, 65000, 65000)
    offline_bundle.write_bytes(raw)
    monkeypatch.setattr(zipfile, "ZipFile", lambda *a, **k: pytest.fail("Unbounded ZIP directory opened"))
    with pytest.raises(VulnerabilityError, match="ZIP directory"):
        svc.import_bundle(offline_bundle, actor="joshua")


def test_kill_during_import_does_not_become_generic_zip_error(svc, offline_bundle, monkeypatch):
    original = svc._guard
    count = 0
    def guard(*args, **kwargs):
        nonlocal count
        count += 1
        if count >= 3:
            raise KillSwitchEngaged("stopped")
        return original(*args, **kwargs)
    monkeypatch.setattr(svc, "_guard", guard)
    with pytest.raises(KillSwitchEngaged):
        svc.import_bundle(offline_bundle, actor="joshua")
    assert not list(svc.generations.iterdir()) and not list(svc.staging.iterdir())


def test_oversized_metadata_is_rejected_before_parsing(svc, tmp_path):
    files = payloads()
    files["db/metadata.json"] = b" " * 70000
    with pytest.raises(VulnerabilityError):
        svc.import_bundle(bundle(tmp_path / "large-meta.zip", files), actor="joshua")


def test_extra_generation_directory_invalidates_cache(svc, offline_bundle):
    status = svc.import_bundle(offline_bundle, actor="joshua")
    (svc.generations / status["generation"] / "db" / "unexpected").mkdir()
    assert svc.status()["state"] == "invalid"


@pytest.mark.parametrize("comment_size", [0, 65535])
def test_zip64_cannot_override_prechecked_directory(svc, offline_bundle, monkeypatch, comment_size):
    raw = offline_bundle.read_bytes()
    end = raw.rfind(b"PK\x05\x06")
    # The ordinary EOCD remains small, but ZipFile prefers this ZIP64 directory.
    extended = struct.pack("<4sQ2H2I4Q", b"PK\x06\x06", 44, 45, 45, 0, 0,
                           100000, 100000, 128 * 1024 * 1024, 0)
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, end, 1)
    ordinary = bytearray(raw[end:])
    location = struct.unpack_from("<I", ordinary, 16)[0]
    struct.pack_into("<I", ordinary, 16, location + len(extended) + len(locator))
    struct.pack_into("<H", ordinary, 20, comment_size)
    offline_bundle.write_bytes(raw[:end] + extended + locator + ordinary + b"x" * comment_size)
    monkeypatch.setattr(zipfile, "ZipFile", lambda *a, **k: pytest.fail("ZIP64 bypassed precheck"))
    with pytest.raises(VulnerabilityError, match="ZIP directory"):
        svc.import_bundle(offline_bundle, actor="joshua")


def test_invalid_utf8_zip_name_is_a_public_validation_error(svc, offline_bundle):
    raw = bytearray(offline_bundle.read_bytes())
    offset = raw.find(b"PK\x01\x02")
    struct.pack_into("<H", raw, offset + 8, 0x800)
    raw[offset + 46] = 0xff
    offline_bundle.write_bytes(raw)
    with pytest.raises(VulnerabilityError):
        svc.import_bundle(offline_bundle, actor="joshua")
    assert not list(svc.staging.iterdir())


@pytest.mark.parametrize("downloaded", [None, "0001-01-01T00:00:00Z"])
def test_original_artifact_without_download_timestamp_roundtrips(svc, tmp_path, downloaded):
    files = payloads()
    for name in ("db/metadata.json", "java-db/metadata.json"):
        metadata = json.loads(files[name])
        if downloaded is None:
            metadata.pop("DownloadedAt")
        else:
            metadata["DownloadedAt"] = downloaded
        files[name] = json.dumps(metadata).encode()
    result = svc.import_bundle(bundle(tmp_path / "artifact.zip", files), actor="joshua")
    assert result["state"] == "ready"
    assert all(d["downloaded_at"] is None for d in result["databases"])
    exported = svc.export_bundle(actor="joshua")
    with zipfile.ZipFile(exported) as archive:
        assert archive.read("db/metadata.json") == files["db/metadata.json"]
    assert svc.import_bundle(exported, actor="joshua")["state"] == "ready"


@pytest.mark.parametrize("kind", ["main", "java"])
def test_recognizable_magic_with_invalid_database_body_is_rejected(svc, tmp_path, kind):
    files = payloads()
    name = "db/trivy.db" if kind == "main" else "java-db/trivy-java.db"
    raw = bytearray(files[name])
    # Both previous validators accepted these unusable files as ready databases.
    if kind == "main":
        raw[32:] = b"\x00" * (len(raw) - 32)
    else:
        raw[100:] = b"\x00" * (len(raw) - 100)
    files[name] = bytes(raw)
    with pytest.raises(VulnerabilityError):
        svc.import_bundle(bundle(tmp_path / "invalid-body.zip", files), actor="joshua")


def test_sqlite_database_without_java_schema_is_rejected(svc, tmp_path):
    import sqlite3
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE unrelated(value TEXT)")
    files = payloads()
    files["java-db/trivy-java.db"] = conn.serialize()
    conn.close()
    with pytest.raises(VulnerabilityError):
        svc.import_bundle(bundle(tmp_path / "wrong-schema.zip", files), actor="joshua")


@pytest.mark.parametrize("damaged_page", [0, 1])
def test_bolt_accepts_one_recoverable_metadata_page(svc, tmp_path, damaged_page):
    files = payloads(java=False)
    raw = bytearray(files["db/trivy.db"])
    raw[damaged_page * 4096 + 72] ^= 1
    files["db/trivy.db"] = bytes(raw)
    assert svc.import_bundle(bundle(tmp_path / "recoverable.zip", files), actor="joshua")["state"] == "ready"


def test_newer_checksummed_bolt_meta_cannot_reference_missing_pages(svc, tmp_path):
    files = payloads(java=False)
    raw = bytearray(files["db/trivy.db"])
    struct.pack_into("<Q", raw, 4096 + 32, 99)
    checksum = 0xcbf29ce484222325
    for byte in raw[4096 + 16:4096 + 72]:
        checksum = ((checksum ^ byte) * 0x100000001b3) & 0xffffffffffffffff
    struct.pack_into("<Q", raw, 4096 + 72, checksum)
    files["db/trivy.db"] = bytes(raw)
    with pytest.raises(VulnerabilityError):
        svc.import_bundle(bundle(tmp_path / "bad-root.zip", files), actor="joshua")


@pytest.mark.parametrize("problem", ["timestamp-space", "timestamp-week", "case-alias"])
def test_metadata_matches_scanner_json_interpretation(svc, tmp_path, problem):
    files = payloads(java=False)
    metadata = json.loads(files["db/metadata.json"])
    if problem == "timestamp-space":
        metadata["UpdatedAt"] = metadata["UpdatedAt"].replace("T", " ")
    elif problem == "timestamp-week":
        from datetime import datetime
        date = datetime.fromisoformat(metadata["UpdatedAt"])
        metadata["UpdatedAt"] = date.strftime("%G-W%V-%uT%H:%M:%S+00:00")
    else:
        metadata["version"] = 3  # Go JSON accepts a case-insensitive field alias.
    files["db/metadata.json"] = json.dumps(metadata).encode()
    with pytest.raises(VulnerabilityError):
        svc.import_bundle(bundle(tmp_path / "different-interpretation.zip", files), actor="joshua")
