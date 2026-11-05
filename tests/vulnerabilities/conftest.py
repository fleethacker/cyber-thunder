from __future__ import annotations

import hashlib
import json
import sqlite3
import socket
import struct
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from cyberthunder.audit.chain import AuditLog
from cyberthunder.control.killswitch import KillSwitch
from cyberthunder.store import StateStore
from cyberthunder.vulnerabilities import engine
from cyberthunder.vulnerabilities.service import VulnerabilityService
from cyberthunder.vulnerabilities.storage import FORMAT


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        pytest.fail("Database tests must not contact a network")
    monkeypatch.setattr(socket.socket, "connect", refuse)


def payloads(*, java=True, age=0, next_hours=12, marker=1) -> dict[str, bytes]:
    """Synthetic file-format fixtures; never used for matching or a real scan."""
    current = datetime.now(timezone.utc)
    updated = current - timedelta(hours=age)
    meta = {"Version": 2, "UpdatedAt": updated.isoformat(),
            "NextUpdate": (updated + timedelta(hours=next_hours)).isoformat(),
            "DownloadedAt": current.isoformat()}
    bolt = bytearray(16384)
    for page in (0, 1):
        offset = page * 4096
        struct.pack_into("<QHHI", bolt, offset, page, 4, 0, 0)
        struct.pack_into("<4I5Q", bolt, offset + 16, 0xED0CDAED, 2, 4096, 0, 3, 0, 2, 4, page)
        checksum = 0xcbf29ce484222325
        for byte in bolt[offset + 16:offset + 72]:
            checksum = ((checksum ^ byte) * 0x100000001b3) & 0xffffffffffffffff
        struct.pack_into("<Q", bolt, offset + 72, checksum)
    struct.pack_into("<QHHI", bolt, 8192, 2, 0x10, 0, 0)
    struct.pack_into("<QHHI", bolt, 12288, 3, 2, 0, 0)
    bolt[-1] = marker
    files = {"db/metadata.json": json.dumps(meta).encode(), "db/trivy.db": bytes(bolt)}
    if java:
        meta["Version"] = 1
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE artifacts(id INTEGER PRIMARY KEY, group_id TEXT, artifact_id TEXT)")
        conn.execute("CREATE TABLE indices(artifact_id INTEGER, version TEXT, sha1 BLOB, archive_type TEXT)")
        files["java-db/trivy-java.db"] = conn.serialize()
        conn.close()
        files["java-db/metadata.json"] = json.dumps(meta).encode()
    return files


def bundle(path: Path, files: dict | None = None, *, mutate=None, provenance="official_download") -> Path:
    files = payloads() if files is None else files
    manifest = {"format": FORMAT, "version": 1, "created_at": datetime.now(timezone.utc).isoformat(),
                "source": "official_trivy", "provenance": provenance,
                "files": {name: {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
                          for name, raw in files.items()}}
    if mutate:
        mutate(manifest)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        for name, raw in files.items():
            archive.writestr(name, raw)
    return path


@pytest.fixture
def svc(state_dir, monkeypatch):
    settings = SimpleNamespace(trivy_binary="trivy", scheduler_actor="scheduler", link_connected=True,
                               link_kbps=56, link_latency_ms=500, vulnerability_max_bundle_bytes=1024 * 1024,
                               vulnerability_max_unpacked_bytes=1024 * 1024,
                               vulnerability_max_staging_bytes=1024 * 1024,
                               vulnerability_update_timeout_s=10, vulnerability_db_max_age_hours=72)
    store = StateStore(state_dir)
    audit = AuditLog(store.audit_log, node="fixture")
    ctx = SimpleNamespace(store=store, settings=settings, audit=audit, killswitch=KillSwitch(state_dir, audit))
    monkeypatch.setattr(VulnerabilityService, "_engine", lambda *a, **k: {
        "available": True, "version": "0.71.1", "supported": True, "error": None})
    service = VulnerabilityService(ctx)
    yield service
    service.wait(5)
    store.close()


@pytest.fixture
def offline_bundle(tmp_path):
    return bundle(tmp_path / "input.zip")


@pytest.fixture
def fake_download(monkeypatch):
    calls = []
    monkeypatch.setattr(engine, "executable", lambda _: sys.executable)

    def run(argv, *, home, timeout, guard, capture=False):
        calls.append(argv)
        guard()
        assert (home / "trivy.yaml").read_text() == "{}\n"
        assert argv[argv.index("--config") + 1] == str(home / "trivy.yaml")
        cache = Path(argv[argv.index("--cache-dir") + 1])
        java = "--download-java-db-only" in argv
        for name, raw in payloads().items():
            if name.startswith("java-db/") == java:
                dest = cache / name
                dest.parent.mkdir(exist_ok=True)
                dest.write_bytes(raw)
        guard()
        return b""

    monkeypatch.setattr(engine, "run", run)
    return calls
