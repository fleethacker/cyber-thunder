"""Verified HTTPS transport receipts do not confer offline signing authority."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import ssl
import threading
from types import SimpleNamespace
import urllib.request

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cyberthunder.control.principal import principal_scope
from cyberthunder.ingest.content import fetch as fx, signatures as sig
from cyberthunder.ingest.content.http import ContentClient, ContentNetworkError
from tests.ingest.content_helpers import scap_zip
from tests.ingest.test_content_signatures import STIG, SCAP, row, signing, key_directory, verified, stig_zip


@pytest.fixture
def https_source(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Loopback content fixture")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "tls.pem", tmp_path / "tls-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    state = SimpleNamespace(files={}, redirects={}, requests=[])

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self):
            state.requests.append((self.command, self.path, dict(self.headers)))
            if self.path in state.redirects:
                self.send_response(302)
                self.send_header("Location", state.redirects[self.path])
                data = b""
            elif self.path in state.files:
                self.send_response(200)
                data = state.files[self.path]
            else:
                self.send_response(404)
                data = b""
            self.send_header("Content-Length", str(len(data)))
            self.send_header("ETag", '"fixture-etag"')
            self.end_headers()
            if self.command == "GET":
                self.wfile.write(data)

        do_HEAD = do_GET = reply

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert_path, key_path)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state.url = f"https://127.0.0.1:{server.server_port}"
    # Production has no configurable host expansion. Only this fixture substitutes
    # its exact loopback host; ContentClient still performs real TLS and redirect checks.
    monkeypatch.setattr(fx, "_LIVE_HOSTS", frozenset({"127.0.0.1"}))
    monkeypatch.setenv("SSL_CERT_FILE", str(cert_path))
    state.client = ContentClient(allowed_hosts={"127.0.0.1"}, proxies={})
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)


def prepare(ctx, source, tmp_path, monkeypatch, kind="manual_stig"):
    name = STIG if kind == "manual_stig" else SCAP
    path = (stig_zip if kind == "manual_stig" else scap_zip)(tmp_path / name)
    source.files["/" + name] = path.read_bytes()
    item = row(path, kind)
    item["url"] = source.url + "/" + name
    ctx.ingest.content.client = source.client
    monkeypatch.setattr(ctx.ingest.content, "_resolve", lambda *a: [item])
    return item


@pytest.mark.parametrize("kind", ["manual_stig", "scap_benchmark"])
def test_verified_live_pull_records_transport_without_signature(verified, https_source, tmp_path, monkeypatch, kind):
    ctx, human = verified
    item = prepare(ctx, https_source, tmp_path, monkeypatch, kind)
    # Preserve existing updater admin authorization; offline import is a separate action.
    human = replace(human, roles=("admin",))
    policy = json.loads(ctx.access.path.read_bytes())
    policy["entries"][0]["node_actions"] = ["admin"]
    ctx.access.path.write_text(json.dumps(policy))
    with principal_scope(human):
        job = ctx.ingest.content.pull(human.actor, all_matching=True, background=False)
    assert job["state"] == "done", job
    evidence = ctx.ingest.content.store.records()[0]["authenticity"]
    assert evidence == {"status": "trusted_https_source", "operator_attested": False, "disa_signature": False,
                        "final_url": item["url"], "sha256": item["sha256"], "bytes": item["bytes"]}
    assert job["files"][0]["authenticity"] == evidence
    assert any(r["details"].get("status") == "trusted_https_source" for r in ctx.audit.records())


def test_approved_final_url_and_stale_partial_bytes(https_source, tmp_path):
    data = stig_zip(tmp_path / STIG).read_bytes()
    https_source.files["/approved.zip"] = data
    https_source.redirects["/entry.zip"] = "/approved.zip"
    url = https_source.url + "/entry.zip"
    dest = tmp_path / "incoming"
    dest.mkdir()
    part = dest / (STIG + ".part")
    part.write_bytes(b"caller-supplied-prefix")
    part.with_name(part.name + ".json").write_text(json.dumps({"url": url, "etag": '"fixture-etag"'}))
    result = fx.download(https_source.client, {"filename": STIG, "url": url}, dest, trusted_source=True)
    assert Path(result.path).read_bytes() == data and not result.resumed
    assert not any("Range" in h for _, _, h in https_source.requests)
    assert fx.live_evidence(result, https_source.client)["final_url"] == https_source.url + "/approved.zip"
    assert "_source_proof" not in result.to_dict()
    forged = fx.FetchResult(**result.to_dict())
    forged.authenticity = {"status": "trusted_https_source"}
    with pytest.raises(fx.ContentError):
        fx.live_evidence(forged, https_source.client)
    with pytest.raises(fx.ContentError):
        fx.live_evidence(result, ContentClient(allowed_hosts={"127.0.0.1"}, proxies={}))


def test_unapproved_redirect_never_contacts_destination(https_source, tmp_path):
    https_source.redirects["/entry.zip"] = https_source.url.replace("127.0.0.1", "localhost") + "/forbidden.zip"
    with pytest.raises(ContentNetworkError):
        fx.download(https_source.client, {"filename": STIG, "url": https_source.url + "/entry.zip"},
                    tmp_path / "dest", trusted_source=True)
    assert all(path != "/forbidden.zip" for _, path, _ in https_source.requests)


@pytest.mark.parametrize("fault", ["http", "insecure_tls", "custom_opener", "extra_host", "untrusted_certificate"])
def test_transport_proof_requires_real_narrow_tls_client(https_source, tmp_path, fault):
    client = https_source.client
    if fault == "http":
        client.allow_http = True
    elif fault == "insecure_tls":
        tls = next(h._context for h in client.opener.handlers if type(h) is urllib.request.HTTPSHandler)
        tls.check_hostname = False
        tls.verify_mode = ssl.CERT_NONE
    elif fault == "custom_opener":
        client.opener = SimpleNamespace(open=lambda *a, **kw: pytest.fail("must refuse before I/O"))
    elif fault == "extra_host":
        client.allowed_hosts |= {"unapproved.example"}
    else:
        # Verification flags alone are not the certificate test: a clean trust store
        # must actually reject the fixture's otherwise valid self-signed certificate.
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        next(h for h in client.opener.handlers if type(h) is urllib.request.HTTPSHandler)._context = tls
    with pytest.raises((fx.ContentError, ContentNetworkError)):
        fx.download(client, {"filename": STIG, "url": https_source.url + "/entry.zip"},
                    tmp_path / "dest", trusted_source=True, retries=0)
    assert not https_source.requests


def test_mutation_before_parser_cannot_inherit_source(https_source, tmp_path, monkeypatch):
    data = stig_zip(tmp_path / STIG).read_bytes()
    https_source.files["/entry.zip"] = data
    dest = tmp_path / "dest"
    def progress(event):
        if event["state"] == "verifying":
            (dest / (STIG + ".part")).write_bytes(data + b"tampering")
    monkeypatch.setattr(fx, "check_file", lambda *a, **kw: pytest.fail("unproven bytes must not reach parser"))
    with pytest.raises(fx.Quarantined):
        fx.download(https_source.client, {"filename": STIG, "url": https_source.url + "/entry.zip"},
                    dest, trusted_source=True, progress=progress)


@pytest.mark.parametrize("fault", ["bytes", "logout", "kill", "link", "policy"])
def test_live_publication_rechecks_bytes_and_runtime_guards(verified, https_source, tmp_path, monkeypatch, fault):
    ctx, human = verified
    prepare(ctx, https_source, tmp_path, monkeypatch)
    active = [True]
    def guard():
        if not active[0]:
            raise PermissionError("session revoked")
    download = fx.download
    def changed(*args, **kwargs):
        result = download(*args, **kwargs)
        if fault == "bytes":
            Path(result.path).write_bytes(b"tampered after download")
        elif fault == "logout":
            active[0] = False
        elif fault == "kill":
            ctx.killswitch.engage(human.actor, "fixture stop before publication")
        elif fault == "link":
            monkeypatch.setattr(ctx.ingest.content, "_link", lambda: SimpleNamespace(connected=False))
        else:
            ctx.access.path.write_text('{"version":1,"entries":[]}')
        return result
    monkeypatch.setattr(fx, "download", changed)
    monkeypatch.setattr(ctx.ingest, "ingest_stig", lambda *a, **kw: pytest.fail("must refuse before publication"))
    with principal_scope(human, validity=guard):
        job = ctx.ingest.content.pull(human.actor, all_matching=True, background=False)
    assert job["state"] == "failed", job
    assert not ctx.ingest.content.store.records()


def test_live_provenance_is_not_a_folder_or_caller_exception(verified, https_source, tmp_path, monkeypatch):
    ctx, human = verified
    item = prepare(ctx, https_source, tmp_path, monkeypatch)
    source = tmp_path / STIG
    entry = fx.entry_from_item(item)
    with principal_scope(human), pytest.raises(sig.AuthenticityError):
        ctx.ingest.content._accept(source, entry, source="trusted_https_source", actor=human.actor,
                                  sha256=item["sha256"], size=item["bytes"], etag=None)
    with principal_scope(human):
        assert ctx.ingest.content.pull(human.actor, all_matching=True, background=False)["state"] == "done"
    # Even exact bytes previously downloaded through HTTPS need offline attestation.
    media = tmp_path / "offline"
    media.mkdir()
    (media / STIG).write_bytes(https_source.files["/" + STIG])
    sig.atomic_document(media / "manifest.lock.json", {"files": [item], "failed": [], "manifest": None})
    with principal_scope(human), pytest.raises(sig.AuthenticityError):
        ctx.ingest.content.import_dir(media, human.actor)
