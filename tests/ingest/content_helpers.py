"""Test doubles for the content-update tests: a loopback file server with Range and ETag support, a fake
urllib opener for the index calls, and small DISA-like zips built from the shared fixtures."""
from __future__ import annotations

import io
import json
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
SNAPSHOT = FIXTURES / "ingest" / "cybermil_catalog_2026-11-04.json"
W11_XCCDF = FIXTURES / "windows" / "w11_subset-xccdf.xml"

DATASTREAM = b"""<?xml version="1.0" encoding="UTF-8"?>
<ds:data-stream-collection xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2" id="scap_mil.disa.stig_collection_test">
  <ds:component id="scap_mil.disa.stig_comp_test">
    <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_mil.disa.stig_benchmark_Test"/>
  </ds:component>
</ds:data-stream-collection>
"""


def stig_zip(path: Path, xccdf: Path = W11_XCCDF, member: str | None = None) -> Path:
    """A manual STIG zip laid out the way DISA ships one: a folder with the -xccdf.xml inside."""
    stem = path.name[:-len(".zip")]
    member = member or f"{stem.replace('_STIG', '_Manual_STIG')}/{stem.replace('U_', 'U_', 1)}_Manual-xccdf.xml"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(member, xccdf.read_bytes())
        zf.writestr(f"{stem}/STIG_unclass.xsl", "<xsl/>")
    return path


def scap_zip(path: Path, data: bytes = DATASTREAM) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(path.name.replace(".zip", ".xml"), data)
    return path


def zip_bytes(maker, name: str, tmp: Path, **kw) -> bytes:
    p = maker(tmp / name, **kw)
    return p.read_bytes()


class FileServer:
    """Loopback HTTP server for downloads. Each file: bytes, an ETag, and optional faults:
    cut_at (fraction of the body after which the first `cuts` GETs drop the connection)."""

    def __init__(self):
        self.files: dict[str, dict] = {}
        self.requests: list[dict] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):  # quiet
                pass

            def _file(self):
                name = self.path.split("?", 1)[0].rsplit("/", 1)[-1]
                return name, server.files.get(name)

            def do_HEAD(self):
                name, f = self._file()
                server.requests.append({"method": "HEAD", "path": self.path, "headers": dict(self.headers)})
                if f is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(f["data"])))
                self.send_header("ETag", f["etag"])
                self.send_header("Last-Modified", "Mon, 05 Oct 2026 12:00:00 GMT")
                self.send_header("Accept-Ranges", "bytes")
                self.end_headers()

            def do_GET(self):
                name, f = self._file()
                hdrs = dict(self.headers)
                server.requests.append({"method": "GET", "path": self.path, "headers": hdrs})
                if f is None:
                    body = b"not found"
                    self.send_response(404)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                data = f["data"]
                start = 0
                rng = self.headers.get("Range")
                if_range = self.headers.get("If-Range")
                partial = bool(rng) and (if_range is None or if_range == f["etag"]) and not f.get("ignore_range")
                if partial:
                    start = int(rng.split("=", 1)[1].split("-", 1)[0])
                    self.send_response(206)
                    self.send_header("Content-Range", f"bytes {start}-{len(data) - 1}/{len(data)}")
                else:
                    self.send_response(200)
                body = data[start:]
                self.send_header("Content-Length", str(len(body)))
                self.send_header("ETag", f["etag"])
                self.send_header("Accept-Ranges", "bytes")
                self.end_headers()
                if f.get("cuts", 0) > 0:
                    f["cuts"] -= 1
                    n = int(len(data) * f.get("cut_at", 0.4)) - start
                    self.wfile.write(body[:max(n, 0)])
                    self.wfile.flush()
                    self.close_connection = True
                    try:
                        self.connection.shutdown(2)
                    except OSError:
                        pass
                    return
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}/wp-content/uploads/stigs/zip"

    def url(self, name: str) -> str:
        return f"{self.base}/{name}"

    def add(self, name: str, data: bytes, etag: str = '"v1"', **faults) -> str:
        self.files[name] = dict(data=data, etag=etag, **faults)
        return self.url(name)

    def gets(self, name: str) -> list[dict]:
        return [r for r in self.requests if r["method"] == "GET" and r["path"].endswith("/" + name)]

    def start(self) -> "FileServer":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def guard_network(monkeypatch) -> None:
    """Refuse name resolution for anything but loopback, so no test can reach the Internet."""
    import socket
    real = socket.getaddrinfo

    def only_loopback(host, *a, **kw):
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise OSError(f"network access disabled in tests (tried {host})")
        return real(host, *a, **kw)

    monkeypatch.setattr(socket, "getaddrinfo", only_loopback)


def loopback_client(**kw):
    from cyberthunder.ingest.content.http import ContentClient
    return ContentClient(allowed_hosts={"127.0.0.1"}, allow_http=True, proxies={}, timeout=10, **kw)


# -- fake opener for the cyber.mil index ----------------------------------------------------------

class FakeResponse(io.BytesIO):
    def __init__(self, status: int, body: bytes, headers: dict | None = None, url: str = ""):
        super().__init__(body)
        self.status = status
        self.code = status
        self.url = url
        self.headers = _Headers(headers or {})

    def geturl(self):
        return self.url


class _Headers(dict):
    def items(self):
        return list(super().items())


class FakeOpener:
    """routes: {(method, url-prefix): callable(request) -> FakeResponse}. Records every request."""

    def __init__(self, routes: dict):
        self.routes = routes
        self.calls: list = []

    def open(self, req, timeout=None):
        self.calls.append(req)
        for (method, prefix), fn in self.routes.items():
            if req.get_method() == method and req.full_url.startswith(prefix):
                return fn(req)
        return FakeResponse(404, b"no route", {"Content-Type": "text/plain"}, req.full_url)


def apex_answer(records: list, *, gzip_it: bool = False) -> FakeResponse:
    import gzip
    body = json.dumps({"returnValue": records}).encode("utf-8")
    headers = {"Content-Type": "application/json;charset=UTF-8"}
    if gzip_it:
        body = gzip.compress(body)
        headers["Content-Encoding"] = "gzip"
    return FakeResponse(200, body, headers)


def snapshot_records() -> list:
    return json.loads(SNAPSHOT.read_text(encoding="utf-8"))["entries"]


def record(filename: str, url: str, *, title: str | None = None, types: str = "STIGs;Operating Systems;Windows",
           date: str = "2026-10-05") -> dict:
    return {"Classification": "Unclassified", "DocumentLibrary": "STIGs", "DownloadLink": url,
            "DownloadType": types.replace(";", ", "), "FileName": title or filename, "Name": "File-9999",
            "RawDocumentLibrary": "STIGs", "RawDownloadType": types, "Topic": "STIG", "UploadDate": date}


class HybridOpener(FakeOpener):
    """Fake routes for the index host; everything else goes to a real opener (the loopback file server)."""

    def __init__(self, routes: dict, real):
        super().__init__(routes)
        self.real = real

    def open(self, req, timeout=None):
        for (method, prefix), fn in self.routes.items():
            if req.get_method() == method and req.full_url.startswith(prefix):
                self.calls.append(req)
                return fn(req)
        return self.real.open(req, timeout=timeout)


def node_client(records_fn):
    """A client for a node under test: the index answers from records_fn(), files come from loopback."""
    from cyberthunder.ingest.content import index as ix
    from cyberthunder.ingest.content.http import ContentClient
    c = ContentClient(allowed_hosts={"www.cyber.mil", "dl.dod.cyber.mil", "127.0.0.1"}, allow_http=True, proxies={}, timeout=10)
    c.opener = HybridOpener({("POST", ix.APEX_URL): lambda r: apex_answer(records_fn())}, c.opener)
    return c


def make_ctx(state_dir):
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext
    state_dir.mkdir(parents=True, exist_ok=True)
    return AppContext(Settings.from_env(state_dir=str(state_dir)))
