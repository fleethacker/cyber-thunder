"""The public DISA STIG index on cyber.mil, and what each entry in it is.

The STIG document library page is a Salesforce site. Its catalog comes from one anonymous Apex call that
returns every document (about 420 entries, about 190 KB of JSON). The Apex class id in that call changes
when the site is redeployed, so a refusal or a non-JSON answer triggers rediscovery: the downloads page
names a view bundle, and the bundle names the class id next to the method we call.

File names follow DISA's conventions closely enough to classify every entry without opening it:

  U_<Product>_V<ver>R<rel>_STIG.zip                     manual STIG (XCCDF rule text, the citations)
  U_<Product>_V<ver>R<rel>_STIG_SCAP_1-3_Benchmark.zip  SCAP datastream a scanner executes
  U_<Product>_Y<yy>M<mm>_STIG.zip                       year-month release of a manual STIG
  U_<Product>_V<ver>R<rel>_SRG.zip                      Security Requirements Guide
  ..._STIG_Ansible.zip / _Chef.zip / _PowerShell_DSC    automation content
  U_SRG-STIG_Library_<Month>_<Year>.zip                 quarterly compilation of everything (large)
"""
from __future__ import annotations

import json
import re
import time
import urllib.parse
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

INDEX_HOST = "www.cyber.mil"
FILES_HOST = "dl.dod.cyber.mil"
ALLOWED_HOSTS = frozenset({INDEX_HOST, FILES_HOST})

KNOWN_CLASSNAME = "@udd/01pRw0000002mOj"
METHOD = "getCyberDocumentCatalogByDocumentLibrary"
LIBRARY = "STIGs"
APEX_URL = (f"https://{INDEX_HOST}/webruntime/api/apex/execute"
            "?language=en-US&asGuest=true&htmlEncode=false")
DOWNLOADS_PAGE = f"https://{INDEX_HOST}/stigs/downloads"
MAX_INDEX_BYTES = 4 * 1024 * 1024
MAX_PAGE_BYTES = 8 * 1024 * 1024

KINDS = ("manual_stig", "scap_benchmark", "srg", "automation", "compilation", "document", "tool", "other")

_STRIP = dict.fromkeys(map(ord, "​‌‍⁠﻿�"), None)
_VER = re.compile(r"_(?:V(\d+)R(\d+)|Y(\d{2})M(\d{2}))(?=[_.\- ]|$)")
_SCAP = re.compile(r"_SCAP_\d-\d_Benchmark$", re.I)
_AUTOMATION = re.compile(r"_(Ansible|Chef|PowerShell_DSC|DSC)$", re.I)
_COMPILATION = re.compile(r"^U_(SRG-STIG_Library_[A-Za-z]+_\d{4}|.*_Compilation)$", re.I)
_PACKAGE = re.compile(r"^U_(STIG_GPO|Intune_Policy)_Package_", re.I)
_DOC_EXT = {".pdf", ".txt", ".docx", ".doc", ".xlsx", ".xls", ".csv", ".html", ".htm", ".cfm"}
_VIEW = re.compile(r"""(?:https://www\.cyber\.mil)?/webruntime/view/[0-9a-f]+/prod/en-US/sTIGs_Document_Library_view[^"'\s<>)]*""")
_INVOKER = re.compile(r"""getApexInvoker\(\s*["'][^"']*["']\s*,\s*["'](@udd/[A-Za-z0-9]+)["']\s*,\s*["']"""
                      + METHOD + r"""["']""")


class IndexFetchError(RuntimeError):
    """The index could not be fetched or understood."""


@dataclass
class Entry:
    filename: str                       # basename of the download link, unquoted
    url: str
    host: str
    title: str
    kind: str
    product_key: str | None
    version: tuple[int, int] | None     # (ver, rel) or (yy, mm); comparable within a product
    version_label: str | None           # "V2R10" / "Y26M10"
    sunset: bool = False
    upload_date: str | None = None
    download_types: list[str] = field(default_factory=list)
    name: str | None = None             # DISA's own record name, e.g. File-0199

    def to_dict(self) -> dict:
        d = asdict(self)
        d["version"] = list(self.version) if self.version else None
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Entry":
        d = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        if d.get("version") is not None:
            d["version"] = tuple(int(x) for x in d["version"])
        return cls(**d)

    @property
    def allowed(self) -> bool:
        return self.allowed_by(ALLOWED_HOSTS)

    def allowed_by(self, hosts=ALLOWED_HOSTS, allow_http: bool = False) -> bool:
        scheme_ok = self.url.lower().startswith("https://") or (allow_http and self.url.lower().startswith("http://"))
        return scheme_ok and self.host in hosts


# -- names --------------------------------------------------------------------------------------

def clean_text(s: Any) -> str:
    return " ".join(str(s or "").translate(_STRIP).split())


def parse_filename(name: str) -> dict:
    """{kind, product_key, version, version_label} from a DISA file name. Never raises."""
    base = Path(str(name).replace("\\", "/")).name
    stem, ext = (base.rsplit(".", 1) + [""])[:2] if "." in base else (base, "")
    ext = f".{ext.lower()}" if ext else ""
    out: dict[str, Any] = {"kind": "other", "product_key": None, "version": None, "version_label": None}
    low = base.lower()
    m = _VER.search(stem)
    if m:
        if m.group(1) is not None:
            out["version"] = (int(m.group(1)), int(m.group(2)))
            out["version_label"] = f"V{int(m.group(1))}R{int(m.group(2))}"
        else:
            out["version"] = (int(m.group(3)), int(m.group(4)))
            out["version_label"] = f"Y{m.group(3)}M{m.group(4)}"
    if low.startswith("scc-") or low.startswith("u_stigviewer") or low.startswith("rpm-gpg-key") \
            or ext == ".scc" or "stig_viewer" in low and ext == ".zip":
        out["kind"] = "tool"
        out["product_key"] = "SCC" if low.startswith(("scc", "rpm-gpg")) or ext == ".scc" else "STIG_Viewer"
        return out
    if ext in _DOC_EXT:
        out["kind"] = "document"
    elif ext == ".zip":
        rest = stem[m.end():] if m else ""
        if _COMPILATION.match(stem):
            out["kind"] = "compilation"
        elif _PACKAGE.match(stem):
            out["kind"] = "automation"
        elif m and _SCAP.search(rest):
            out["kind"] = "scap_benchmark"
        elif m and _AUTOMATION.search(rest):
            out["kind"] = "automation"
        elif m and rest.upper() in ("_STIG",):
            out["kind"] = "manual_stig"
        elif m and rest.upper().endswith("SRG"):
            out["kind"] = "srg"
        elif not m and stem.upper().endswith("_STIG") and stem.upper().startswith("U_"):
            out["kind"] = "manual_stig"
    if stem.upper().startswith("U_"):
        prefix = stem[2:m.start()] if m else stem[2:]
        if out["kind"] == "compilation":
            prefix = re.sub(r"_[A-Za-z]+_\d{4}$", "", prefix)
        prefix = re.sub(r"_(STIG|SRG)$", "", prefix, flags=re.I)
        out["product_key"] = normalize_product(prefix) or None
    return out


def normalize_product(prefix: str) -> str:
    """Product prefix as used for matching: spaces to underscores, the "_LTS" marker dropped (DISA names
    Ubuntu benchmarks with and without it)."""
    p = re.sub(r"\s+", "_", prefix.strip()).strip("_")
    return re.sub(r"_LTS$", "", p, flags=re.I)


def entry_from_record(rec: dict) -> Entry | None:
    link = str(rec.get("DownloadLink") or "").strip()
    if not link:
        return None
    parts = urllib.parse.urlsplit(link)
    filename = urllib.parse.unquote(parts.path.rstrip("/").rsplit("/", 1)[-1]) or (parts.hostname or "item")
    info = parse_filename(filename)
    types = [clean_text(t) for t in re.split(r"[;,]", str(rec.get("RawDownloadType") or rec.get("DownloadType") or ""))]
    types = [t for t in types if t]
    return Entry(filename=filename, url=link, host=(parts.hostname or "").lower(), title=clean_text(rec.get("FileName")),
                 kind=info["kind"], product_key=info["product_key"], version=info["version"],
                 version_label=info["version_label"], sunset=any("sunset" in t.lower() for t in types),
                 upload_date=clean_text(rec.get("UploadDate")) or None, download_types=types,
                 name=clean_text(rec.get("Name")) or None)


def entries_from_records(records: list) -> list[Entry]:
    out = []
    for r in records:
        if isinstance(r, dict):
            e = entry_from_record(r)
            if e is not None:
                out.append(e)
    return out


def records_of(doc: Any) -> list:
    """The record list from an Apex answer ({returnValue}), a saved snapshot ({entries}) or a bare list."""
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict):
        for k in ("returnValue", "entries"):
            v = doc.get(k)
            if isinstance(v, list):
                return v
            if isinstance(v, dict) and isinstance(v.get("returnValue"), list):
                return v["returnValue"]
    raise IndexFetchError("not a STIG index: expected returnValue or entries")


def load_snapshot(path: str | Path) -> list[Entry]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    return entries_from_records(records_of(doc))


BUNDLED_SNAPSHOT = Path(__file__).resolve().parents[1] / "data" / "cybermil_catalog.json"


# -- fetching -----------------------------------------------------------------------------------

@dataclass
class IndexResult:
    entries: list[Entry]
    classname: str
    rediscovered: bool
    wire_bytes: int
    bytes: int
    gzip: bool
    seconds: float
    url: str

    def stats(self) -> dict:
        return {"classname": self.classname, "rediscovered": self.rediscovered, "wire_bytes": self.wire_bytes,
                "bytes": self.bytes, "gzip": self.gzip, "seconds": self.seconds, "entries": len(self.entries)}


def _body(classname: str) -> bytes:
    return json.dumps({"namespace": "", "classname": classname, "method": METHOD, "isContinuation": False,
                       "params": {"documentLibrary": LIBRARY}, "cacheable": False}).encode("utf-8")


def decode_body(raw: bytes, encoding: str | None, max_bytes: int) -> bytes:
    """Undo Content-Encoding gzip/deflate with the output capped at max_bytes."""
    enc = (encoding or "").lower().strip()
    if enc in ("", "identity"):
        return raw
    if enc not in ("gzip", "x-gzip", "deflate"):
        raise IndexFetchError(f"unsupported content encoding {enc!r}")
    d = zlib.decompressobj(16 + zlib.MAX_WBITS if "gzip" in enc else zlib.MAX_WBITS)
    out = d.decompress(raw, max_bytes + 1)
    if len(out) > max_bytes or d.unconsumed_tail:
        raise IndexFetchError(f"index larger than {max_bytes} bytes once decompressed")
    return out


def _call(client, classname: str, *, timeout: float, max_bytes: int) -> tuple[int, dict, bytes, int]:
    status, headers, raw = client.request("POST", APEX_URL, data=_body(classname), timeout=timeout,
                                          max_bytes=max_bytes,
                                          headers={"Content-Type": "application/json", "Accept": "application/json",
                                                   "Accept-Encoding": "gzip"})
    return status, headers, decode_body(raw, headers.get("content-encoding"), max_bytes), len(raw)


def _parse(status: int, headers: dict, body: bytes) -> list | None:
    if status != 200:
        return None
    ctype = headers.get("content-type", "")
    if "json" not in ctype.lower():
        return None
    try:
        return records_of(json.loads(body.decode("utf-8")))
    except (ValueError, UnicodeDecodeError, IndexFetchError):
        return None


def discover_classname(client, *, timeout: float = 30.0) -> str:
    """Find the Apex class id the downloads page uses today."""
    status, headers, raw = client.request("GET", DOWNLOADS_PAGE, timeout=timeout, max_bytes=MAX_PAGE_BYTES,
                                          headers={"Accept": "text/html", "Accept-Encoding": "gzip"})
    page = decode_body(raw, headers.get("content-encoding"), MAX_PAGE_BYTES).decode("utf-8", "replace")
    if status != 200:
        raise IndexFetchError(f"downloads page answered {status}")
    m = _VIEW.search(page)
    if not m:
        raise IndexFetchError("downloads page names no STIG library view bundle")
    view = urllib.parse.urljoin(DOWNLOADS_PAGE, m.group(0))
    status, headers, raw = client.request("GET", view, timeout=timeout, max_bytes=MAX_PAGE_BYTES,
                                          headers={"Accept": "*/*", "Accept-Encoding": "gzip"})
    if status != 200:
        raise IndexFetchError(f"view bundle answered {status}")
    js = decode_body(raw, headers.get("content-encoding"), MAX_PAGE_BYTES).decode("utf-8", "replace")
    m = _INVOKER.search(js)
    if not m:
        raise IndexFetchError("view bundle does not name the catalog class")
    return m.group(1)


def fetch_index_result(client, *, timeout: float = 30.0, max_bytes: int = MAX_INDEX_BYTES,
                       classname: str | None = None,
                       on_discover: Callable[[str], None] | None = None) -> IndexResult:
    """Fetch the STIG index. Tries the cached or known class id first and rediscovers it once if the site
    refuses or answers with something that is not the catalog."""
    from cyberthunder.ingest.content.http import as_client
    client = as_client(client)
    start = time.monotonic()
    tried = []
    rediscovered = False
    cls = classname or KNOWN_CLASSNAME
    for attempt in range(2):
        tried.append(cls)
        status, headers, body, wire = _call(client, cls, timeout=timeout, max_bytes=max_bytes)
        records = _parse(status, headers, body)
        if records is not None:
            entries = entries_from_records(records)
            return IndexResult(entries=entries, classname=cls, rediscovered=rediscovered, wire_bytes=wire,
                               bytes=len(body), gzip="gzip" in headers.get("content-encoding", "").lower(),
                               seconds=round(time.monotonic() - start, 3), url=APEX_URL)
        if attempt:
            break
        found = discover_classname(client, timeout=timeout)
        # The page may still name the id that just failed (a transient refusal); one more try costs a
        # single round trip either way.
        rediscovered = found != cls
        cls = found
        if on_discover is not None and rediscovered:
            on_discover(found)
    raise IndexFetchError(f"the STIG index did not answer with a catalog (tried {', '.join(tried)})")


def fetch_index(opener, *, timeout: float = 30.0, max_bytes: int = MAX_INDEX_BYTES,
                classname: str | None = None, on_discover: Callable[[str], None] | None = None) -> list[Entry]:
    return fetch_index_result(opener, timeout=timeout, max_bytes=max_bytes, classname=classname,
                              on_discover=on_discover).entries


__all__ = ["Entry", "IndexResult", "IndexFetchError", "parse_filename", "load_snapshot", "fetch_index",
           "fetch_index_result", "discover_classname", "KNOWN_CLASSNAME", "ALLOWED_HOSTS", "BUNDLED_SNAPSHOT",
           "clean_text", "entries_from_records", "records_of"]
