"""Resumable, size-capped, verified download of one DISA file.

  1. HEAD for size and ETag, and an estimate of the transfer time at the link rate before the first byte.
  2. GET streamed to <dest>/<name>.part in 64 KB chunks. An existing .part resumes with Range plus
     If-Range: <ETag>; a 200 answer to a Range request, or a changed ETag, restarts from zero.
  3. The size cap holds on Content-Length and on the bytes actually read.
  4. The result is hashed (SHA-256), zip-tested, and for manual STIGs and SCAP benchmarks the XCCDF or
     datastream inside is parsed. Only then does the file get its final name. A file that fails a check
     moves to the quarantine folder with a note saying why.

Nothing downloaded is executed, imported or extracted to a path taken from the archive.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import shutil
import tempfile
import time
import urllib.parse
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable
from xml.etree import ElementTree as ET

from cyberthunder.findings.schema import utcnow
from cyberthunder.ingest.content.http import ContentClient, ContentNetworkError, HostNotAllowed, as_client
from cyberthunder.ingest.content.index import Entry, parse_filename
from cyberthunder.ingest.delta import BenchmarkError, _pick_member
from cyberthunder.ingest.link import LinkState, transfer_seconds
from cyberthunder.parsers.xccdf import parse_xccdf

CHUNK = 64 * 1024
DEFAULT_MAX_BYTES = 512 * 1024 * 1024          # the quarterly library is about 400 MB
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 2 * 1024 * 1024 * 1024
MAX_MEMBERS = 20000


class ContentError(RuntimeError):
    """A download could not be completed. `resumable` means the .part was kept for a later resume."""

    def __init__(self, msg: str, *, resumable: bool = False, filename: str | None = None):
        super().__init__(msg)
        self.resumable = resumable
        self.filename = filename


class SizeCapExceeded(ContentError):
    pass


class Stopped(ContentError):
    """The caller asked the download to stop (kill switch, link down). The .part is kept for a resume."""


class Quarantined(ContentError):
    def __init__(self, msg: str, *, path: Path, filename: str | None = None):
        super().__init__(msg, filename=filename)
        self.path = path


@dataclass
class FetchResult:
    filename: str
    path: str
    url: str
    bytes: int
    sha256: str
    etag: str | None
    last_modified: str | None
    seconds: float
    estimate_seconds: float | None
    resumed: bool = False
    restarted: bool = False
    requests: int = 0
    fetched_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        return asdict(self)


def disk_name(filename: str) -> str:
    """The file name used on disk: basename only, nothing a shell or a path could misread."""
    base = Path(str(filename).replace("\\", "/")).name
    safe = re.sub(r"[^A-Za-z0-9._+-]+", "_", base).strip("._")[:200] or "download"
    if safe.split(".", 1)[0].upper() in _WINDOWS_RESERVED:
        safe = "_" + safe                  # CON.zip, NUL.xml and the like open a device on Windows
    return safe


_WINDOWS_RESERVED = frozenset({"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
                               *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))})


# -- integrity ------------------------------------------------------------------------------------

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_root(data: bytes) -> str:
    class NoDTD(ET.TreeBuilder):
        def doctype(self, name, pubid, system):
            raise ValueError("DTD and entity declarations are not permitted")

    try:
        root = ET.fromstring(data, parser=ET.XMLParser(target=NoDTD()))
    except ET.ParseError as e:
        raise ValueError(f"XML does not parse: {e}") from None
    return _local(root.tag)


def find_datastream(zf: zipfile.ZipFile) -> zipfile.ZipInfo:
    """The SCAP datastream member of a DISA benchmark zip."""
    xml = [m for m in zf.infolist() if not m.is_dir() and m.filename.lower().endswith(".xml")]
    if not xml:
        raise ValueError("benchmark zip has no XML member")
    pref = [m for m in xml if "benchmark" in Path(m.filename).name.lower()] or xml
    pref.sort(key=lambda m: (-m.file_size, m.filename))
    return pref[0]


def check_file(path: str | Path, kind: str | None = None, *, filename: str | None = None) -> dict:
    """Integrity checks for one file. Returns {checked: [...], member?} or raises ValueError with the reason."""
    p = Path(path)
    name = filename or p.name
    kind = kind or parse_filename(name)["kind"]
    checked: list[str] = []
    out: dict[str, Any] = {"checked": checked}
    if name.lower().endswith(".xml"):
        if p.stat().st_size > MAX_MEMBER_BYTES:
            raise ValueError("XML exceeds the size limit")
        root = _xml_root(p.read_bytes())
        allowed = ("Benchmark", "data-stream-collection") if kind in ("scap_benchmark", "other") else ("Benchmark",)
        if root not in allowed:
            raise ValueError(f"not an XCCDF benchmark or SCAP datastream (root {root})")
        checked.append(f"xml:{root}")
        if root == "Benchmark":
            parsed = parse_xccdf(p)
            if not parsed.benchmark_id or not parsed.rules:
                raise ValueError("XML has no benchmark id or no rules")
            out.update(benchmark_id=parsed.benchmark_id, rules=len(parsed.rules))
            checked.append("xccdf")
        return out
    is_zip = name.lower().endswith(".zip") or kind in ("manual_stig", "scap_benchmark", "srg", "automation",
                                                      "compilation")
    if not is_zip:
        return out
    if not zipfile.is_zipfile(p):
        raise ValueError("not a zip archive")
    try:
        with zipfile.ZipFile(p) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_MEMBERS:
                raise ValueError(f"zip has {len(infos)} members; refusing")
            total = 0
            for m in infos:
                n = m.filename.replace("\\", "/")
                if n.startswith("/") or re.match(r"^[A-Za-z]:", n) or ".." in n.split("/"):
                    raise ValueError(f"zip member has an unsafe path: {m.filename!r}")
                total += m.file_size
            if total > MAX_TOTAL_UNCOMPRESSED:
                raise ValueError(f"zip expands to {total} bytes; refusing")
            bad = zf.testzip()
            if bad is not None:
                raise ValueError(f"zip member {bad!r} fails its CRC check")
            checked.append("zip")
            if kind in ("manual_stig", "srg"):
                try:
                    m = _pick_member(zf)
                except BenchmarkError as e:
                    raise ValueError(str(e)) from None
                if m.file_size > MAX_MEMBER_BYTES:
                    raise ValueError(f"{m.filename} is {m.file_size} bytes uncompressed; refusing")
                root = _xml_root(zf.read(m))
                if root != "Benchmark":
                    raise ValueError(f"{m.filename} is not an XCCDF benchmark (root {root})")
                tmp = Path(tempfile.mkdtemp(prefix="ct-check-"))
                try:
                    x = tmp / "check-xccdf.xml"
                    x.write_bytes(zf.read(m))
                    parsed = parse_xccdf(x)
                    if not parsed.benchmark_id or not parsed.rules:
                        raise ValueError(f"{m.filename} has no benchmark id or no rules")
                except ValueError:
                    raise
                except Exception as e:  # noqa: BLE001 - any parser failure is a reason to refuse
                    raise ValueError(f"{m.filename} does not parse as XCCDF: {e}") from None
                finally:
                    shutil.rmtree(tmp, ignore_errors=True)
                checked.append("xccdf")
                out["member"] = m.filename
                out["benchmark_id"] = parsed.benchmark_id
                out["rules"] = len(parsed.rules)
            elif kind == "scap_benchmark":
                m = find_datastream(zf)
                if m.file_size > MAX_MEMBER_BYTES:
                    raise ValueError(f"{m.filename} is {m.file_size} bytes uncompressed; refusing")
                root = _xml_root(zf.read(m))
                if root not in ("data-stream-collection", "Benchmark"):
                    raise ValueError(f"{m.filename} is not a SCAP datastream (root {root})")
                checked.append("datastream")
                out["member"] = m.filename
    except zipfile.BadZipFile as e:
        raise ValueError(f"bad zip: {e}") from None
    return out


def quarantine(path: Path, qdir: Path, reason: str, *, filename: str, url: str | None = None) -> Path:
    qdir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    dest = qdir / f"{stamp}-{disk_name(filename)}"
    n = 1
    while dest.exists():
        dest = qdir / f"{stamp}-{n}-{disk_name(filename)}"
        n += 1
    os.replace(path, dest)
    note = {"filename": filename, "url": url, "reason": reason, "quarantined_at": utcnow(), "bytes": dest.stat().st_size}
    dest.with_name(dest.name + ".why.json").write_text(json.dumps(note, indent=2), encoding="utf-8")
    return dest


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# -- download -------------------------------------------------------------------------------------

def _int(v: Any) -> int | None:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _meta_path(part: Path) -> Path:
    return part.with_name(part.name + ".json")


def download(opener: ContentClient | Any, entry: Entry | dict, dest_dir: str | Path, *, link: LinkState | None = None,
             max_bytes: int = DEFAULT_MAX_BYTES, pace: bool = False,
             progress: Callable[[dict], None] | None = None, quarantine_dir: str | Path | None = None,
             retries: int = 2, timeout: float | None = None, expected_sha256: str | None = None,
             sleep: Callable[[float], None] = time.sleep,
             stop: Callable[[], str | None] | None = None) -> FetchResult:
    """Fetch entry.url into dest_dir and verify it. See the module docstring for the steps.

    `stop` is polled between chunks; a non-empty answer ends the download with Stopped and keeps the .part."""
    client = as_client(opener)
    if isinstance(entry, dict):
        entry = Entry.from_dict(entry) if "host" in entry else _entry_from_item(entry)
    url = entry.url
    client.check_url(url)
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    qdir = Path(quarantine_dir) if quarantine_dir else dest_dir / "quarantine"
    name = disk_name(entry.filename)
    final = dest_dir / name
    part = dest_dir / (name + ".part")
    meta_p = _meta_path(part)
    started = time.monotonic()
    requests = 0

    def report(**kw) -> None:
        if progress is not None:
            try:
                progress(dict(kw, filename=entry.filename))
            except Exception:  # noqa: BLE001 - a progress sink must never break a download
                pass

    # 1. HEAD
    status, head, _ = client.request("HEAD", url, timeout=timeout, max_bytes=0)
    requests += 1
    total = etag = last_mod = None
    if status == 200:
        total = _int(head.get("content-length"))
        etag = head.get("etag")
        last_mod = head.get("last-modified")
    elif status in (403, 404, 410):
        raise ContentError(f"{entry.filename}: the server answered {status}", filename=entry.filename)
    if total is not None and total > max_bytes:
        raise SizeCapExceeded(f"{entry.filename} is {total} bytes; the cap is {max_bytes}", filename=entry.filename)
    estimate = transfer_seconds(total, link) if (link is not None and total is not None) else None
    report(state="starting", bytes=0, total=total, estimate_seconds=estimate)

    resumed = restarted = False
    attempt = 0
    while True:
        attempt += 1
        have = part.stat().st_size if part.exists() else 0
        saved = {}
        if have and meta_p.exists():
            try:
                saved = json.loads(meta_p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                saved = {}
        if have and (not saved.get("etag") or (etag and saved.get("etag") != etag) or saved.get("url") != url):
            part.unlink(missing_ok=True)          # changed upstream, or no validator to resume against
            have = 0
            restarted = True
        if total is not None and have > total:
            part.unlink(missing_ok=True)
            have = 0
            restarted = True
        headers = {"Accept-Encoding": "identity"}
        if have and etag:
            headers["Range"] = f"bytes={have}-"
            headers["If-Range"] = etag
        _write_meta(meta_p, url, etag, total)
        try:
            n = _get(client, url, part, headers, have=have, total=total, max_bytes=max_bytes, link=link, pace=pace,
                     report=report, timeout=timeout, sleep=sleep, stop=stop)
            requests += 1
            if n.get("resumed"):
                resumed = True
            if n.get("restarted"):
                restarted = True
            if n.get("etag") and etag and n["etag"] != etag:
                etag = n["etag"]
            if n.get("etag") and not etag:
                etag = n["etag"]
            break
        except SizeCapExceeded:
            requests += 1
            qpath = quarantine(part, qdir, "size cap exceeded while reading", filename=entry.filename, url=url) \
                if part.exists() else qdir
            meta_p.unlink(missing_ok=True)
            raise SizeCapExceeded(f"{entry.filename}: more than {max_bytes} bytes; refused (kept at {qpath})",
                                  filename=entry.filename) from None
        except ContentError as e:
            requests += 1
            if not e.resumable or attempt > retries:
                raise
            report(state="retrying", bytes=part.stat().st_size if part.exists() else 0, total=total, error=str(e))
            sleep(min(1.0 * attempt, 5.0))

    got = part.stat().st_size
    if total is not None and got != total:
        raise ContentError(f"{entry.filename}: got {got} of {total} bytes", resumable=True, filename=entry.filename)
    digest = sha256_file(part)
    report(state="verifying", bytes=got, total=total)
    reason = None
    if expected_sha256 and digest.lower() != expected_sha256.lower():
        reason = f"SHA-256 {digest} does not match the expected {expected_sha256}"
    else:
        try:
            check_file(part, entry.kind, filename=entry.filename)
        except ValueError as e:
            reason = str(e)
    meta_p.unlink(missing_ok=True)
    if reason is not None:
        qpath = quarantine(part, qdir, reason, filename=entry.filename, url=url)
        report(state="quarantined", bytes=got, total=total, error=reason)
        raise Quarantined(f"{entry.filename}: {reason}", path=qpath, filename=entry.filename)
    os.replace(part, final)
    secs = round(time.monotonic() - started, 3)
    report(state="done", bytes=got, total=total)
    return FetchResult(filename=entry.filename, path=str(final), url=url, bytes=got, sha256=digest, etag=etag,
                       last_modified=last_mod, seconds=secs, estimate_seconds=estimate, resumed=resumed,
                       restarted=restarted, requests=requests)


def _write_meta(p: Path, url: str, etag: str | None, total: int | None) -> None:
    p.write_text(json.dumps({"url": url, "etag": etag, "total": total}), encoding="utf-8")


def _get(client: ContentClient, url: str, part: Path, headers: dict, *, have: int, total: int | None, max_bytes: int,
         link: LinkState | None, pace: bool, report, timeout, sleep, stop=None) -> dict:
    try:
        status, h, resp = client.open("GET", url, headers=headers, timeout=timeout)
    except ContentNetworkError as e:
        if isinstance(e, HostNotAllowed):
            raise
        raise ContentError(str(e), resumable=True) from None
    info: dict[str, Any] = {"etag": h.get("etag")}
    try:
        if status == 206 and have:
            m = re.match(r"bytes\s+(\d+)-", h.get("content-range", ""))
            if not m or int(m.group(1)) != have:
                raise ContentError(f"{url}: the server resumed at the wrong offset", resumable=False)
            mode = "ab"
            info["resumed"] = True
        elif status == 200:
            mode = "wb"
            if have:
                info["restarted"] = True     # If-Range did not match: the server sent the whole file again
            have = 0
        elif status == 416:
            part.unlink(missing_ok=True)
            raise ContentError(f"{url}: the server refused the resume range; starting over", resumable=True)
        else:
            raise ContentError(f"{url}: the server answered {status}", resumable=status >= 500)
        length = _int(h.get("content-length"))
        if length is not None and have + length > max_bytes:
            raise SizeCapExceeded(f"{url}: {have + length} bytes; the cap is {max_bytes}")
        expect_total = total if total is not None else (have + length if length is not None else None)
        done = have
        session = 0
        slept = 0.0
        t0 = time.monotonic()
        last_report = 0.0
        rate = (link.kbps * 1000 / 8) if (pace and link is not None and link.kbps > 0) else None
        with open(part, mode) as fh:
            while True:
                try:
                    chunk = resp.read(CHUNK)
                except (http.client.IncompleteRead, OSError, ValueError) as e:
                    fh.flush()
                    raise ContentError(f"{url}: connection lost after {done} bytes ({e.__class__.__name__})",
                                       resumable=True) from None
                if not chunk:
                    break
                done += len(chunk)
                session += len(chunk)
                if done > max_bytes:
                    fh.write(chunk[: max(0, max_bytes - (done - len(chunk)))])
                    raise SizeCapExceeded(f"{url}: more than {max_bytes} bytes")
                fh.write(chunk)
                if stop is not None:
                    why = stop()
                    if why:
                        fh.flush()
                        raise Stopped(f"{url}: stopped after {done} bytes ({why})", resumable=False)
                if rate:
                    # time already spent, counting the sleeps themselves (a test clock does not advance)
                    spent = max(time.monotonic() - t0, slept)
                    ahead = session / rate - spent
                    if ahead > 0:
                        sleep(ahead)
                        slept = spent + ahead
                now = time.monotonic()
                if now - last_report >= 0.25:
                    last_report = now
                    report(state="downloading", bytes=done, total=expect_total)
        if expect_total is not None and done < expect_total:
            raise ContentError(f"{url}: connection closed after {done} of {expect_total} bytes", resumable=True)
        return info
    finally:
        try:
            resp.close()
        except Exception:  # noqa: BLE001
            pass


def _entry_from_item(item: dict) -> Entry:
    """An Entry from a manifest item {filename, url, product_key?, kind?, version?}."""
    url = str(item["url"])
    filename = item.get("filename") or urllib.parse.unquote(urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1])
    info = parse_filename(filename)
    version = item.get("version")
    return Entry(filename=filename, url=url, host=(urllib.parse.urlsplit(url).hostname or "").lower(),
                 title=item.get("title") or filename, kind=item.get("kind") or info["kind"],
                 product_key=item.get("product_key") or info["product_key"],
                 version=tuple(version) if version else info["version"],
                 version_label=item.get("version_label") or info["version_label"])


entry_from_item = _entry_from_item

__all__ = ["download", "check_file", "disk_name", "find_datastream", "quarantine", "sha256_file", "FetchResult",
           "ContentError", "SizeCapExceeded", "Stopped", "Quarantined", "ContentNetworkError", "entry_from_item"]
