"""The only network client in Cyber Thunder that reaches outside the enclave.

Read-only egress to an allow-list of exactly two DoD hosts over HTTPS with certificate verification.
Redirects are followed only while they stay on the allow-list. Every answer is size-capped as it is read.
Nothing fetched is executed or imported: callers open zips with zipfile and parse XML with ElementTree.
"""
from __future__ import annotations

import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterable

from cyberthunder import __version__
from cyberthunder.ingest.content.index import ALLOWED_HOSTS

USER_AGENT = f"cyber-thunder/{__version__} (content pull)"
DEFAULT_TIMEOUT = 30.0
_URL_SAFE = "/%+()-_.~!$&'*,;=:@"


class ContentNetworkError(RuntimeError):
    """A request was refused by policy or failed on the wire."""


class HostNotAllowed(ContentNetworkError):
    pass


def quote_url(url: str) -> str:
    """Percent-encode characters that cannot appear in a request line (DISA has a file name with a space)."""
    p = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((p.scheme, p.netloc, urllib.parse.quote(p.path, safe=_URL_SAFE),
                                    urllib.parse.quote(p.query, safe="=&%+:@/,;"), ""))


class _AllowListRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, client: "ContentClient"):
        super().__init__()
        self.client = client

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.client.check_url(urllib.parse.urljoin(req.full_url, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class ContentClient:
    """Small policy wrapper around a urllib opener.

    `opener` is anything with urllib's OpenerDirector.open(request, timeout=) and is injectable for tests.
    `allowed_hosts` and `allow_http` exist so a test can point the client at a loopback server; the
    service never takes them from settings, so the production allow-list cannot be widened by config."""

    def __init__(self, opener: Any = None, *, allowed_hosts: Iterable[str] = ALLOWED_HOSTS,
                 allow_http: bool = False, timeout: float = DEFAULT_TIMEOUT, user_agent: str = USER_AGENT,
                 proxies: dict | None = None):
        self.allowed_hosts = frozenset(h.lower() for h in allowed_hosts)
        self.allow_http = allow_http
        self.timeout = timeout
        self.user_agent = user_agent
        self.proxies = proxies          # None: the environment's HTTPS_PROXY / NO_PROXY, as for any tool
        self.opener = opener if opener is not None else self.build_opener()

    def build_opener(self) -> urllib.request.OpenerDirector:
        ctx = ssl.create_default_context()           # certificate and host name verification on
        handlers: list = [urllib.request.HTTPSHandler(context=ctx), _AllowListRedirects(self)]
        if self.proxies is not None:
            handlers.append(urllib.request.ProxyHandler(self.proxies))
        return urllib.request.build_opener(*handlers)

    # -- policy ---------------------------------------------------------------------------------
    def check_url(self, url: str) -> str:
        p = urllib.parse.urlsplit(url)
        scheme = (p.scheme or "").lower()
        if scheme != "https" and not (self.allow_http and scheme == "http"):
            raise HostNotAllowed(f"refusing {scheme or 'schemeless'} URL {url!r}: HTTPS only")
        host = (p.hostname or "").lower()
        if host not in self.allowed_hosts:
            raise HostNotAllowed(f"refusing {host or url!r}: not on the content allow-list "
                                 f"({', '.join(sorted(self.allowed_hosts))})")
        if p.username or p.password:
            raise HostNotAllowed("refusing a URL with embedded credentials")
        try:
            port = p.port
        except ValueError:
            raise HostNotAllowed(f"refusing {url!r}: the port does not parse") from None
        if port is not None and port != 443 and host in ALLOWED_HOSTS:
            raise HostNotAllowed(f"refusing {url!r}: the DoD content hosts are reached on port 443 only")
        return url

    # -- requests -------------------------------------------------------------------------------
    def open(self, method: str, url: str, *, headers: dict | None = None, data: bytes | None = None,
             timeout: float | None = None):
        """(status, headers with lower-case names, response). Non-2xx answers come back too, not raised."""
        self.check_url(url)
        h = {"User-Agent": self.user_agent}
        h.update(headers or {})
        req = urllib.request.Request(quote_url(url), data=data, headers=h, method=method)
        try:
            resp = self.opener.open(req, timeout=timeout or self.timeout)
        except urllib.error.HTTPError as e:
            resp = e
        except HostNotAllowed:
            raise
        except urllib.error.URLError as e:
            reason = e.reason
            if isinstance(reason, HostNotAllowed):
                raise reason from None
            raise ContentNetworkError(f"{urllib.parse.urlsplit(url).hostname}: {reason}") from None
        except (OSError, ValueError) as e:
            raise ContentNetworkError(f"{urllib.parse.urlsplit(url).hostname}: {e}") from None
        final = getattr(resp, "url", None) or (resp.geturl() if hasattr(resp, "geturl") else None)
        if final:
            self.check_url(final)
        status = int(getattr(resp, "status", None) or getattr(resp, "code", 0) or 0)
        hdrs = {k.lower(): v for k, v in (resp.headers.items() if getattr(resp, "headers", None) is not None else [])}
        return status, hdrs, resp

    def request(self, method: str, url: str, *, headers: dict | None = None, data: bytes | None = None,
                timeout: float | None = None, max_bytes: int = 4 * 1024 * 1024) -> tuple[int, dict, bytes]:
        status, hdrs, resp = self.open(method, url, headers=headers, data=data, timeout=timeout)
        try:
            length = hdrs.get("content-length")
            if method != "HEAD" and length and length.isdigit() and int(length) > max_bytes:
                raise ContentNetworkError(f"{url} answers {length} bytes; the cap is {max_bytes}")
            body = b""
            if method != "HEAD":
                try:
                    body = resp.read(max_bytes + 1)
                except (OSError, ValueError) as e:
                    raise ContentNetworkError(f"{urllib.parse.urlsplit(url).hostname}: {e}") from None
                if len(body) > max_bytes:
                    raise ContentNetworkError(f"{url} answered more than {max_bytes} bytes")
        finally:
            try:
                resp.close()
            except Exception:  # noqa: BLE001 - closing a dead socket must not hide the real error
                pass
        return status, hdrs, body


def as_client(x: Any) -> ContentClient:
    if isinstance(x, ContentClient):
        return x
    return ContentClient(opener=x)
