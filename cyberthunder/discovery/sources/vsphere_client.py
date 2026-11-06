"""Small, bounded client for the vSphere Web Services inventory API (/sdk).

Only session, ephemeral view and property retrieval methods are available.
No redirect, proxy, ambient credential, guest operation or inventory mutation.
"""
from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit

SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
VIM = "urn:vim25"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
MAX_BODY = 2 * 1024 * 1024
MAX_TOTAL_BODY = 16 * 1024 * 1024
MAX_PAGES, PAGE_SIZE, MAX_OBJECTS = 20, 250, 5000
CALL_TIMEOUT, TOTAL_TIMEOUT = 10.0, 60.0
PROPERTIES = {
    "VirtualMachine": ("name", "config.instanceUuid", "config.uuid", "config.guestFullName",
                       "runtime.powerState", "runtime.host", "guest.ipAddress", "guest.hostName"),
    "HostSystem": ("name", "hardware.systemInfo.uuid", "summary.config.product.fullName",
                   "runtime.connectionState", "runtime.powerState", "config.network.vnic"),
}
METHODS = frozenset({"RetrieveServiceContent", "Login", "Logout", "CreateContainerView", "DestroyView",
                     "RetrievePropertiesEx", "ContinueRetrievePropertiesEx", "CancelRetrievePropertiesEx"})


class VsphereError(RuntimeError):
    """Only fixed error codes cross the boundary; never remote fault text or secrets."""


def text(value, limit=1024):
    if (not isinstance(value, str) or not value or len(value) > limit
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise VsphereError("vsphere:invalid_data")
    return value


def reference(node, kind):
    if node is None or node.get("type") != kind or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", node.text or ""):
        raise VsphereError("vsphere:invalid_reference")
    return node.text


@dataclass(frozen=True)
class Endpoint:
    url: str
    host: str
    port: int
    address: str
    ca_file: str | None

    @classmethod
    def parse(cls, url, address, *, tls_trust=None, ca_file=None):
        try:
            if not isinstance(url, str) or len(url) > 512 or not url.isascii() or any(ord(c) < 33 for c in url):
                raise ValueError
            u = urlsplit(url)
            if (u.scheme != "https" or not u.hostname or u.username is not None or u.password is not None
                    or u.path != "/sdk" or u.query or u.fragment or "%" in url or "\\" in url):
                raise ValueError
            host = u.hostname
            try:
                host_ip = ipaddress.ip_address(host)
            except ValueError:
                if re.fullmatch(r"[0-9.]+", host) or len(host) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", p)
                                             for p in host.split(".")):
                    raise ValueError
                host_ip = None
            ip = ipaddress.ip_address(address)
            if "%" in str(address) or ip.is_unspecified or ip.is_multicast or (host_ip and ip != host_ip):
                raise ValueError
            port = 443 if u.port is None else u.port
            if not 1 <= port <= 65535 or u.netloc.endswith(":"):
                raise ValueError
            if tls_trust == "system":
                if ca_file is not None:
                    raise ValueError
            elif tls_trust == "ca_file":
                if not isinstance(ca_file, str) or not Path(ca_file).is_absolute() or not Path(ca_file).is_file():
                    raise ValueError
            else:
                raise ValueError
            authority = f"[{host}]" if host_ip and host_ip.version == 6 else host
            return cls(f"https://{authority}:{port}/sdk", host, port, str(ip), ca_file)
        except (ValueError, TypeError, OSError):
            raise VsphereError("vsphere:invalid_endpoint_or_trust") from None

    def tls_context(self):
        try:
            context = ssl.create_default_context(cafile=self.ca_file)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            return context
        except (OSError, ssl.SSLError):
            raise VsphereError("vsphere:invalid_tls_trust") from None


class _Connection(http.client.HTTPSConnection):
    """Pin the socket to the reviewed IP; the endpoint hostname is only Host/SNI/TLS identity."""

    def __init__(self, endpoint, timeout, context, guard):
        super().__init__(endpoint.host, endpoint.port, timeout=timeout, context=context)
        self.endpoint, self.guard, self.active_socket = endpoint, guard, None
        self.expired = threading.Event()

    def _check_expired(self):
        if self.expired.is_set():
            if self.active_socket is not None:
                self.active_socket.close()
            raise VsphereError("vsphere:deadline")

    def connect(self):
        self.guard()
        self._check_expired()
        ip = ipaddress.ip_address(self.endpoint.address)
        self.sock = self.active_socket = socket.socket(socket.AF_INET6 if ip.version == 6 else socket.AF_INET,
                                                       socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self._check_expired()
        self.sock.connect((str(ip), self.port))
        self.guard()
        self._check_expired()
        self.sock = self.active_socket = self._context.wrap_socket(
            self.sock, server_hostname=self.host, do_handshake_on_connect=False)
        self._check_expired()
        self.sock.do_handshake()
        self.guard()
        self._check_expired()

    def interrupt(self):
        self.expired.set()
        sock = self.active_socket
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()


def _element(parent, name, value=None, **attrs):
    child = ET.SubElement(parent, f"{{{VIM}}}{name}", attrs)
    child.text = value
    return child


def _xml(body, method):
    try:
        decoded = body.decode("utf-8", "strict")
        if "\x00" in decoded or re.search(r"<!\s*(?:DOCTYPE|ENTITY)", decoded, re.I):
            raise ValueError
        root = ET.fromstring(decoded)
        envelope_body = root.find(f"{{{SOAP}}}Body") if root.tag == f"{{{SOAP}}}Envelope" else None
        if envelope_body is None or len(envelope_body) != 1:
            raise ValueError
        response = envelope_body[0]
        if response.tag == f"{{{SOAP}}}Fault":
            raise VsphereError("vsphere:api_fault")
        if response.tag != f"{{{VIM}}}{method}Response":
            raise ValueError
        return response
    except (UnicodeError, ValueError, ET.ParseError):
        raise VsphereError("vsphere:invalid_xml_response") from None


class InventoryClient:
    def __init__(self, endpoint: Endpoint, guard):
        self.endpoint, self.guard = endpoint, guard
        self.context = endpoint.tls_context()
        self.deadline = time.monotonic() + TOTAL_TIMEOUT
        self.total_body = 0
        self.cookie = None

    def _exchange(self, payload, method):
        self.guard()
        remaining = min(CALL_TIMEOUT, self.deadline - time.monotonic())
        if remaining <= 0:
            raise VsphereError("vsphere:deadline")
        connection = _Connection(self.endpoint, remaining, self.context, self.guard)
        timer_started = time.monotonic()
        timer = threading.Timer(remaining, connection.interrupt)
        timer.daemon = True
        timer.start()
        try:
            headers = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": '"urn:vim25/6.5"',
                       "Accept-Encoding": "identity", "Connection": "close"}
            if self.cookie:
                headers["Cookie"] = self.cookie
            connection.connect()
            self.guard()  # Immediately before transmitting session credentials or the next page token.
            connection.request("POST", "/sdk", payload, headers)
            response = connection.getresponse()
            if response.status != 200:
                raise VsphereError("vsphere:http_failure")
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                raise VsphereError("vsphere:encoded_response")
            if response.getheader("Content-Type", "").split(";", 1)[0].lower() not in {"text/xml", "application/xml"}:
                raise VsphereError("vsphere:invalid_content_type")
            lengths = response.headers.get_all("Content-Length", [])
            transfers = response.headers.get_all("Transfer-Encoding", [])
            if (len(lengths) > 1 or len(transfers) > 1 or (lengths and transfers)
                    or (transfers and transfers[0].lower() != "chunked")):
                raise VsphereError("vsphere:invalid_framing")
            if lengths and (not re.fullmatch(r"[0-9]{1,10}", lengths[0]) or int(lengths[0]) > MAX_BODY):
                raise VsphereError("vsphere:body_limit")
            body = response.read(MAX_BODY + 1)
            self.total_body += len(body)
            if (len(body) > MAX_BODY or self.total_body > MAX_TOTAL_BODY
                    or (lengths and len(body) != int(lengths[0]))):
                raise VsphereError("vsphere:body_limit")
            if time.monotonic() >= self.deadline or time.monotonic() >= timer_started + remaining:
                raise VsphereError("vsphere:deadline")
            self.guard()
            if method == "Login":
                cookies = SimpleCookie()
                for value in response.headers.get_all("Set-Cookie", []):
                    if len(value) > 8192:
                        raise VsphereError("vsphere:invalid_session")
                    cookies.load(value)
                session = cookies.get("vmware_soap_session")
                if session is None or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,4096}", session.value):
                    raise VsphereError("vsphere:invalid_session")
                self.cookie = session.OutputString(attrs=[])
            return body
        except PermissionError:
            raise
        except (OSError, http.client.HTTPException, ValueError, CookieError):
            raise VsphereError("vsphere:transport_failure") from None
        finally:
            timer.cancel()
            connection.close()

    def _call(self, method, kind, ref, build=None):
        if method not in METHODS:
            raise VsphereError("vsphere:unsupported_method")
        self.guard()
        envelope = ET.Element(f"{{{SOAP}}}Envelope", {"xmlns:vim": VIM})
        request = ET.SubElement(ET.SubElement(envelope, f"{{{SOAP}}}Body"), f"{{{VIM}}}{method}")
        _element(request, "_this", ref, type=kind)
        if build:
            build(request)
        body = self._exchange(ET.tostring(envelope, encoding="utf-8", xml_declaration=True), method)
        result = _xml(body, method)
        self.guard()
        return result.find(f"{{{VIM}}}returnval")

    def inventory(self, credentials):
        """A complete bounded snapshot or an exception; incomplete pages never become candidates."""
        manager = collector = view = token = None
        logged_in = False
        try:
            content = self._call("RetrieveServiceContent", "ServiceInstance", "ServiceInstance")
            if content is None:
                raise VsphereError("vsphere:missing_service_content")
            manager = reference(content.find(f"{{{VIM}}}sessionManager"), "SessionManager")
            collector = reference(content.find(f"{{{VIM}}}propertyCollector"), "PropertyCollector")
            views = reference(content.find(f"{{{VIM}}}viewManager"), "ViewManager")
            root = reference(content.find(f"{{{VIM}}}rootFolder"), "Folder")
            api_type = content.findtext(f"{{{VIM}}}about/{{{VIM}}}apiType")
            if api_type not in {"VirtualCenter", "HostAgent"}:
                raise VsphereError("vsphere:unsupported_server")
            instance = content.findtext(f"{{{VIM}}}about/{{{VIM}}}instanceUuid")
            instance = text(instance, 128) if instance else self.endpoint.url
            self.guard()
            username, password = credentials()
            text(username, 256)
            text(password, 16384)
            self._call("Login", "SessionManager", manager, lambda r: (
                _element(r, "userName", username), _element(r, "password", password)))
            del username, password
            logged_in = True
            view_node = self._call("CreateContainerView", "ViewManager", views, lambda r: (
                _element(r, "container", root, type="Folder"),
                *(_element(r, "type", kind) for kind in PROPERTIES), _element(r, "recursive", "true")))
            view = reference(view_node, "ContainerView")

            def query(r):
                spec = _element(r, "specSet")
                for kind, paths in PROPERTIES.items():
                    prop = _element(spec, "propSet")
                    _element(prop, "type", kind)
                    _element(prop, "all", "false")
                    for path in paths:
                        _element(prop, "pathSet", path)
                obj = _element(spec, "objectSet")
                _element(obj, "obj", view, type="ContainerView")
                _element(obj, "skip", "true")
                traversal = _element(obj, "selectSet", **{f"{{{XSI}}}type": "vim:TraversalSpec"})
                _element(traversal, "type", "ContainerView")
                _element(traversal, "path", "view")
                _element(traversal, "skip", "false")
                _element(_element(r, "options"), "maxObjects", str(PAGE_SIZE))

            result = self._call("RetrievePropertiesEx", "PropertyCollector", collector, query)
            records, seen_tokens = {}, set()
            for _ in range(MAX_PAGES):
                if result is None:
                    raise VsphereError("vsphere:missing_page")
                rows = result.findall(f"{{{VIM}}}objects")
                if len(rows) > PAGE_SIZE:
                    raise VsphereError("vsphere:page_limit")
                for row in rows:
                    record = _record(row)
                    key = record["kind"], record["ref"]
                    if key in records and records[key] != record:
                        raise VsphereError("vsphere:inconsistent_inventory")
                    records[key] = record
                    if len(records) > MAX_OBJECTS:
                        raise VsphereError("vsphere:object_limit")
                token = result.findtext(f"{{{VIM}}}token") or None
                if not token:
                    self.guard()
                    return instance, api_type, list(records.values())
                text(token, 4096)
                if token in seen_tokens:
                    raise VsphereError("vsphere:repeated_page_token")
                seen_tokens.add(token)
                if len(seen_tokens) >= MAX_PAGES:
                    raise VsphereError("vsphere:page_limit")
                result = self._call("ContinueRetrievePropertiesEx", "PropertyCollector", collector,
                                    lambda r: _element(r, "token", token))
            raise VsphereError("vsphere:page_limit")
        finally:
            # Cleanup also passes the guard. Revocation means no more network I/O;
            # the server expires the session/view if guarded logout cannot run.
            cleanup = []
            if token and collector:
                cleanup.append(("CancelRetrievePropertiesEx", "PropertyCollector", collector,
                                lambda r: _element(r, "token", token)))
            if view:
                cleanup.append(("DestroyView", "ContainerView", view, None))
            if logged_in:
                cleanup.append(("Logout", "SessionManager", manager, None))
            try:
                for method, kind, ref, build in cleanup:
                    try:
                        self._call(method, kind, ref, build)
                    except PermissionError:
                        break
                    except VsphereError:
                        continue
            finally:
                self.cookie = None


def _record(row):
    obj = row.find(f"{{{VIM}}}obj")
    kind = obj.get("type") if obj is not None else None
    if kind not in PROPERTIES or row.find(f"{{{VIM}}}missingSet") is not None:
        raise VsphereError("vsphere:incomplete_object")
    record = {"kind": kind, "ref": reference(obj, kind), "properties": {}}
    for prop in row.findall(f"{{{VIM}}}propSet"):
        name, val = prop.findtext(f"{{{VIM}}}name"), prop.find(f"{{{VIM}}}val")
        if name not in PROPERTIES[kind] or name in record["properties"] or val is None:
            raise VsphereError("vsphere:invalid_property")
        if name == "config.network.vnic":
            value = [text(n.text, 64) for n in val.findall(f".//{{{VIM}}}ipAddress") if n.text and not len(n)]
        elif name == "runtime.host":
            value = reference(val, "HostSystem")
        else:
            if len(val):
                raise VsphereError("vsphere:invalid_property")
            value = text(val.text) if val.text else ""
        record["properties"][name] = value
    return record
