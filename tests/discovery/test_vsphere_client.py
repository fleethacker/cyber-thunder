import ssl
from io import BytesIO
from threading import Event
from types import SimpleNamespace
from xml.etree import ElementTree as ET

import pytest

from cyberthunder.discovery.sources import vsphere_client as wire
from .vsphere_support import PASSWORD, Response, Server, endpoint, envelope


def read(server, guard=lambda: None):
    client = wire.InventoryClient(endpoint(), guard)
    result = client.inventory(lambda: ("reader@lab", PASSWORD))
    assert client.cookie is None
    assert all(c.closed for c in server.connections)
    return result


@pytest.mark.parametrize("api_type", ["VirtualCenter", "HostAgent"])
def test_supported_inventory_flow_and_only_read_queries(monkeypatch, api_type):
    server = Server(monkeypatch)
    server.service = server.service.replace(b"VirtualCenter", api_type.encode())
    instance, returned_type, rows = read(server)
    assert returned_type == api_type and instance.startswith("c2ff7f98")
    assert len(rows) == 5
    assert {r["ref"] for r in rows} == {"host-10", "vm-101", "vm-102", "vm-103", "vm-104"}
    assert server.methods == ["RetrieveServiceContent", "Login", "CreateContainerView", "RetrievePropertiesEx",
                              "ContinueRetrievePropertiesEx", "DestroyView", "Logout"]
    login = server.calls[1][1]
    assert login.findtext(f"{{{wire.VIM}}}password") == PASSWORD
    assert b"&lt;&amp;&gt;" in server.calls[1][3]
    query = server.calls[3][1]
    assert query.findtext(f".//{{{wire.VIM}}}maxObjects") == "250"
    assert {n.text for n in query.findall(f".//{{{wire.VIM}}}propSet/{{{wire.VIM}}}type")} == {"VirtualMachine", "HostSystem"}
    assert all(n.text == "false" for n in query.findall(f".//{{{wire.VIM}}}all"))
    # Resolve the xsi:type QName rather than merely checking its spelling.
    nsmap = dict(value for _, value in ET.iterparse(BytesIO(server.calls[3][3]), events=["start-ns"]))
    traversal = query.find(f".//{{{wire.VIM}}}selectSet").get(f"{{{wire.XSI}}}type")
    assert nsmap[traversal.split(":")[0]] == wire.VIM
    assert all("Cookie" not in c[2] for c in server.calls[:2])
    assert all(c[2]["Cookie"].startswith("vmware_soap_session=") for c in server.calls[2:])
    assert all(c.context.check_hostname and c.context.verify_mode == ssl.CERT_REQUIRED for c in server.connections)
    assert all(c.endpoint.address == "10.20.0.2" and c.endpoint.host == "vc.lab" for c in server.connections)
    assert all(0 < c.timeout <= wire.CALL_TIMEOUT for c in server.connections)


@pytest.mark.parametrize("url,address,trust,ca", [
    ("http://vc.lab/sdk", "10.20.0.2", "system", None),
    ("https://u:secret@vc.lab/sdk", "10.20.0.2", "system", None),
    ("https://vc.lab/sdk?token=secret", "10.20.0.2", "system", None),
    ("https://vc.lab/sdk#fragment", "10.20.0.2", "system", None),
    ("https://vc.lab/other", "10.20.0.2", "system", None),
    ("https://vc.lab:0/sdk", "10.20.0.2", "system", None),
    ("https://vc.lab:/sdk", "10.20.0.2", "system", None),
    ("https://999.1.1.1/sdk", "10.20.0.2", "system", None),
    ("https://vc.lab/sdk\r\nX:secret", "10.20.0.2", "system", None),
    ("https://vc.lab/sdk", "unreviewed.lab", "system", None),
    ("https://vc.lab/sdk", "0.0.0.0", "system", None),
    ("https://vc.lab/sdk", "ff02::1", "system", None),
    ("https://vc.lab/sdk", "fe80::1%12", "system", None),
    ("https://10.20.0.3/sdk", "10.20.0.2", "system", None),
    ("https://vc.lab/sdk", "10.20.0.2", None, None),
    ("https://vc.lab/sdk", "10.20.0.2", "insecure", None),
    ("https://vc.lab/sdk", "10.20.0.2", "ca_file", "relative.pem"),
])
def test_invalid_endpoint_and_trust_are_rejected_without_echo(url, address, trust, ca):
    with pytest.raises(wire.VsphereError, match="^vsphere:invalid_endpoint_or_trust$"):
        wire.Endpoint.parse(url, address, tls_trust=trust, ca_file=ca)


def test_ipv6_and_explicit_ca_validation(tmp_path):
    ep = wire.Endpoint.parse("https://[fd00::2]:8443/sdk", "fd00::2", tls_trust="system")
    assert ep.host == "fd00::2" and ep.port == 8443
    ca = tmp_path / "ca.pem"
    ca.write_text("invalid certificate fixture")
    ep = wire.Endpoint.parse("https://vc.lab/sdk", "10.20.0.2", tls_trust="ca_file", ca_file=str(ca))
    with pytest.raises(wire.VsphereError, match="invalid_tls_trust"):
        ep.tls_context()


@pytest.mark.parametrize("fault", [
    lambda: Response(b"password=session-secret", status=302, headers={"Location": "https://outside.lab/sdk"}),
    lambda: Response(b"password=session-secret", status=401),
    lambda: Response(b"password=session-secret", status=500),
    lambda: Response(b"bad", headers={"Content-Type": "text/xml", "Content-Encoding": "gzip"}),
    lambda: Response(b"bad", headers={"Content-Type": "text/html"}),
    lambda: Response(b"bad", headers={"Content-Type": "text/xml", "Content-Length": str(wire.MAX_BODY + 1)}),
    lambda: Response(b"x" * (wire.MAX_BODY + 1), headers={"Content-Type": "text/xml"}),
    lambda: Response(b"bad", headers={"Content-Type": "text/xml", "Content-Length": "12"}),
    lambda: Response(b"bad", headers={"Content-Type": "text/xml", "Content-Length": "3", "Transfer-Encoding": "chunked"}),
    lambda: Response(b"bad", headers={"Content-Type": "text/xml", "Transfer-Encoding": "invalid"}),
    lambda: Response(b'<!DOCTYPE x [<!ENTITY s SYSTEM "file:///secret">]><x>&s;</x>'),
    lambda: Response(b"<bad>session-secret"),
    lambda: Response(('<s:Envelope xmlns:s="' + wire.SOAP + '"><s:Body><s:Fault><faultstring>session-secret</faultstring></s:Fault></s:Body></s:Envelope>').encode()),
    lambda: OSError("password=session-secret"),
    lambda: ssl.SSLCertVerificationError("secret peer text"),
])
def test_remote_failures_are_bounded_redacted_and_do_not_follow_redirects(monkeypatch, fault):
    server = Server(monkeypatch)
    server.overrides["RetrieveServiceContent"] = fault()
    with pytest.raises(wire.VsphereError) as caught:
        read(server)
    assert "secret" not in str(caught.value) and "password" not in str(caught.value)
    assert server.methods == ["RetrieveServiceContent"]
    assert all(c.closed for c in server.connections)


@pytest.mark.parametrize("limit,value", [("PAGE_SIZE", 2), ("MAX_PAGES", 1), ("MAX_OBJECTS", 3), ("MAX_TOTAL_BODY", 10)])
def test_resource_limits_fail_without_returning_partial_inventory(monkeypatch, limit, value):
    server = Server(monkeypatch)
    monkeypatch.setattr(wire, limit, value)
    with pytest.raises(wire.VsphereError, match="limit"):
        read(server)
    if "Login" in server.methods:
        assert "Logout" in server.methods


def test_repeated_token_and_duplicate_object_conflict_fail_closed(monkeypatch):
    server = Server(monkeypatch)
    server.pages[1] = server.pages[1].replace(b"<returnval>", b"<returnval><token>page-two-fixture</token>")
    with pytest.raises(wire.VsphereError, match="repeated_page_token"):
        read(server)
    assert server.methods.count("ContinueRetrievePropertiesEx") == 1
    assert server.methods[-3:] == ["CancelRetrievePropertiesEx", "DestroyView", "Logout"]
    server = Server(monkeypatch)
    server.pages[1] = server.pages[0].replace(b"RetrievePropertiesExResponse", b"ContinueRetrievePropertiesExResponse").replace(
        b"<token>page-two-fixture</token>", b"").replace(b"build-box", b"renamed")
    with pytest.raises(wire.VsphereError, match="inconsistent_inventory"):
        read(server)


def test_same_object_repeated_on_pages_deduplicates(monkeypatch):
    server = Server(monkeypatch)
    server.pages[1] = server.pages[0].replace(b"RetrievePropertiesExResponse", b"ContinueRetrievePropertiesExResponse").replace(
        b"<token>page-two-fixture</token>", b"")
    assert len(read(server)[2]) == 3


def test_missing_property_fault_or_malformed_reference_refuses_partial_results(monkeypatch):
    for replacement in [b'<missingSet><path>name</path><fault>session-secret</fault></missingSet>', b'<propSet><name>unexpected</name><val>session-secret</val></propSet>']:
        server = Server(monkeypatch)
        server.pages[1] = server.pages[1].replace(b"</objects>", replacement + b"</objects>", 1)
        with pytest.raises(wire.VsphereError) as caught:
            read(server)
        assert "session-secret" not in str(caught.value)


def test_revocation_after_page_prevents_continuation_and_cleanup_io(monkeypatch):
    server = Server(monkeypatch)
    revoked = False

    def after(method):
        nonlocal revoked
        revoked = method == "RetrievePropertiesEx"

    def guard():
        if revoked:
            raise PermissionError("revoked")

    server.after = after
    with pytest.raises(PermissionError, match="revoked"):
        read(server, guard)
    assert server.methods[-1] == "RetrievePropertiesEx"
    assert all(c.closed for c in server.connections)


def test_cleanup_attempts_logout_after_view_failure_and_forgets_cookie(monkeypatch):
    server = Server(monkeypatch)
    server.overrides["DestroyView"] = OSError("secret")
    assert len(read(server)[2]) == 5
    assert server.methods[-1] == "Logout"


def test_total_deadline_is_checked_after_a_response(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(wire, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    server = Server(monkeypatch)
    server.after = lambda _: clock.__setitem__(0, 100.0)
    with pytest.raises(wire.VsphereError, match="deadline"):
        read(server)
    assert server.methods == ["RetrieveServiceContent"]


def test_fixed_client_does_not_expose_mutation_method(monkeypatch):
    server = Server(monkeypatch)
    with pytest.raises(wire.VsphereError, match="unsupported_method"):
        wire.InventoryClient(endpoint(), lambda: None)._call("PowerOnVM_Task", "VirtualMachine", "vm-101")
    assert not server.calls


def test_socket_pins_reviewed_ip_and_validates_endpoint_tls_name_without_dns(monkeypatch):
    events = []

    class Socket:
        def settimeout(self, value):
            events.append(("timeout", value))

        def connect(self, address):
            events.append(("connect", address))

        def do_handshake(self):
            events.append(("tls",))

        def close(self):
            pass

    context = ssl.create_default_context()
    monkeypatch.setattr(wire.socket, "socket", lambda *args: Socket())
    monkeypatch.setattr(wire.socket, "getaddrinfo", lambda *args: pytest.fail("No DNS resolution is permitted"))

    def wrap(sock, **kwargs):
        assert kwargs == {"server_hostname": "vc.lab", "do_handshake_on_connect": False}
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        return sock

    monkeypatch.setattr(context, "wrap_socket", wrap)
    connection = wire._Connection(endpoint(), 2, context, lambda: events.append(("guard",)))
    connection.connect()
    connection.close()
    assert events == [("guard",), ("timeout", 2), ("connect", ("10.20.0.2", 443)), ("guard",), ("tls",), ("guard",)]


def test_request_watchdog_interrupts_a_stalled_body(monkeypatch):
    server = Server(monkeypatch)
    interrupted = Event()
    monkeypatch.setattr(wire, "CALL_TIMEOUT", 0.02)
    monkeypatch.setattr(wire._Connection, "interrupt", lambda _: interrupted.set())
    response = Response(server.service)

    def stalled(_):
        assert interrupted.wait(2), "Request watchdog did not interrupt the read"
        return server.service

    response.read = stalled
    server.overrides["RetrieveServiceContent"] = response
    with pytest.raises(wire.VsphereError, match="deadline"):
        read(server)
    assert interrupted.is_set()
    assert all(c.closed for c in server.connections)


def test_expired_watchdog_cannot_open_a_late_socket(monkeypatch):
    connection = wire._Connection(endpoint(), 2, ssl.create_default_context(), lambda: None)
    connection.interrupt()
    monkeypatch.setattr(wire.socket, "socket", lambda *args: pytest.fail("Expired call opened a socket"))
    with pytest.raises(wire.VsphereError, match="deadline"):
        connection.connect()
