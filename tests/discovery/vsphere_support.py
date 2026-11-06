"""Wire-level vSphere responses without sockets, subprocesses or external discovery."""
from email.message import Message
from io import BytesIO
from pathlib import Path
from xml.etree import ElementTree as ET

from cyberthunder.discovery.sources import vsphere_client as wire

FIX = Path(__file__).parents[1] / "fixtures" / "discovery" / "vsphere"
PASSWORD = "fixture-password-<&>-not-a-real-secret"
COOKIE = 'vmware_soap_session="session-fixture-only"; Path=/; Secure; HttpOnly'


def envelope(method, inner=""):
    return (f'<s:Envelope xmlns:s="{wire.SOAP}" xmlns="urn:vim25"><s:Body>'
            f'<{method}Response>{inner}</{method}Response></s:Body></s:Envelope>').encode()


class Response:
    def __init__(self, body, *, status=200, headers=None):
        self.status, self.body = status, BytesIO(body)
        self.headers = Message()
        for key, value in (headers or {"Content-Type": "text/xml", "Content-Length": str(len(body))}).items():
            self.headers[key] = value

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def read(self, count):
        return self.body.read(count)


class Server:
    def __init__(self, monkeypatch):
        self.calls, self.connections = [], []
        self.pages = [(FIX / "page1.xml").read_bytes(), (FIX / "page2.xml").read_bytes()]
        self.service = (FIX / "service.xml").read_bytes()
        self.overrides, self.after = {}, None
        server = self

        class Connection:
            def __init__(self, endpoint, timeout, context, guard):
                self.endpoint, self.timeout, self.context, self.guard = endpoint, timeout, context, guard
                self.closed = False
                server.connections.append(self)

            def connect(self):
                self.guard()

            def request(self, method, path, payload, headers):
                assert method == "POST" and path == "/sdk"
                self.xml = ET.fromstring(payload).find(f"{{{wire.SOAP}}}Body")[0]
                self.method = self.xml.tag.split("}")[-1]
                server.calls.append((self.method, self.xml, headers, payload))

            def getresponse(self):
                response = server.response(self.method)
                if server.after:
                    server.after(self.method)
                return response

            def close(self):
                self.closed = True

            def interrupt(self):
                self.closed = True

        monkeypatch.setattr(wire, "_Connection", Connection)

    def response(self, method):
        if method in self.overrides:
            value = self.overrides[method]
            if isinstance(value, Exception):
                raise value
            return value() if callable(value) else value
        if method == "RetrieveServiceContent":
            return Response(self.service)
        if method == "Login":
            response = Response(envelope(method, "<returnval><key>session-fixture-only</key></returnval>"))
            response.headers["Set-Cookie"] = COOKIE
            return response
        if method == "CreateContainerView":
            return Response(envelope(method, '<returnval type="ContainerView">view-1</returnval>'))
        if method in {"RetrievePropertiesEx", "ContinueRetrievePropertiesEx"}:
            return Response(self.pages.pop(0))
        assert method in {"DestroyView", "Logout", "CancelRetrievePropertiesEx"}, method
        return Response(envelope(method))

    @property
    def methods(self):
        return [c[0] for c in self.calls]


def endpoint():
    return wire.Endpoint.parse("https://vc.lab/sdk", "10.20.0.2", tls_trust="system")
