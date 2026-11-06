"""Ephemeral peers bound only to IPv4 loopback; no live target access."""
from __future__ import annotations

import contextlib
import ipaddress
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import paramiko
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@pytest.fixture(scope="session")
def ssh_keys():
    return paramiko.RSAKey.generate(2048), paramiko.RSAKey.generate(2048)


@pytest.fixture
def ssh_peer():
    @contextlib.contextmanager
    def start(key):
        stop, requested = threading.Event(), threading.Event()
        peer = SimpleNamespace(auth=[], commands=[], failures=[])
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(0.1)
        peer.port = listener.getsockname()[1]

        class Server(paramiko.ServerInterface):
            def check_auth_password(self, username, password):
                peer.auth.append((username, password))
                return paramiko.AUTH_SUCCESSFUL

            def check_auth_publickey(self, username, key):
                peer.auth.append((username, "publickey"))
                return paramiko.AUTH_SUCCESSFUL

            def check_channel_request(self, kind, chanid):
                return paramiko.OPEN_SUCCEEDED

            def check_channel_exec_request(self, channel, command):
                peer.commands.append(command)
                requested.set()
                return True

        def serve():
            remote = None
            try:
                while not stop.is_set():
                    try:
                        conn, _ = listener.accept()
                        break
                    except socket.timeout:
                        continue
                else:
                    return
                remote = paramiko.Transport(conn)
                remote.add_server_key(key)
                remote.start_server(server=Server())
                while not stop.is_set() and remote.is_active():
                    channel = remote.accept(0.1)
                    if channel is not None:
                        if requested.wait(3):
                            channel.sendall(b"loopback-ok\n")
                            channel.send_exit_status(0)
                        channel.close()
            except (EOFError, OSError, paramiko.SSHException):
                # Peer termination after a deliberate trust failure is expected.
                pass
            except Exception as exc:
                peer.failures.append(type(exc).__name__)
            finally:
                if remote is not None:
                    remote.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            yield peer
        finally:
            stop.set()
            listener.close()
            thread.join(4)
            assert not thread.is_alive(), "loopback SSH peer leaked"
            assert not peer.failures

    return start


@pytest.fixture(scope="session")
def certificates(tmp_path_factory):
    root = tmp_path_factory.mktemp("transport-certs")
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Loopback test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    ca_path = root / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    result = {"ca": str(ca_path)}
    for label in ("valid", "dns", "wrong_ip", "wrong_dns", "untrusted", "expired", "cn_only"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        builder = (x509.CertificateBuilder().subject_name(subject)
                   .issuer_name(subject if label == "untrusted" else ca_name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(days=2))
                   .not_valid_after(now - timedelta(days=1) if label == "expired" else now + timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                       key.public_key() if label == "untrusted" else ca_key.public_key()), critical=False))
        if label != "cn_only":
            sans = {"dns": [x509.DNSName("localhost")], "wrong_dns": [x509.DNSName("wrong.invalid")],
                    "wrong_ip": [x509.IPAddress(ipaddress.ip_address("127.0.0.2"))]}.get(
                        label, [x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")])
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        cert = builder.sign(key if label == "untrusted" else ca_key, hashes.SHA256())
        cert_path, key_path = root / f"{label}.pem", root / f"{label}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        result[label] = (str(cert_path), str(key_path))
    return result


@pytest.fixture
def tls_peer(certificates):
    @contextlib.contextmanager
    def start(kind="valid", *, redirect=False, tls=True):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append((self.path, self.headers.get("Authorization")))
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.send_response(302 if redirect else 200)
                if redirect:
                    self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/elsewhere")
                self.end_headers()
                self.wfile.write(b"loopback-ok")

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(*certificates[kind])
            server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()
        try:
            yield SimpleNamespace(port=server.server_port, requests=requests)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)
            assert not thread.is_alive(), "loopback TLS peer leaked"

    return start
