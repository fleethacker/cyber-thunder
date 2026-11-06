"""Disposable SSH credentials and loopback-only networking for focused validation."""
from contextlib import contextmanager
import ipaddress
import socket
import threading
from types import SimpleNamespace

import paramiko
import pytest


def generated_key_material(algorithm):
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    if algorithm.startswith("rsa"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif algorithm.startswith("ecdsa"):
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = ed25519.Ed25519PrivateKey.generate()
    form = ser.PrivateFormat.TraditionalOpenSSL if algorithm.endswith("pem") else ser.PrivateFormat.OpenSSH
    return (key.private_bytes(ser.Encoding.PEM, form, ser.NoEncryption()),
            key.public_key().public_bytes(ser.Encoding.OpenSSH, ser.PublicFormat.OpenSSH))


@pytest.fixture(autouse=True)
def loopback_network_only(monkeypatch):
    connect, connect_ex, resolve = socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo

    def allowed(address):
        if not isinstance(address, tuple):
            return  # Native local sockets have no public endpoint.
        host = address[0]
        assert host == "localhost" or ipaddress.ip_address(host).is_loopback, "public network blocked"

    def checked_connect(sock, address):
        allowed(address)
        return connect(sock, address)

    def checked_connect_ex(sock, address):
        allowed(address)
        return connect_ex(sock, address)

    def checked_resolve(host, *args, **kwargs):
        allowed((host,))
        return resolve(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", checked_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", checked_connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", checked_resolve)


@pytest.fixture(scope="session")
def generated_ssh_keys():
    return paramiko.RSAKey.generate(2048), paramiko.RSAKey.generate(2048)


@pytest.fixture
def private_key_file(tmp_path, generated_ssh_keys):
    path = tmp_path / "selected_key"
    generated_ssh_keys[0].write_private_key_file(str(path))
    path.chmod(0o600)
    return path


@pytest.fixture
def publickey_peer(generated_ssh_keys):
    @contextmanager
    def start(*, username="reader", accepted=None, partial=False, auth_delay=0):
        stop = threading.Event()
        peer = SimpleNamespace(auth=[], interactive=[], commands=[], failures=[])
        accepted = accepted or generated_ssh_keys[0]
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(0.1)
        peer.port = listener.getsockname()[1]

        class Server(paramiko.ServerInterface):
            def get_allowed_auths(self, user):
                return "publickey,keyboard-interactive" if partial else "publickey"

            def check_auth_publickey(self, user, key):
                peer.auth.append((user, key.asbytes()))
                stop.wait(auth_delay)
                success = paramiko.AUTH_PARTIALLY_SUCCESSFUL if partial else paramiko.AUTH_SUCCESSFUL
                return (success if user == username and key.asbytes() == accepted.asbytes()
                        else paramiko.AUTH_FAILED)

            def check_auth_interactive(self, user, submethods):
                peer.interactive.append(user)
                return paramiko.AUTH_SUCCESSFUL

            def check_channel_request(self, kind, chanid):
                return paramiko.OPEN_SUCCEEDED

            def check_channel_exec_request(self, channel, command):
                peer.commands.append(command)
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
                remote.add_server_key(generated_ssh_keys[1])
                remote.start_server(server=Server())
                while not stop.wait(0.01) and remote.is_active():
                    channel = remote.accept(0.1)
                    if channel is not None:
                        while not peer.commands and not stop.wait(0.01):
                            pass
                        if peer.commands:
                            channel.sendall(b"isolated-key-ok\n")
                            channel.send_exit_status(0)
                        channel.close()
            except (EOFError, OSError, paramiko.SSHException):
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
            assert not thread.is_alive()
            assert not peer.failures

    return start
