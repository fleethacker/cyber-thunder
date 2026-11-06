"""Read a selected private key through the shared native secret-file boundary."""
from __future__ import annotations

import base64
import getpass
import io
import re
import struct

import paramiko
from paramiko.auth_strategy import AuthStrategy

from .secret_resolver import MountedSecret, _path, _read_mounted


MAX_KEY_BYTES = 32 * 1024
_ENVELOPE = re.compile(
    rb"-{5}BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-{5}\r?\n"
    rb"([A-Za-z0-9+/=\r\n]+)-{5}END \1 PRIVATE KEY-{5}"
)


class SSHKeyError(PermissionError):
    """Fixed diagnostic with no filesystem, provider or private-key details."""


def _parse_private_key(raw):
    # Provider readers search for headers and can ignore subsequent keys/data.
    # Require one complete envelope and canonical base64 before parsing it.
    raw = raw.strip(b" \t\r\n")
    envelope = _ENVELOPE.fullmatch(raw)
    if envelope is None:
        raise ValueError
    label, body = envelope.groups()
    encoded = b"".join(body.splitlines())
    payload = base64.b64decode(encoded, validate=True)
    if base64.b64encode(payload) != encoded:
        raise ValueError
    if label == b"OPENSSH":
        from cryptography.hazmat.primitives.serialization import load_ssh_private_key

        # One unencrypted key, with no KDF options. The validating reader also
        # checks inner/public key agreement, padding and complete binary input.
        header = b"openssh-key-v1\0" + struct.pack(">I4sI4sII", 4, b"none", 4, b"none", 0, 1)
        if not payload.startswith(header):
            raise ValueError
        load_ssh_private_key(raw, password=None)
        kinds = (paramiko.RSAKey, paramiko.ECDSAKey, paramiko.Ed25519Key)
    else:
        kinds = ({b"RSA": paramiko.RSAKey, b"EC": paramiko.ECDSAKey,
                  b"DSA": getattr(paramiko, "DSSKey", None)}[label],)
    for kind in kinds:
        if kind is None:
            continue
        try:
            with io.StringIO(raw.decode("ascii")) as stream:
                key = kind.from_private_key(stream)
            if not key.can_sign():
                raise ValueError
            return key
        except (paramiko.SSHException, ValueError):
            continue
    raise ValueError


def _read_private_key(filename):
    path = _path(filename)
    source = MountedSecret(str(path.parent), path.name)
    return _parse_private_key(_read_mounted(source, private=True, maximum=MAX_KEY_BYTES))


def load_private_key(filename):
    """Parse only the checked, bounded snapshot; never let the SSH provider reopen it.

    The regular mounted-secret reader pins/checks ancestors and the open file,
    rejects links and foreign access, and revalidates before releasing bytes.
    No password, agent, adjacent certificate or alternate file is consulted.
    """
    # Keep secret-bearing frames below this boundary. Raising after the handler
    # drops parser exceptions and their frames rather than merely hiding them.
    key = None
    try:
        key = _read_private_key(filename)
    except Exception:
        # Provider/parser exceptions can contain input or local account details.
        # Raise outside their handler so they cannot survive as chained context.
        key = None
    if key is None:
        raise SSHKeyError("SSH private key is unavailable or unsafe") from None
    return key


class SelectedKeyAuth(AuthStrategy):
    """Exactly one public-key attempt; partial authentication fails closed."""

    def __init__(self, username, pkey):
        super().__init__(ssh_config=None)
        self.username = username if username is not None else getpass.getuser()
        self.pkey = pkey

    def authenticate(self, transport):
        try:
            transport.auth_publickey(self.username, self.pkey)
            if not transport.is_authenticated():
                raise paramiko.AuthenticationException("Selected SSH key did not complete authentication")
        finally:
            self.pkey = None
