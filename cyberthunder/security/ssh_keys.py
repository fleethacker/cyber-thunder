"""Read a selected private key through the shared native secret-file boundary."""
from __future__ import annotations

import io

from .secret_resolver import MountedSecret, _path, _read_mounted


MAX_KEY_BYTES = 32 * 1024


class SSHKeyError(PermissionError):
    """Fixed diagnostic with no filesystem, provider or private-key details."""


def load_private_key(filename):
    """Parse only the checked, bounded snapshot; never let the SSH provider reopen it.

    The regular mounted-secret reader pins/checks ancestors and the open file,
    rejects links and foreign access, and revalidates before releasing bytes.
    No password, agent, adjacent certificate or alternate file is consulted.
    """
    import paramiko

    key = None
    try:
        path = _path(filename)
        source = MountedSecret(str(path.parent), path.name)
        raw = _read_mounted(source, private=True, maximum=MAX_KEY_BYTES)
        text = raw.decode("ascii")
        for kind in (paramiko.RSAKey, paramiko.ECDSAKey, paramiko.Ed25519Key,
                     getattr(paramiko, "DSSKey", None)):
            if kind is None:
                continue
            try:
                with io.StringIO(text) as stream:
                    candidate = kind.from_private_key(stream)
                if not candidate.can_sign():
                    raise ValueError
                key = candidate
                break
            except paramiko.PasswordRequiredException:
                # Encrypted files need a separate, explicit passphrase design.
                raise
            except (paramiko.SSHException, ValueError):
                continue
    except Exception:
        # Provider/parser exceptions can contain input or local account details.
        # Raise outside their handler so they cannot survive as chained context.
        key = None
    if key is None:
        raise SSHKeyError("SSH private key is unavailable or unsafe") from None
    return key
