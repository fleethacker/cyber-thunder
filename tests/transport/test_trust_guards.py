from types import SimpleNamespace

import pytest

from cyberthunder.transport.base import CommandResult, TransportError
from cyberthunder.transport.ssh import SSHTransport
from cyberthunder.transport.trust import GuardedShell, TrustError
from cyberthunder.transport.winrm import WinRMTransport


@pytest.mark.parametrize("transport", [SSHTransport, WinRMTransport])
def test_check_output_errors_do_not_include_command_or_remote_streams(transport, monkeypatch):
    tr = transport("localhost")
    monkeypatch.setattr(tr, "run", lambda *a, **kw: CommandResult("secret argv", 1, "secret stdout", "secret stderr"))
    with pytest.raises(TransportError) as error:
        tr.check_output("secret argv")
    assert str(error.value) == "Remote command returned a nonzero status"


@pytest.mark.parametrize("transport", [SSHTransport, WinRMTransport])
@pytest.mark.parametrize("mode", ["Fleet", "invalid", "", False, None])
def test_invalid_mode_fails_closed(transport, mode):
    with pytest.raises(TrustError, match="range or fleet"):
        transport("localhost", security_mode=mode)


def test_shell_rechecks_guard_on_each_io_and_allows_cleanup():
    calls = []
    blocked = False

    def guard():
        if blocked:
            raise PermissionError("scope revoked")

    raw = SimpleNamespace(send=lambda data: calls.append(data), recv=lambda count: b"data",
                          close=lambda: calls.append("closed"), closed=False)
    shell = GuardedShell(raw, guard)
    shell.send("read")
    assert shell.recv(4) == b"data" and shell.closed is False
    blocked = True
    with pytest.raises(PermissionError):
        shell.send("must-not-send")
    with pytest.raises(PermissionError):
        shell.recv(4)
    shell.close()
    assert calls == ["read", "closed"]
