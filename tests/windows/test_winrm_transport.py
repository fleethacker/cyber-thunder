import base64

import pytest


class FakeResponse:
    def __init__(self, out=b"", err=b"", code=0):
        self.std_out, self.std_err, self.status_code = out, err, code


class FakeSession:
    """Stands in for winrm.Session: records calls, never touches the network."""
    def __init__(self, files=None):
        self.cmd_calls, self.ps_calls = [], []
        self.files = files or {}

    def run_cmd(self, command, args=()):
        self.cmd_calls.append((command, list(args)))
        return FakeResponse("résumé ok\n".encode("utf-8") + b"\xff", b"", 0)

    def run_ps(self, script):
        self.ps_calls.append(script)
        if "ReadAllBytes" in script:
            if "missing" in self._path(script):
                return FakeResponse(b"", b"not found", 2)
            return FakeResponse(base64.b64encode(self.files[self._path(script)]) + b"\r\n")
        return FakeResponse(b"", b"", 0)

    @staticmethod
    def _path(script):
        b64 = script.split("FromBase64String('")[1].split("'")[0]
        return base64.b64decode(b64).decode("utf-8")


def make(session, **kw):
    from cyberthunder.transport.winrm import WinRMTransport
    return WinRMTransport("10.0.0.5", username="itadmin", password="x", session=session, **kw)


def test_encoded_command_is_not_double_wrapped(state_dir):
    from cyberthunder.adapters.windows.scripts import command_for
    s = FakeSession()
    t = make(s)
    r = t.run(command_for("# cyberthunder-script: facts\nGet-Date\n"))
    assert r.ok and not s.ps_calls
    exe, args = s.cmd_calls[0]
    assert exe == "powershell"
    assert args[:3] == ["-NoProfile", "-NonInteractive", "-EncodedCommand"]
    assert base64.b64decode(args[3]).decode("utf-16-le").startswith("# cyberthunder-script: facts")
    assert "résumé ok" in r.stdout and "\ufffd" in r.stdout      # utf-8 decoded, bad bytes replaced


def test_plain_command_goes_through_run_ps(state_dir):
    s = FakeSession()
    make(s).run("Get-Service WinRM")
    assert s.ps_calls == ["Get-Service WinRM"] and not s.cmd_calls


def test_read_file_decodes_base64_and_quotes_nothing(state_dir):
    path = r"C:\Program Files\it's here\out.cklb"
    s = FakeSession({path: b"\x00\x01data"})
    t = make(s)
    assert t.read_file(path) == b"\x00\x01data"
    assert path not in s.ps_calls[0]                     # path travels as base64 only
    from cyberthunder.transport.base import TransportError
    with pytest.raises(TransportError):
        t.read_file(r"C:\missing.txt")


def test_write_file_is_chunked(state_dir):
    from cyberthunder.transport import winrm
    s = FakeSession()
    data = bytes(range(256)) * 60                     # 15360 bytes -> 3 chunks
    make(s).write_file(r"C:\Windows\Temp\x.bin", data)
    assert len(s.ps_calls) == 3
    assert "FileMode]::Create" in s.ps_calls[0] and all("FileMode]::Append" in c for c in s.ps_calls[1:])
    chunks = [base64.b64decode(c.split("$b = [Convert]::FromBase64String('")[1].split("'")[0]) for c in s.ps_calls]
    assert b"".join(chunks) == data and max(map(len, chunks)) <= winrm.WRITE_CHUNK


def test_from_target_reads_password_from_env(state_dir, monkeypatch):
    from cyberthunder.inventory.targets import Target
    from cyberthunder.transport.base import TransportError
    from cyberthunder.transport.winrm import WinRMTransport
    tgt = Target(id="ws-02", name="ws-02", asset_type="windows", transport="winrm", address="10.0.0.6",
                 port=5986, username="itadmin", credential_ref="WS02", options={"transport": "ntlm", "cert_validation": "ignore"})
    monkeypatch.delenv("CT_CRED_WS02", raising=False)
    with pytest.raises(TransportError):
        WinRMTransport.from_target(tgt)
    monkeypatch.setenv("CT_CRED_WS02", "range-test-value")
    t = WinRMTransport.from_target(tgt)
    assert t.endpoint == "https://10.0.0.6:5986/wsman" and t.auth == "ntlm" and t.cert_validation == "ignore"
    assert "range-test-value" not in repr(tgt.to_dict())
    plain = Target(id="ws-03", name="ws-03", asset_type="windows", transport="winrm", address="h",
                   options={"transport": "kerberos"})
    assert WinRMTransport.from_target(plain).endpoint == "http://h:5985/wsman"


def test_unknown_auth_rejected(state_dir):
    from cyberthunder.transport.base import TransportError
    from cyberthunder.transport.winrm import WinRMTransport
    with pytest.raises(TransportError):
        WinRMTransport("h", auth="digest")


def test_adapter_runs_over_fake_winrm(state_dir, monkeypatch, tmp_path):
    """The adapter's live path over WinRM, with the session answered by the simulated host."""
    monkeypatch.setenv("CT_STATE_DIR", str(state_dir))
    from cyberthunder.adapters.windows.adapter import WindowsAdapter
    from cyberthunder.adapters.windows.simhost import SimulatedWindowsHost

    sim = SimulatedWindowsHost(tmp_path / "sim.json")
    sim.reset()

    class SimSession(FakeSession):
        def run_cmd(self, command, args=()):
            r = sim.run(" ".join([command, *args]))
            return FakeResponse(r.stdout.encode("utf-8"), r.stderr.encode("utf-8"), r.exit_code)

    a = WindowsAdapter()
    target = a.demo_targets()[0]
    col = a.collect(target, make(SimSession()), tmp_path / "w")
    assert not col.errors
    assert any(f.rule_version == "WN11-SO-000010" and f.is_open for f in a.run_detection(target, col))
