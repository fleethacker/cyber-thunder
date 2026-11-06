from __future__ import annotations

import traceback
from types import SimpleNamespace

import pytest
import winrm

from cyberthunder.inventory.targets import Target
from cyberthunder.transport.base import TransportError
from cyberthunder.transport.trust import TrustError
from cyberthunder.transport.winrm import WRITE_CHUNK, WinRMTransport


def fleet(certificates, **overrides):
    options = dict(username="loopback-user", password="loopback-secret", security_mode="fleet", auth="ntlm",
                   ca_trust_path=certificates["ca"], operation_timeout_s=1, read_timeout_s=2)
    options.update(overrides)
    return WinRMTransport(options.pop("host", "127.0.0.1"), **options)


@pytest.mark.parametrize("overrides,code", [
    ({"port": 5985}, "transport:https_required"),
    ({"port": 5985, "ssl": True}, "transport:https_required"),
    ({"ssl": False}, "transport:https_required"),
    ({"cert_validation": "ignore"}, "transport:certificate_required"),
    ({"auth": "basic"}, "transport:auth_refused"),
    ({"auth": "credssp"}, "transport:auth_refused"),
    ({"ca_trust_path": None}, "transport:ca_required"),
    ({"ca_trust_path": "legacy_requests"}, "transport:invalid_trust_file"),
])
def test_fleet_rejects_unsafe_options_before_session(certificates, monkeypatch, overrides, code):
    monkeypatch.setattr(winrm, "Session", lambda *a, **kw: pytest.fail("unsafe session constructed"))
    with pytest.raises(TrustError) as error:
        fleet(certificates, allow_insecure_range=True, **overrides)
    assert error.value.code == code


@pytest.mark.parametrize("kind", ["missing", "directory", "malformed", "leaf"])
def test_fleet_requires_ca_material(certificates, tmp_path, kind):
    path = tmp_path / "bad.pem"
    if kind == "directory":
        path.mkdir()
    elif kind == "malformed":
        path.write_text("not a CA; secret fixture text")
    elif kind == "leaf":
        path = certificates["valid"][0]
    with pytest.raises(TrustError) as error:
        fleet(certificates, ca_trust_path=str(path))
    assert "secret fixture" not in str(error.value)


def test_fleet_defaults_to_https_kerberos_without_downgrade(certificates, monkeypatch):
    target = Target("t", "t", "windows", transport="winrm", address="localhost",
                    options={"ca_trust_path": certificates["ca"], "security_mode": "range"})
    tr = WinRMTransport.from_target(target, SimpleNamespace(security_mode="fleet"))
    assert tr.auth == "kerberos" and tr.endpoint == "https://localhost:5986/wsman"
    assert tr.cert_validation == "validate" and tr._password is None
    target.credential_ref = "LOOPBACK"
    monkeypatch.setenv("CT_CRED_LOOPBACK", "fixture-password")
    legacy = WinRMTransport.from_target(target, SimpleNamespace())
    assert legacy.auth == "ntlm" and legacy.endpoint == "http://localhost:5985/wsman"


@pytest.mark.parametrize("host,kind", [("127.0.0.1", "valid"), ("localhost", "dns"), ("LOCALHOST", "dns")])
def test_real_tls_with_exact_ca_and_name_ignores_environment(certificates, tls_peer, monkeypatch, host, kind):
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", certificates["untrusted"][0])
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NETRC", "nonexistent-secret-netrc")
    with tls_peer(kind) as peer, fleet(certificates, host=host, port=peer.port, ssl=True) as tr:
        protocol = tr._sess().protocol
        assert protocol.transport.send_message("loopback request") == b"loopback-ok"
        assert peer.requests == [("/wsman", None)]
        http = protocol.transport.session
        assert http.trust_env is False and http.proxies == {} and http.verify == tr.ca_trust_path
        assert tr.security_events == []


@pytest.mark.parametrize("host,kind", [("127.0.0.1", "untrusted"), ("127.0.0.1", "wrong_ip"),
                                      ("localhost", "wrong_dns"), ("127.0.0.1", "expired"),
                                      ("localhost", "cn_only"), ("127.0.0.1", "dns")])
def test_real_tls_failure_prevents_http_and_credentials(certificates, tls_peer, host, kind, caplog):
    events = []
    with tls_peer(kind) as peer, fleet(certificates, host=host, port=peer.port, ssl=True,
                                     on_security_event=events.append) as tr:
        with pytest.raises(TrustError, match="TLS trust or handshake failed") as error:
            tr.run("must-never-run")
        assert error.value.code == "transport:tls_failed"
        assert peer.requests == []
        assert len(events) == 1 and events[0].severity == "high"
        assert "loopback-secret" not in str(error.value) + caplog.text + repr(events)


def test_authenticated_session_refuses_redirects(certificates, tls_peer):
    with tls_peer(redirect=True) as peer, fleet(certificates, port=peer.port, ssl=True) as tr:
        with pytest.raises(TrustError, match="redirects are refused"):
            tr.run("must-not-redirect")
        assert len(peer.requests) == 1 and peer.requests[0][0] == "/wsman"


def test_session_cannot_be_reused_for_other_endpoint(certificates):
    with fleet(certificates) as tr:
        session = tr._sess().protocol.transport.session
        with pytest.raises(TrustError, match="configured HTTPS endpoint"):
            session.post("http://127.0.0.1:1/wsman", data=b"must-not-send")


def test_direct_protocol_failure_also_emits_tls_event(certificates, tls_peer):
    with tls_peer("untrusted") as peer, fleet(certificates, port=peer.port, ssl=True) as tr:
        with pytest.raises(TrustError, match="TLS trust or handshake failed"):
            tr._sess().protocol.transport.send_message("must-not-send")
        assert peer.requests == []
        assert [event.code for event in tr.security_events] == ["transport:tls_failed"]


def test_fleet_refuses_injected_session(certificates):
    with pytest.raises(TrustError, match="construct its own trusted session"):
        fleet(certificates, session=object())


@pytest.mark.parametrize("options,code", [({}, "transport:winrm_http"),
                                        ({"ssl": True, "cert_validation": "ignore"}, "transport:winrm_cert_unverified"),
                                        ({"ssl": True, "auth": "basic"}, "transport:winrm_legacy_auth"),
                                        ({"ssl": True, "auth": "credssp"}, "transport:winrm_legacy_auth")])
def test_range_exceptions_require_explicit_ack_and_are_visible(options, code, caplog):
    calls = []
    response = SimpleNamespace(status_code=0, std_out=b"ok", std_err=b"")
    session = SimpleNamespace(run_ps=lambda command: calls.append(command) or response)
    with pytest.raises(TrustError, match="allow_insecure_range"):
        WinRMTransport("localhost", session=session, **options).run("blocked")
    assert calls == []
    tr = WinRMTransport("localhost", session=session, allow_insecure_range=True, **options)
    assert tr.run("allowed").ok and calls == ["allowed"]
    assert any(event.code == code and event.verified is False for event in tr.security_events)
    assert code in caplog.text


@pytest.mark.parametrize("operation", ["run", "read_file", "write_file", "fetch"])
def test_guard_blocks_every_operation_with_cached_session(operation, tmp_path):
    class Revoked(RuntimeError):
        pass

    def guard():
        raise Revoked("scope revoked")

    tr = WinRMTransport("localhost", session=object(), allow_insecure_range=True, guard=guard)
    args = {"run": ("read",), "read_file": ("path",), "write_file": ("path", b"x"),
            "fetch": ("path", str(tmp_path / "out"))}
    with pytest.raises(Revoked):
        getattr(tr, operation)(*args[operation])


def test_guard_revocation_stops_subsequent_file_chunks():
    calls = []

    def guard():
        if calls:
            raise PermissionError("revoked")

    response = SimpleNamespace(status_code=0, std_out=b"", std_err=b"")
    session = SimpleNamespace(run_ps=lambda command: calls.append(command) or response)
    tr = WinRMTransport("localhost", session=session, allow_insecure_range=True, guard=guard)
    with pytest.raises(PermissionError):
        tr.write_file("path", b"x" * (WRITE_CHUNK * 2 + 1))
    assert len(calls) == 1


def test_kerberos_unavailable_does_not_fallback(certificates, monkeypatch):
    import winrm.transport
    monkeypatch.setattr(winrm.transport, "HAVE_KERBEROS", False)
    with fleet(certificates, auth="kerberos") as tr:
        with pytest.raises(TransportError, match="authentication support"):
            tr.run("blocked")
        assert tr.auth == "kerberos" and tr._session is None


def test_transport_error_is_sanitized():
    def fail(command):
        raise RuntimeError("private-password Authorization body")

    tr = WinRMTransport("localhost", session=SimpleNamespace(run_ps=fail), allow_insecure_range=True)
    with pytest.raises(TransportError) as error:
        tr.run("secret command")
    formatted = "".join(traceback.format_exception(error.type, error.value, error.tb))
    assert "private-password Authorization body" not in formatted
    assert error.value.__cause__ is None and error.value.__suppress_context__
    assert str(error.value) == "WinRM command failed"


def test_failed_event_sink_cannot_be_bypassed_by_retry():
    attempts = []

    def unavailable(event):
        attempts.append(event)
        raise RuntimeError("sink unavailable with private details")

    tr = WinRMTransport("localhost", allow_insecure_range=True, session=object(), on_security_event=unavailable)
    for _ in range(2):
        with pytest.raises(TrustError, match="could not be recorded"):
            tr.run("blocked")
    assert len(attempts) == 2 and not tr.security_events


@pytest.mark.parametrize("tls", [False, True])
def test_real_range_exception_is_visible_for_http_or_untrusted_tls(tls_peer, tls):
    with tls_peer("untrusted", tls=tls) as peer:
        with WinRMTransport("127.0.0.1", port=peer.port, ssl=tls, auth="basic", username="loopback-user",
                            password="fixture-secret", cert_validation="ignore", allow_insecure_range=True) as tr:
            assert tr._sess().protocol.transport.send_message("loopback request") == b"loopback-ok"
            assert len(peer.requests) == 1
            codes = {event.code for event in tr.security_events}
            assert "transport:winrm_legacy_auth" in codes
            assert ("transport:winrm_cert_unverified" if tls else "transport:winrm_http") in codes
            assert not any(event.verified for event in tr.security_events)


@pytest.mark.parametrize("options", [{"ssl": "false"}, {"allow_insecure_range": "false"},
                                     {"cert_validation": "anything"}, {"auth": "ssl"}])
def test_non_boolean_or_unknown_options_rejected(options):
    with pytest.raises(TransportError):
        WinRMTransport("localhost", **options)


@pytest.mark.parametrize("host", ["https://localhost", "u:p@localhost", "localhost/a", "localhost?x", "[::1]",
                                  "localhost\r\nAuthorization: value", "localhost:5986", "127.0.0.1.evil/anything"])
def test_endpoint_cannot_inject_url_components(host):
    with pytest.raises(TrustError, match="DNS name or IP literal"):
        WinRMTransport(host)
