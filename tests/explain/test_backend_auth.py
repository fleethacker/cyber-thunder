"""Optional backend authentication: mocked transport only, with no sockets opened."""
import http.client
import io
import json
import urllib.error
import urllib.response
from email.message import Message
from types import SimpleNamespace

import pytest

from cyberthunder.explain import backends
from cyberthunder.explain.backends import OllamaBackend, OpenAICompatBackend


KEY = "test-credential-alpha"
NEXT_KEY = "test-credential-beta"
MODEL_LIST = {"data": [{"id": "local"}]}
COMPLETION = {"choices": [{"message": {"content": '{"ok": true}'}}]}


@pytest.fixture
def transport(monkeypatch):
    """Intercept both paths while retaining the real request and JSON handling."""
    calls = []
    responses = []

    def send(req, timeout=None):
        calls.append(req)
        result = responses.pop(0)
        if callable(result):
            result = result(req)
        if isinstance(result, Exception):
            raise result
        return io.BytesIO(json.dumps(result).encode())

    def opener(*handlers):
        assert len(handlers) == 1 and isinstance(handlers[0], backends._RefuseRedirects)
        return SimpleNamespace(open=send)

    monkeypatch.setattr(backends.urllib.request, "urlopen", send)
    monkeypatch.setattr(backends.urllib.request, "build_opener", opener)
    return SimpleNamespace(calls=calls, responses=responses)


def backend():
    return OpenAICompatBackend("http://127.0.0.1:1234", "local")


def hostile_error(code=401):
    reflected = f"Authorization: Bearer {KEY}"
    return urllib.error.HTTPError(
        f"http://127.0.0.1/{KEY}", code, reflected,
        {"Authorization": reflected}, io.BytesIO(reflected.encode()),
    )


@pytest.mark.parametrize("value", [None, "", " \t\r\n "])
def test_absent_or_blank_key_preserves_local_requests(monkeypatch, transport, value):
    if value is not None:
        monkeypatch.setenv("CT_LLM_API_KEY", value)
    transport.responses.extend([MODEL_LIST, COMPLETION])
    b = backend()
    assert b.available()[0]
    assert b.available()[0]  # Unauthenticated probes retain the existing cache.
    assert b.generate("prompt", timeout=1) == '{"ok": true}'
    assert len(transport.calls) == 2
    assert all(req.get_header("Authorization") is None for req in transport.calls)


def test_probe_and_generate_send_key_only_in_header(monkeypatch, transport):
    b = backend()  # Configuration does not snapshot the credential.
    monkeypatch.setenv("CT_LLM_API_KEY", f"  {KEY}  ")
    transport.responses.extend([MODEL_LIST, COMPLETION])
    assert b.available()[0]
    assert b.generate("prompt", timeout=1) == '{"ok": true}'
    assert [(r.get_method(), r.full_url) for r in transport.calls] == [
        ("GET", "http://127.0.0.1:1234/v1/models"),
        ("POST", "http://127.0.0.1:1234/v1/chat/completions"),
    ]
    for req in transport.calls:
        assert req.get_header("Authorization") == f"Bearer {KEY}"
        assert req.get_header("Content-type") == "application/json"
        assert req.get_header("Accept") == "application/json"
        assert KEY not in req.full_url
        assert KEY not in (req.data or b"").decode()
        assert "Authorization" not in (req.data or b"").decode()
    assert KEY not in repr(vars(b))
    assert json.loads(transport.calls[1].data)["messages"] == [{"role": "user", "content": "prompt"}]


@pytest.mark.parametrize("code", [400, 422])
def test_json_fallback_reads_current_key_for_each_attempt(monkeypatch, transport, code):
    monkeypatch.setenv("CT_LLM_API_KEY", KEY)

    def reject_format(req):
        monkeypatch.setenv("CT_LLM_API_KEY", NEXT_KEY)
        return hostile_error(code)

    transport.responses.extend([reject_format, COMPLETION])
    b = backend()
    assert b.generate("prompt", timeout=1) == '{"ok": true}'
    assert [r.get_header("Authorization") for r in transport.calls] == [f"Bearer {KEY}", f"Bearer {NEXT_KEY}"]
    first, second = [json.loads(r.data) for r in transport.calls]
    assert first.pop("response_format") == {"type": "json_object"}
    assert first == second
    assert b.json_mode_supported is False


def test_runtime_rotation_and_removal_affect_subsequent_requests(monkeypatch, transport):
    b = backend()
    for key in (None, KEY, NEXT_KEY, None):
        if key:
            monkeypatch.setenv("CT_LLM_API_KEY", key)
        else:
            monkeypatch.delenv("CT_LLM_API_KEY", raising=False)
        transport.responses.extend([MODEL_LIST, COMPLETION])
        assert b.available()[0]
        assert b.generate("prompt", timeout=1)
    assert [r.get_header("Authorization") for r in transport.calls] == [
        None, None, f"Bearer {KEY}", f"Bearer {KEY}", f"Bearer {NEXT_KEY}", f"Bearer {NEXT_KEY}", None, None,
    ]


@pytest.mark.parametrize("code", [401, 403])
def test_revocation_and_recovery_bypass_availability_cache(monkeypatch, transport, code):
    monkeypatch.setenv("CT_LLM_API_KEY", KEY)
    transport.responses.extend([MODEL_LIST, hostile_error(code), MODEL_LIST])
    b = backend()
    assert b.available()[0]
    ok, detail = b.available()
    assert not ok and "authentication failed" in detail
    monkeypatch.setenv("CT_LLM_API_KEY", NEXT_KEY)
    assert b.available()[0]
    assert len(transport.calls) == 3
    assert KEY not in detail and "Authorization" not in detail


@pytest.mark.parametrize("code", [401, 403])
@pytest.mark.parametrize("fallback", [False, True])
def test_auth_failure_returns_none_without_retry_or_secret_logs(monkeypatch, transport, caplog, code, fallback):
    monkeypatch.setenv("CT_LLM_API_KEY", KEY)
    if fallback:
        transport.responses.append(hostile_error(400))
    transport.responses.append(hostile_error(code))
    b = backend()
    assert b.generate("prompt", timeout=1) is None
    assert len(transport.calls) == (2 if fallback else 1)
    assert b.json_mode_supported is not fallback
    assert "authentication failed" in caplog.text
    assert KEY not in caplog.text and "Authorization" not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.parametrize("kind", ["http", "url", "os", "value", "protocol"])
def test_untrusted_exception_text_never_reaches_status_or_logs(monkeypatch, transport, caplog, kind):
    monkeypatch.setenv("CT_LLM_API_KEY", KEY)
    reflected = f"Authorization: Bearer {KEY}"
    errors = {
        "http": lambda: hostile_error(500),
        "url": lambda: urllib.error.URLError(reflected),
        "os": lambda: OSError(reflected),
        "value": lambda: ValueError(reflected),
        "protocol": lambda: http.client.BadStatusLine(reflected),
    }
    transport.responses.extend([errors[kind](), errors[kind]()])
    b = backend()
    ok, detail = b.available()
    assert not ok
    assert b.generate("prompt", timeout=1) is None
    assert KEY not in detail + caplog.text
    assert "Authorization" not in detail + caplog.text


def test_model_list_does_not_echo_remote_diagnostics(transport):
    transport.responses.append({"data": [{"id": f"Authorization: Bearer {KEY}"}]})
    ok, detail = backend().available()
    assert not ok
    assert KEY not in detail and "Authorization" not in detail


@pytest.mark.parametrize("payload", [
    {"error": f"Authorization: Bearer {KEY}"},
    {"data": f"Authorization: Bearer {KEY}"},
])
def test_invalid_probe_payload_is_not_healthy_or_echoed(transport, payload):
    transport.responses.append(payload)
    ok, detail = backend().available()
    assert not ok
    assert KEY not in detail and "Authorization" not in detail


def test_reflected_credentials_are_rejected_before_explanation_persistence(monkeypatch, transport, caplog):
    monkeypatch.setenv("CT_LLM_API_KEY", KEY)
    transport.responses.extend([
        {"data": [{"id": KEY}]},
        {"choices": [{"message": {"content": f"Authorization: Bearer {KEY}"}}]},
    ])
    b = backend()
    ok, detail = b.available()
    assert not ok
    assert b.generate("prompt", timeout=1) is None
    assert KEY not in detail + caplog.text and "Authorization" not in detail + caplog.text


@pytest.mark.parametrize("wrapper", ["{}", "```json\n{}\n```", "Explanation follows:\n{}\nEnd."])
def test_encoded_completion_credentials_never_reach_saved_explanation(
    monkeypatch, transport, state_dir, caplog, wrapper,
):
    from cyberthunder.explain.validator import validate
    from tests.explain.helpers import canned, make_ctx, ssh_root_finding

    monkeypatch.setenv("CT_LLM_API_KEY", KEY)
    finding = ssh_root_finding()
    content = json.dumps(dict(json.loads(canned("valid")), risk=KEY)).replace(KEY, r"\u0074est-credential-alpha")
    content = wrapper.format(content)
    assert KEY not in content
    # This is otherwise valid text that the normal validator would decode and save.
    validated, _ = validate(content, finding)
    assert validated is not None and validated["risk"] == KEY
    response = {"choices": [{"message": {"content": content}}]}
    transport.responses.extend([MODEL_LIST, response, response])
    ctx = make_ctx(state_dir)
    ctx.explain.backend = backend()
    result = ctx.explain.explain(finding)
    assert result.fallback and result.attempts == 2
    assert ctx.explain.get(finding.id).fallback
    serialized = json.dumps([result.to_dict(), ctx.store.load_explanation(finding.id), list(ctx.audit.records())])
    assert KEY not in serialized + caplog.text
    assert "Authorization" not in serialized + caplog.text
    assert len(transport.calls) == 3
    for path in state_dir.rglob("*"):
        if path.is_file():
            assert KEY.encode() not in path.read_bytes()


def test_auth_failure_cannot_enter_service_status_audit_or_settings(monkeypatch, transport, state_dir, caplog):
    from tests.explain.helpers import make_ctx, ssh_root_finding

    monkeypatch.setenv("CT_LLM_API_KEY", KEY)
    transport.responses.extend([hostile_error(), hostile_error()])
    ctx = make_ctx(state_dir)
    ctx.explain.backend = backend()
    status = ctx.explain.status()
    assert status["available"] is False
    result = ctx.explain.explain(ssh_root_finding())
    assert result.fallback
    serialized = json.dumps([ctx.settings.to_dict(), status, result.to_dict()])
    assert KEY not in serialized + caplog.text
    assert "Authorization" not in serialized + caplog.text
    assert "llm_api_key" not in ctx.settings.to_dict()
    for path in state_dir.rglob("*"):
        if path.is_file():
            assert KEY.encode() not in path.read_bytes()
            assert b"Authorization" not in path.read_bytes()


def test_shared_helper_and_local_backend_do_not_inherit_key(monkeypatch, transport):
    monkeypatch.setenv("CT_LLM_API_KEY", KEY)
    transport.responses.extend([{}, {"models": [{"name": "local"}]}, {"response": "answer"}])
    assert backends._http_json("GET", "http://127.0.0.1/unrelated", None, 1) == {}
    b = OllamaBackend("http://127.0.0.1:11434", "local")
    assert b.available()[0]
    assert b.generate("prompt", timeout=1) == "answer"
    assert all(req.get_header("Authorization") is None for req in transport.calls)


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("operation", ["probe", "generate"])
@pytest.mark.parametrize("same_origin", [False, True])
def test_authenticated_redirects_never_forward_credentials(monkeypatch, caplog, code, operation, same_origin):
    monkeypatch.setenv("CT_LLM_API_KEY", KEY)
    source_url = "http://127.0.0.1:1234"
    destination_url = source_url if same_origin else "http://127.0.0.1:5678"
    destination_calls = []
    source_calls = []

    class MockHTTPHandler(backends.urllib.request.HTTPHandler):
        def http_open(self, req):
            headers = Message()
            if req.full_url == f"{destination_url}/destination":
                destination_calls.append(dict(req.header_items()))
                status, reason, body = 200, "OK", json.dumps(COMPLETION)
            else:
                source_calls.append(req.get_header("Authorization"))
                headers["Location"] = "/destination" if same_origin else f"{destination_url}/destination"
                status, reason, body = code, f"Authorization: Bearer {KEY}", "redirect"
            response = urllib.response.addinfourl(io.BytesIO(body.encode()), headers, req.full_url, status)
            response.msg = reason
            return response

    build_opener = backends.urllib.request.build_opener
    monkeypatch.setattr(
        backends.urllib.request, "build_opener",
        lambda *handlers: build_opener(backends.urllib.request.ProxyHandler({}), MockHTTPHandler(), *handlers),
    )
    b = OpenAICompatBackend(source_url, "local")
    if operation == "probe":
        ok, detail = b.available()
        assert not ok
    else:
        assert b.generate("prompt", timeout=1) is None
        detail = caplog.text
    assert source_calls == [f"Bearer {KEY}"]
    assert destination_calls == []
    assert "redirect refused" in detail
    assert KEY not in detail + caplog.text and "Authorization" not in detail + caplog.text
