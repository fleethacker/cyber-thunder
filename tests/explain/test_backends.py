"""Backends are tested with urlopen replaced: no sockets are opened."""
import io
import json
import urllib.error

import pytest

from cyberthunder.explain import backends
from cyberthunder.explain.backends import OllamaBackend, OpenAICompatBackend, TemplateBackend, make_backend


class _Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): self.close()


class FakeServer:
    def __init__(self, routes):
        self.routes = routes          # (method, path) -> dict | Exception | callable(body)
        self.calls = []

    def __call__(self, req, timeout=None):
        path = "/" + req.full_url.split("/", 3)[3]
        body = json.loads(req.data) if req.data else None
        self.calls.append((req.get_method(), path, body))
        r = self.routes.get((req.get_method(), path))
        if callable(r) and not isinstance(r, dict):
            r = r(body)
        if isinstance(r, Exception):
            raise r
        if r is None:
            raise urllib.error.URLError("connection refused")
        return _Resp(json.dumps(r).encode())


@pytest.fixture
def server(monkeypatch):
    def install(routes):
        s = FakeServer(routes)
        monkeypatch.setattr(backends.urllib.request, "urlopen", s)
        return s
    return install


def test_ollama_generate_request_shape(server):
    s = server({("GET", "/api/tags"): {"models": [{"name": "gemma3:4b"}]},
                ("POST", "/api/generate"): {"response": '{"risk": "r"}'}})
    b = OllamaBackend("http://127.0.0.1:11434/", "gemma3:4b", "qwen2.5:3b")
    assert b.available()[0] is True and b.model == "gemma3:4b"
    assert b.generate("hello", json_mode=True, timeout=5) == '{"risk": "r"}'
    body = s.calls[-1][2]
    assert body == {"model": "gemma3:4b", "prompt": "hello", "stream": False, "format": "json",
                    "options": {"temperature": 0.2, "num_predict": 300}}


def test_ollama_uses_fallback_model_and_caches(server):
    s = server({("GET", "/api/tags"): {"models": [{"name": "qwen2.5:3b"}]}})
    b = OllamaBackend("http://127.0.0.1:11434", "gemma3:4b", "qwen2.5:3b")
    ok, detail = b.available()
    assert ok and b.using_fallback and b.model == "qwen2.5:3b" and "fallback" in detail
    b.available()
    assert len(s.calls) == 1       # cached


def test_ollama_missing_model_and_unreachable(server):
    server({("GET", "/api/tags"): {"models": [{"name": "llama3:8b"}]}})
    assert OllamaBackend("http://h:1", "gemma3:4b", "qwen2.5:3b").available()[0] is False
    server({})
    b = OllamaBackend("http://h:1", "gemma3:4b")
    assert b.available()[0] is False
    assert b.generate("x", json_mode=True, timeout=1) is None      # never raises


def test_openai_compat_retries_without_response_format(server):
    def chat(body):
        if "response_format" in body:
            return urllib.error.HTTPError("u", 400, "bad", {}, None)
        return {"choices": [{"message": {"content": '{"ok": true}'}}]}
    s = server({("GET", "/v1/models"): {"data": [{"id": "local"}]}, ("POST", "/v1/chat/completions"): chat})
    b = OpenAICompatBackend("http://127.0.0.1:1234", "local")
    assert b.available()[0]
    assert b.generate("p", json_mode=True, timeout=5) == '{"ok": true}'
    assert b.json_mode_supported is False and len(s.calls) == 3


def test_openai_compat_errors_return_none(server):
    server({("POST", "/v1/chat/completions"): {"choices": []}})
    assert OpenAICompatBackend("http://h:1", "m").generate("p", json_mode=True, timeout=1) is None
    server({("POST", "/v1/chat/completions"): urllib.error.HTTPError("u", 500, "err", {}, None)})
    assert OpenAICompatBackend("http://h:1", "m").generate("p", json_mode=True, timeout=1) is None


def test_template_and_factory():
    t = TemplateBackend()
    assert t.available()[0] and t.generate("x", json_mode=True, timeout=1) is None

    class S:
        llm_backend, llm_url, llm_model, llm_fallback_model = "ollama", "http://h:1", "m", "f"
    assert isinstance(make_backend(S), OllamaBackend)
    S.llm_backend = "openai"
    assert isinstance(make_backend(S), OpenAICompatBackend)
    S.llm_backend = "template"
    assert isinstance(make_backend(S), TemplateBackend)
