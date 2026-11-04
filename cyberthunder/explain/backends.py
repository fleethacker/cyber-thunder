"""Local model backends for the explain layer.

Every backend talks only to a model server on the enclave (default localhost). Standard library only.
generate() never raises on network or server errors: it returns None and the service falls back to the
deterministic template, so a dead or slow model never blocks a scan or the approval workflow.
"""
from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from typing import Protocol, runtime_checkable

log = logging.getLogger(__name__)

AVAILABILITY_TTL_S = 30.0
GENERATE_OPTIONS = {"temperature": 0.2, "num_predict": 300}


@runtime_checkable
class Backend(Protocol):
    name: str
    model: str | None

    def generate(self, prompt: str, *, json_mode: bool, timeout: int) -> str | None: ...
    def available(self) -> tuple[bool, str]: ...


def _http_json(method: str, url: str, body: dict | None, timeout: float) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # noqa: S310  local model server only
        raw = resp.read().decode("utf-8", errors="replace")
    out = json.loads(raw) if raw.strip() else {}
    return out if isinstance(out, dict) else {}


class _CachedAvailability:
    """Caches an availability probe so status polls do not hammer the model server."""

    def __init__(self, ttl: float = AVAILABILITY_TTL_S):
        self.ttl = ttl
        self._lock = threading.Lock()
        self._at = 0.0
        self._value: tuple[bool, str] | None = None

    def get(self, probe) -> tuple[bool, str]:
        with self._lock:
            now = time.monotonic()
            if self._value is not None and now - self._at < self.ttl:
                return self._value
            self._value = probe()
            self._at = now
            return self._value

    def clear(self) -> None:
        with self._lock:
            self._value = None


class OllamaBackend:
    """Ollama: GET /api/tags to check the model is pulled, POST /api/generate with format=json."""
    name = "ollama"

    def __init__(self, url: str, model: str, fallback_model: str | None = None, *, probe_timeout: float = 3.0):
        self.url = url.rstrip("/")
        self.configured_model = model
        self.model: str | None = model
        self.fallback_model = fallback_model or None
        self.using_fallback = False
        self.probe_timeout = probe_timeout
        self._avail = _CachedAvailability()

    def _probe(self) -> tuple[bool, str]:
        try:
            tags = _http_json("GET", f"{self.url}/api/tags", None, self.probe_timeout)
        except (urllib.error.URLError, OSError, ValueError) as e:
            return False, f"ollama unreachable at {self.url}: {e}"
        names = {m.get("name") or m.get("model") for m in tags.get("models", []) if isinstance(m, dict)}
        names.discard(None)

        def present(model: str) -> bool:
            # "gemma3:4b" matches itself; a bare "gemma3" also matches "gemma3:latest"
            return model in names or (":" not in model and f"{model}:latest" in names)

        if present(self.configured_model):
            self.model, self.using_fallback = self.configured_model, False
            return True, f"ollama {self.url} model {self.configured_model}"
        if self.fallback_model and present(self.fallback_model):
            self.model, self.using_fallback = self.fallback_model, True
            log.warning("model %s not pulled; using fallback %s", self.configured_model, self.fallback_model)
            return True, f"ollama {self.url}: {self.configured_model} not pulled, using fallback {self.fallback_model}"
        have = ", ".join(sorted(names)) or "none"
        return False, f"ollama {self.url}: model {self.configured_model} not pulled (have: {have})"

    def available(self) -> tuple[bool, str]:
        return self._avail.get(self._probe)

    def generate(self, prompt: str, *, json_mode: bool = True, timeout: int = 180) -> str | None:
        body: dict = {"model": self.model, "prompt": prompt, "stream": False, "options": dict(GENERATE_OPTIONS)}
        if json_mode:
            body["format"] = "json"
        try:
            out = _http_json("POST", f"{self.url}/api/generate", body, timeout)
        except (urllib.error.URLError, OSError, ValueError) as e:
            log.warning("ollama generate failed: %s", e)
            self._avail.clear()
            return None
        text = out.get("response")
        return text if isinstance(text, str) and text.strip() else None


class OpenAICompatBackend:
    """Any OpenAI-compatible local server (llama.cpp server, LM Studio, vLLM): /v1/models, /v1/chat/completions."""
    name = "openai"

    def __init__(self, url: str, model: str, *, probe_timeout: float = 3.0):
        self.url = url.rstrip("/")
        self.model: str | None = model
        self.probe_timeout = probe_timeout
        self.json_mode_supported = True     # cleared the first time the server rejects response_format
        self._avail = _CachedAvailability()

    def _probe(self) -> tuple[bool, str]:
        try:
            out = _http_json("GET", f"{self.url}/v1/models", None, self.probe_timeout)
        except (urllib.error.URLError, OSError, ValueError) as e:
            return False, f"model server unreachable at {self.url}: {e}"
        ids = {m.get("id") for m in out.get("data", []) if isinstance(m, dict)}
        ids.discard(None)
        if not ids or self.model in ids:
            return True, f"openai-compatible {self.url} model {self.model}"
        return False, f"openai-compatible {self.url}: model {self.model} not loaded (have: {', '.join(sorted(ids))})"

    def available(self) -> tuple[bool, str]:
        return self._avail.get(self._probe)

    def _body(self, prompt: str, json_mode: bool) -> dict:
        body: dict = {"model": self.model, "messages": [{"role": "user", "content": prompt}],
                      "temperature": GENERATE_OPTIONS["temperature"], "max_tokens": GENERATE_OPTIONS["num_predict"],
                      "stream": False}
        if json_mode and self.json_mode_supported:
            body["response_format"] = {"type": "json_object"}
        return body

    def generate(self, prompt: str, *, json_mode: bool = True, timeout: int = 180) -> str | None:
        url = f"{self.url}/v1/chat/completions"
        try:
            try:
                out = _http_json("POST", url, self._body(prompt, json_mode), timeout)
            except urllib.error.HTTPError as e:
                if e.code in (400, 422) and json_mode and self.json_mode_supported:
                    # this server does not accept response_format; ask again without it
                    self.json_mode_supported = False
                    out = _http_json("POST", url, self._body(prompt, json_mode), timeout)
                else:
                    raise
        except (urllib.error.URLError, OSError, ValueError) as e:
            log.warning("openai-compatible generate failed: %s", e)
            self._avail.clear()
            return None
        try:
            text = out["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            return None
        return text if isinstance(text, str) and text.strip() else None


class TemplateBackend:
    """No network. The service writes template explanations itself; this backend exists so selection and
    status treat 'template' like any other backend."""
    name = "template"
    model = None

    def available(self) -> tuple[bool, str]:
        return True, "deterministic template (no model configured)"

    def generate(self, prompt: str, *, json_mode: bool = True, timeout: int = 180) -> str | None:
        return None


def make_backend(settings) -> Backend:
    kind = (settings.llm_backend or "template").strip().lower()
    if kind == "ollama":
        return OllamaBackend(settings.llm_url, settings.llm_model, settings.llm_fallback_model)
    if kind in ("openai", "openai-compat", "openai_compat"):
        return OpenAICompatBackend(settings.llm_url, settings.llm_model)
    return TemplateBackend()
