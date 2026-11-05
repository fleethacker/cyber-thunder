"""Local model backends for the explain layer.

Every backend talks only to a model server on the enclave (default localhost). Standard library only.
generate() never raises on network or server errors: it returns None and the service falls back to the
deterministic template, so a dead or slow model never blocks a scan or the approval workflow.
"""
from __future__ import annotations

import http.client
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from typing import Protocol, runtime_checkable

from .validator import extract_json_object

log = logging.getLogger(__name__)

AVAILABILITY_TTL_S = 30.0
GENERATE_OPTIONS = {"temperature": 0.2, "num_predict": 300}


@runtime_checkable
class Backend(Protocol):
    name: str
    model: str | None

    def generate(self, prompt: str, *, json_mode: bool, timeout: int) -> str | None: ...
    def available(self) -> tuple[bool, str]: ...


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Credentialed requests must stay at the configured endpoint."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http_json(method: str, url: str, body: dict | None, timeout: float,
               *, bearer_token: str | None = None) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", "Accept": "application/json"})
    open_request = urllib.request.urlopen
    if bearer_token:
        req.add_unredirected_header("Authorization", f"Bearer {bearer_token}")
        open_request = urllib.request.build_opener(_RefuseRedirects()).open
    with open_request(req, timeout=timeout) as resp:   # noqa: S310  local model server only
        raw = resp.read().decode("utf-8", errors="replace")
    out = json.loads(raw) if raw.strip() else {}
    if bearer_token and _contains_secret(out, bearer_token):
        raise ValueError("model server response contained a credential")
    return out if isinstance(out, dict) else {}


def _contains_secret(value, secret: str) -> bool:
    """Reject reflected credentials before response text can reach persisted explanations."""
    if isinstance(value, str):
        return secret in value
    if isinstance(value, dict):
        return any(_contains_secret(k, secret) or _contains_secret(v, secret) for k, v in value.items())
    if isinstance(value, list):
        return any(_contains_secret(item, secret) for item in value)
    return False


def _completion_text(out: dict) -> str | None:
    try:
        text = out["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return None
    return text if isinstance(text, str) and text.strip() else None


def _compatible_failure(error: Exception) -> str:
    """Only fixed diagnostics may leave this backend; remote error text is untrusted."""
    if isinstance(error, urllib.error.HTTPError):
        if error.code in (401, 403):
            return "model server authentication failed; check CT_LLM_API_KEY and endpoint access"
        if error.code in (301, 302, 303, 307, 308):
            return "model server redirect refused; configure the final endpoint directly"
        return "model server returned an HTTP error"
    return "model server request failed; check endpoint, credential format and server availability"


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

    def _request(self, method: str, url: str, body: dict | None, timeout: float) -> dict:
        # Read for every attempt, including the JSON-mode fallback; never retain the credential.
        key = os.environ.get("CT_LLM_API_KEY", "").strip()
        out = _http_json(method, url, body, timeout, bearer_token=key or None)
        text = _completion_text(out)
        # Match the validator's decoding, including JSON inside fences or surrounding prose.
        if key and text and _contains_secret(extract_json_object(text), key):
            raise ValueError("model server response contained a credential")
        return out

    def _probe(self) -> tuple[bool, str]:
        try:
            out = self._request("GET", f"{self.url}/v1/models", None, self.probe_timeout)
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as e:
            return False, _compatible_failure(e)
        models = out.get("data", [])
        if "error" in out or not isinstance(models, list):
            return False, "model server returned an invalid model list"
        ids = {m["id"] for m in models if isinstance(m, dict) and isinstance(m.get("id"), str)}
        if not ids or self.model in ids:
            return True, "compatible model server available"
        return False, "configured model not loaded on compatible server"

    def available(self) -> tuple[bool, str]:
        if os.environ.get("CT_LLM_API_KEY", "").strip():
            # Do not let a cached success or failure hide credential rotation or revocation.
            self._avail.clear()
            return self._probe()
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
                out = self._request("POST", url, self._body(prompt, json_mode), timeout)
            except urllib.error.HTTPError as e:
                if e.code in (400, 422) and json_mode and self.json_mode_supported:
                    # this server does not accept response_format; ask again without it
                    self.json_mode_supported = False
                    out = self._request("POST", url, self._body(prompt, json_mode), timeout)
                else:
                    raise
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as e:
            log.warning("compatible generate failed: %s", _compatible_failure(e))
            self._avail.clear()
            return None
        return _completion_text(out)


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
