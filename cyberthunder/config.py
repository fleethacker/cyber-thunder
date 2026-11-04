"""Runtime settings. Everything comes from environment variables prefixed CT_ or from CLI flags.

No cloud endpoints. The only network the runtime talks to is the enclave (targets) and the local model.
"""
from __future__ import annotations

import os
import platform
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

_TRUE = {"1", "true", "yes", "on"}


def _env(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name)
    return default if v is None or v == "" else v


def _env_bool(name: str, default: bool) -> bool:
    v = _env(name)
    return default if v is None else v.strip().lower() in _TRUE


def _env_num(name: str, default: float, cast=float):
    v = _env(name)
    try:
        return cast(v) if v is not None else default
    except ValueError:
        return default


@dataclass
class Settings:
    # state
    state_dir: Path = field(default_factory=lambda: Path(_env("CT_STATE_DIR", "state")))
    # local model (explain layer). backend: ollama | openai | template
    llm_backend: str = field(default_factory=lambda: _env("CT_LLM_BACKEND", "ollama"))
    llm_url: str = field(default_factory=lambda: _env("CT_LLM_URL", "http://localhost:11434"))
    llm_model: str = field(default_factory=lambda: _env("CT_LLM_MODEL", "gemma3:4b"))
    llm_fallback_model: str = field(default_factory=lambda: _env("CT_LLM_FALLBACK_MODEL", "qwen2.5:3b"))
    llm_timeout_s: int = field(default_factory=lambda: _env_num("CT_LLM_TIMEOUT", 180, int))
    explain_precompute: bool = field(default_factory=lambda: _env_bool("CT_EXPLAIN_PRECOMPUTE", True))
    # behaviour
    auto_propose: bool = field(default_factory=lambda: _env_bool("CT_AUTO_PROPOSE", True))
    demo: bool = field(default_factory=lambda: _env_bool("CT_DEMO", False))
    # constrained link emulation (used by ingest/outbox; real shaping is done on the range with tc/netem)
    link_kbps: float = field(default_factory=lambda: _env_num("CT_LINK_KBPS", 56.0))
    link_latency_ms: int = field(default_factory=lambda: _env_num("CT_LINK_LATENCY_MS", 500, int))
    link_connected: bool = field(default_factory=lambda: _env_bool("CT_LINK_CONNECTED", True))
    # web
    host: str = field(default_factory=lambda: _env("CT_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_num("CT_PORT", 8000, int))
    ui_dist: Path = field(default_factory=lambda: Path(_env("CT_UI_DIST", str(Path(__file__).parent / "ui" / "dist"))))
    # identity of this node in the audit log
    node: str = field(default_factory=lambda: _env("CT_NODE", platform.node() or "cyberthunder"))

    @classmethod
    def from_env(cls, **overrides) -> "Settings":
        s = cls()
        for k, v in overrides.items():
            if v is None:
                continue
            if k not in {f.name for f in fields(cls)}:
                raise KeyError(f"unknown setting {k}")
            setattr(s, k, Path(v) if isinstance(getattr(s, k), Path) else v)
        return s

    def to_dict(self) -> dict:
        d = asdict(self)
        for k, v in d.items():
            if isinstance(v, Path):
                d[k] = str(v)
        return d
