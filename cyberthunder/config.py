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
    scheduler_actor: str = field(default_factory=lambda: _env("CT_SCHEDULER_ACTOR", "scheduler"))
    scan_interval_s: int = field(default_factory=lambda: _env_num("CT_SCAN_INTERVAL_SECONDS", 0, int))
    content_check_interval_s: int = field(default_factory=lambda: _env_num("CT_CONTENT_CHECK_INTERVAL_SECONDS", 0, int))
    bootstrap_cluster_target: bool = field(default_factory=lambda: _env_bool("CT_BOOTSTRAP_CLUSTER_TARGET", False))
    bootstrap_cluster_target_id: str = field(default_factory=lambda: _env("CT_BOOTSTRAP_CLUSTER_TARGET_ID", "test-cluster"))
    bootstrap_cluster_name: str = field(default_factory=lambda: _env("CT_BOOTSTRAP_CLUSTER_NAME", "Test Kubernetes cluster"))
    bootstrap_cluster_kubeconfig: str = field(default_factory=lambda: _env("CT_BOOTSTRAP_CLUSTER_KUBECONFIG", "/etc/cyberthunder/kubeconfig"))
    trivy_binary: str = field(default_factory=lambda: _env("CT_TRIVY_BINARY", "trivy"))
    trivy_skip_db_update: bool = field(default_factory=lambda: _env_bool("CT_TRIVY_SKIP_DB_UPDATE", True))
    trivy_timeout_s: int = field(default_factory=lambda: _env_num("CT_TRIVY_TIMEOUT", 300, int))
    openai_api_key: str | None = field(default_factory=lambda: _env("CT_OPENAI_API_KEY") or _env("OPENAI_API_KEY"))
    openai_model: str = field(default_factory=lambda: _env("CT_OPENAI_MODEL", "gpt-4o-mini"))
    openai_timeout_s: int = field(default_factory=lambda: _env_num("CT_OPENAI_TIMEOUT", 60, int))
    # constrained link emulation (used by ingest/outbox; real shaping is done on the range with tc/netem)
    link_kbps: float = field(default_factory=lambda: _env_num("CT_LINK_KBPS", 56.0))
    link_latency_ms: int = field(default_factory=lambda: _env_num("CT_LINK_LATENCY_MS", 500, int))
    link_connected: bool = field(default_factory=lambda: _env_bool("CT_LINK_CONNECTED", True))
    # DISA content pulls (ingest/content): check the public index when the link comes back, pull only on request
    content_check_on_reconnect: bool = field(default_factory=lambda: _env_bool("CT_CONTENT_CHECK_ON_RECONNECT", True))
    content_auto_pull: bool = field(default_factory=lambda: _env_bool("CT_CONTENT_AUTO_PULL", False))
    content_max_bytes: int = field(default_factory=lambda: _env_num("CT_CONTENT_MAX_BYTES", 512 * 1024 * 1024, int))
    content_timeout_s: int = field(default_factory=lambda: _env_num("CT_CONTENT_TIMEOUT", 30, int))
    content_snapshot: str | None = field(default_factory=lambda: _env("CT_CONTENT_SNAPSHOT", "") or None)
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
