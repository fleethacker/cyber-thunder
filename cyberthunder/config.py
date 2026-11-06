"""Runtime settings. Everything comes from environment variables prefixed CT_ or from CLI flags.

Model endpoints and connected content updates are explicit configuration; ordinary
offline scans use locally provisioned content and scoped enclave targets.
"""
from __future__ import annotations

import os
import platform
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from cyberthunder.security.step_up import StepUpPolicy, parse_acr_values, parse_max_age

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
    # where documents live: json (one file each, the default) or sqlite (state.db in the state directory)
    state_backend: str = field(default_factory=lambda: (_env("CT_STATE_BACKEND", "json") or "json").strip().lower())
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
    vulnerability_max_bundle_bytes: int = field(default_factory=lambda: _env_num("CT_VULN_MAX_BUNDLE_BYTES", 4 * 1024 * 1024 * 1024, int))
    vulnerability_max_unpacked_bytes: int = field(default_factory=lambda: _env_num("CT_VULN_MAX_UNPACKED_BYTES", 8 * 1024 * 1024 * 1024, int))
    vulnerability_max_staging_bytes: int = field(default_factory=lambda: _env_num("CT_VULN_MAX_STAGING_BYTES", 12 * 1024 * 1024 * 1024, int))
    vulnerability_update_timeout_s: int = field(default_factory=lambda: _env_num("CT_VULN_UPDATE_TIMEOUT", 1800, int))
    vulnerability_db_max_age_hours: int = field(default_factory=lambda: _env_num("CT_VULN_DB_MAX_AGE_HOURS", 72, int))
    vulnerability_poll_s: int = field(default_factory=lambda: _env_num("CT_VULN_POLL_SECONDS", 60, int))
    openai_api_key: str | None = field(default_factory=lambda: _env("CT_OPENAI_API_KEY") or _env("OPENAI_API_KEY"))
    openai_model: str = field(default_factory=lambda: _env("CT_OPENAI_MODEL", "gpt-4o-mini"))
    openai_timeout_s: int = field(default_factory=lambda: _env_num("CT_OPENAI_TIMEOUT", 60, int))
    # Legacy numbers cannot enable emulation; test mode requires an audited link control.
    link_kbps: float = field(default_factory=lambda: _env_num("CT_LINK_KBPS", 56.0))
    link_latency_ms: int = field(default_factory=lambda: _env_num("CT_LINK_LATENCY_MS", 500, int))
    link_connected: bool = field(default_factory=lambda: _env_bool("CT_LINK_CONNECTED", True))
    link_offline: bool = field(default_factory=lambda: _env_bool("CT_LINK_OFFLINE", False))
    # DISA content pulls (ingest/content): check the public index when the link comes back, pull only on request
    content_check_on_reconnect: bool = field(default_factory=lambda: _env_bool("CT_CONTENT_CHECK_ON_RECONNECT", False))
    content_auto_pull: bool = field(default_factory=lambda: _env_bool("CT_CONTENT_AUTO_PULL", False))
    content_max_bytes: int = field(default_factory=lambda: _env_num("CT_CONTENT_MAX_BYTES", 512 * 1024 * 1024, int))
    content_timeout_s: int = field(default_factory=lambda: _env_num("CT_CONTENT_TIMEOUT", 30, int))
    content_snapshot: str | None = field(default_factory=lambda: _env("CT_CONTENT_SNAPSHOT", "") or None)
    content_trust_config: str | None = field(default_factory=lambda: _env("CT_CONTENT_TRUST_CONFIG", "") or None)
    # web
    auth_mode: str = field(default_factory=lambda: _env("CT_AUTH_MODE", "dev"))
    security_mode: str = field(default_factory=lambda: _env("CT_SECURITY_MODE", "range"))
    # None alone is unconfigured: an explicit empty value must fail closed.
    credential_sources: str | None = field(default_factory=lambda: os.environ.get("CT_CREDENTIAL_SOURCES"))
    step_up_max_age_s: int = field(default_factory=lambda: parse_max_age(os.environ.get("CT_STEP_UP_MAX_AGE_SECONDS")))
    step_up_acr_values: tuple[str, ...] = field(default_factory=lambda: parse_acr_values(os.environ.get("CT_STEP_UP_ACR_VALUES")))
    oidc_issuer: str = field(default_factory=lambda: _env("CT_OIDC_ISSUER", ""))
    oidc_audience: str = field(default_factory=lambda: _env("CT_OIDC_AUDIENCE", ""))
    oidc_jwks_url: str = field(default_factory=lambda: _env("CT_OIDC_JWKS_URL", ""))
    oidc_jwks_max_age: int = field(default_factory=lambda: _env_num("CT_OIDC_JWKS_MAX_AGE", 86400, int))
    oidc_authorized_party: str | None = field(default_factory=lambda: _env("CT_OIDC_AUTHORIZED_PARTY", "") or None)
    oidc_roles_claim: str = field(default_factory=lambda: _env("CT_OIDC_ROLES_CLAIM", "ct_roles"))
    oidc_client_id: str = field(default_factory=lambda: _env("CT_OIDC_CLIENT_ID", ""))
    oidc_authorization_endpoint: str = field(default_factory=lambda: _env("CT_OIDC_AUTHORIZATION_ENDPOINT", ""))
    oidc_token_endpoint: str = field(default_factory=lambda: _env("CT_OIDC_TOKEN_ENDPOINT", ""))
    oidc_redirect_uri: str = field(default_factory=lambda: _env("CT_OIDC_REDIRECT_URI", ""))
    oidc_client_secret_ref: str | None = field(default_factory=lambda: _env("CT_OIDC_CLIENT_SECRET_REF", "") or None)
    oidc_scope: str = field(default_factory=lambda: _env("CT_OIDC_SCOPE", "openid"))
    session_idle_seconds: int = field(default_factory=lambda: _env_num("CT_SESSION_IDLE_SECONDS", 900, int))
    session_absolute_seconds: int = field(default_factory=lambda: _env_num("CT_SESSION_ABSOLUTE_SECONDS", 28800, int))
    tls_cert: str | None = field(default_factory=lambda: _env("CT_TLS_CERT", "") or None)
    tls_key: str | None = field(default_factory=lambda: _env("CT_TLS_KEY", "") or None)
    host: str = field(default_factory=lambda: _env("CT_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_num("CT_PORT", 8000, int))
    ui_dist: Path = field(default_factory=lambda: Path(_env("CT_UI_DIST", str(Path(__file__).parent / "ui" / "dist"))))
    # identity of this node in the audit log
    node: str = field(default_factory=lambda: _env("CT_NODE", platform.node() or "cyberthunder"))

    def __post_init__(self):
        StepUpPolicy.from_settings(self)

    @classmethod
    def from_env(cls, **overrides) -> "Settings":
        s = cls()
        for k, v in overrides.items():
            if v is None:
                continue
            if k not in {f.name for f in fields(cls)}:
                raise KeyError(f"unknown setting {k}")
            setattr(s, k, Path(v) if isinstance(getattr(s, k), Path) else v)
        StepUpPolicy.from_settings(s)
        return s

    def to_dict(self) -> dict:
        d = asdict(self)
        for k, v in d.items():
            if isinstance(v, Path):
                d[k] = str(v)
        return d
