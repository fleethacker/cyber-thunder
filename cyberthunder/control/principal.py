"""Validated identities and request-local attribution; credentials never enter this model."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
import hashlib
import math
import time


def _text(value, name: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f"invalid identity {name}")
    return value


def _strings(value, name: str, maximum: int = 64) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > maximum:
        raise ValueError(f"invalid identity {name}")
    return tuple(sorted({_text(v, name) for v in value}))


@dataclass(frozen=True)
class Principal:
    issuer: str
    subject: str
    display_name: str
    kind: str = "workload"
    roles: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()
    via: str = "oidc"
    acr: str | None = None
    amr: tuple[str, ...] = ()
    auth_time: float | None = None
    expires_at: float | None = None
    session_id: str | None = None

    def __post_init__(self):
        for name in ("issuer", "subject", "display_name"):
            _text(getattr(self, name), name)
        if self.kind not in {"human", "workload", "dev"} or self.via not in {"dev", "oidc", "mesh"}:
            raise ValueError("invalid identity kind or source")
        if (self.kind == "dev") != (self.via == "dev"):
            raise ValueError("development identity cannot claim verification")
        for name in ("roles", "groups", "scopes", "amr"):
            object.__setattr__(self, name, _strings(getattr(self, name), name))
        for name in ("auth_time", "expires_at"):
            value = getattr(self, name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)):
                raise ValueError(f"invalid identity {name}")
        for name in ("acr", "session_id"):
            if getattr(self, name) is not None:
                _text(getattr(self, name), name)

    @property
    def actor(self) -> str:
        if self.kind == "dev":
            return self.subject
        digest = hashlib.sha256((self.issuer + "\x00" + self.subject).encode()).hexdigest()
        return f"{self.kind}:{digest}"

    @property
    def verified(self) -> bool:
        return self.via in {"oidc", "mesh"}

    def evidence(self) -> dict:
        return {"kind": self.kind, "iss": self.issuer, "sub": self.subject, "name": self.display_name,
                "roles": list(self.roles), "groups": list(self.groups), "scopes": list(self.scopes),
                "via": self.via, "verified": self.verified, "acr": self.acr, "amr": list(self.amr),
                "auth_time": self.auth_time, "expires_at": self.expires_at, "session_id": self.session_id}

    @classmethod
    def from_claims(cls, claims: dict, *, via: str, roles_claim: str = "ct_roles") -> "Principal":
        # The issuer must deliberately distinguish human accounts from service accounts.
        # A valid signature alone does not establish that a person authenticated.
        kind = claims.get("ct_kind", "workload")
        if kind not in {"human", "workload"}:
            raise ValueError("invalid identity account kind")
        subject = _text(claims.get("sub"), "subject")
        return cls(issuer=_text(claims.get("iss"), "issuer"), subject=subject,
                   display_name=claims.get("name") or claims.get("preferred_username") or subject,
                   kind=kind, roles=_strings(claims.get(roles_claim, []), "roles"),
                   groups=_strings(claims.get("groups", []), "groups"),
                   scopes=_strings(claims.get("ct_scopes", []), "scopes"), via=via,
                   acr=claims.get("acr"), amr=_strings(claims.get("amr", []), "amr"),
                   auth_time=claims.get("auth_time"), expires_at=claims.get("exp"), session_id=claims.get("sid"))


_current: ContextVar[Principal | None] = ContextVar("current_principal", default=None)
_operation: ContextVar[str | None] = ContextVar("authorized_operation", default=None)
_session_guard: ContextVar[object | None] = ContextVar("session_validity", default=None)


def current_principal() -> Principal | None:
    return _current.get()


def current_operation() -> str | None:
    return _operation.get()


@contextmanager
def operation_scope(action: str):
    token = _operation.set(action)
    try:
        yield
    finally:
        _operation.reset(token)


def operation(action: str):
    """Carry the actual operation into nested transport calls and their audit records."""
    def decorate(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            with operation_scope(action):
                return fn(*args, **kwargs)
        return wrapped
    return decorate


def authorize(ctx, action: str, *, actor: str | None = None, target=None):
    """Shared service guard; lightweight test contexts retain the explicit development default."""
    if getattr(getattr(ctx, "settings", None), "auth_mode", "dev") == "dev":
        return None
    return ctx.authorize(action, actor=actor, target=target)


@contextmanager
def principal_scope(principal: Principal | None, *, validity=None):
    token = _current.set(principal)
    lease = _session_guard.set(validity)
    try:
        yield
    finally:
        _session_guard.reset(lease)
        _current.reset(token)


def require_current(action: str, actor: str | None = None) -> Principal:
    from .roles import permits
    principal = current_principal()
    if principal is None or not principal.verified:
        raise PermissionError("a verified identity is required; authenticate through the application")
    if principal.expires_at is None or principal.expires_at <= time.time():
        raise PermissionError("the authenticated identity has expired")
    validity = _session_guard.get()
    if validity is not None:
        validity()
    if actor is not None and principal.actor != actor:
        raise PermissionError("the actor does not match the authenticated identity")
    if not permits(principal, action):
        raise PermissionError(f"permission required: {action}")
    return principal
