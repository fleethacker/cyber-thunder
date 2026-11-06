"""Bounded authentication-event policy; application roles and resource grants are separate."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
import re
import threading
import time

RISKY_ACTIONS = frozenset({"approve", "policy", "kill.release", "admin", "risk.accept", "maintenance.override"})
ERROR = "insufficient_user_authentication"
DETAIL = "Fresh authentication with an accepted assurance context is required."
_ACR = re.compile(r'[\x21\x23-\x5b\x5d-\x7e]{1,128}\Z', re.ASCII)
REASONS = frozenset({"assurance_not_configured", "human_authentication_required", "invalid_authentication_time",
                     "future_authentication_time", "authentication_too_old", "assurance_not_accepted"})
_clock_lock = threading.Lock()


class FreshnessClock:
    """One node's nondecreasing authentication-age clock, shared by API and core.

    Wall-clock corrections cannot renew an authentication event. Count suspend
    time where the operating system's monotonic clock excludes it, and fail
    closed permanently if the monotonic source itself becomes invalid.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._wall, self._mono = time.time(), time.monotonic()
        self._failed = False

    def now(self):
        with self._lock:
            before, wall, mono = time.monotonic(), time.time(), time.monotonic()
            if (self._failed or not all(math.isfinite(v) for v in (self._wall, self._mono, before, wall, mono))
                    or before < self._mono or mono < before or wall < 0):
                self._failed = True
                return float("nan")
            self._wall = max(wall, self._wall + mono - self._mono)
            self._mono = mono
            return self._wall


def freshness_clock(ctx):
    """Also support service contexts that bind AppContext.authorize explicitly."""
    with _clock_lock:
        if not hasattr(ctx, "step_up_clock"):
            ctx.step_up_clock = FreshnessClock()
        return ctx.step_up_clock


def parse_max_age(value: str | None) -> int:
    if value is None:
        return 300
    if not isinstance(value, str) or re.fullmatch(r"[1-9][0-9]{0,3}", value) is None:
        raise ValueError("invalid step-up maximum age")
    result = int(value)
    if result > 3600:
        raise ValueError("invalid step-up maximum age")
    return result


def parse_acr_values(value: str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    try:
        if not isinstance(value, str) or len(value) > 2048:
            raise ValueError()
        result = json.loads(value)
        if not isinstance(result, list):
            raise ValueError()
        return StepUpPolicy(acr_values=tuple(result)).acr_values
    except Exception:
        raise ValueError("invalid step-up accepted ACR values") from None


@dataclass(frozen=True)
class StepUpPolicy:
    max_age: int = 300
    acr_values: tuple[str, ...] = ()

    def __post_init__(self):
        if type(self.max_age) is not int or not 1 <= self.max_age <= 3600:
            raise ValueError("invalid step-up maximum age")
        if (not isinstance(self.acr_values, tuple) or len(self.acr_values) > 8
                or any(not isinstance(v, str) or _ACR.fullmatch(v) is None for v in self.acr_values)
                or len(set(self.acr_values)) != len(self.acr_values)):
            raise ValueError("invalid step-up accepted ACR values")

    @classmethod
    def from_settings(cls, settings):
        return cls(getattr(settings, "step_up_max_age_s", 300), getattr(settings, "step_up_acr_values", ()))

    def require(self, principal, *, now=None):
        now = time.time() if now is None else now
        reason = None
        when = getattr(principal, "auth_time", None)
        if not self.acr_values:
            reason = "assurance_not_configured"
        elif not getattr(principal, "verified", False) or getattr(principal, "kind", None) != "human":
            reason = "human_authentication_required"
        elif (type(when) is not int or not 0 <= when <= 253402300799
              or type(now) not in (int, float) or not math.isfinite(now) or now < 0):
            reason = "invalid_authentication_time"
        elif when > now:
            reason = "future_authentication_time"
        elif now - when > self.max_age:
            reason = "authentication_too_old"
        elif getattr(principal, "acr", None) not in self.acr_values:
            reason = "assurance_not_accepted"
        if reason:
            raise StepUpRequired(self, reason)

    def login_parameters(self) -> dict:
        if not self.acr_values:
            raise ValueError("step-up accepted ACR values must be configured")
        return {"max_age": self.max_age, "prompt": "login", "acr_values": " ".join(self.acr_values)}


class StepUpRequired(PermissionError):
    """Safe public challenge containing only protected configuration and a fixed reason."""

    def __init__(self, policy: StepUpPolicy, reason: str):
        if reason not in REASONS:
            raise ValueError("invalid step-up reason")
        super().__init__(DETAIL)
        self.policy, self.reason = policy, reason

    def challenge(self) -> dict:
        return {"reason": self.reason, "max_age": self.policy.max_age, "acr_values": list(self.policy.acr_values)}

    def authenticate_header(self) -> str:
        value = f'Bearer error="{ERROR}", max_age="{self.policy.max_age}"'
        if self.policy.acr_values:
            value += ', acr_values="' + " ".join(self.policy.acr_values) + '"'
        return value


def require_step_up(settings, principal, action: str, *, clock=None, ctx=None, target=None, continuation=None) -> None:
    if continuation is not None and (action != "admin" or target is not None or type(continuation) is not _TransferContinuation):
        raise PermissionError("invalid transfer continuation")
    if settings.auth_mode != "dev" and action in RISKY_ACTIONS:
        policy = StepUpPolicy.from_settings(settings)
        now = clock.now() if clock is not None else time.time()
        if continuation is not None:
            continuation.require(ctx, principal, policy, now)
        else:
            policy.require(principal, now=now)


_TRANSFERS = frozenset({"content.pull", "vulnerabilities.update"})


def _intent_digest(intent):
    raw = json.dumps(intent, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("transfer declaration is too large")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, eq=False, repr=False)
class _TransferAdmission:
    owner: object
    principal: object
    operation: str
    job_id: str
    intent: str
    policy_digest: str
    assurance: StepUpPolicy
    mode: tuple
    deadline: float
    closed: object = field(default_factory=threading.Event)
    lock: object = field(default_factory=threading.Lock)

    def close(self):
        with self.lock:
            self.closed.set()


@dataclass(frozen=True, repr=False)
class _TransferContinuation:
    admission: _TransferAdmission
    operation: str
    job_id: str
    intent: str

    def require(self, ctx, principal, policy, now):
        receipt = self.admission
        if type(receipt) is not _TransferAdmission:
            raise PermissionError("invalid transfer admission")
        with receipt.lock:
            if (receipt.closed.is_set() or receipt.owner is not ctx or receipt.principal != principal
                    or self.operation != receipt.operation or self.job_id != receipt.job_id
                    or self.intent != receipt.intent or policy != receipt.assurance
                    or receipt.mode != (ctx.settings.auth_mode, getattr(ctx.settings, "security_mode", "range"))
                    or not math.isfinite(now) or now >= receipt.deadline
                    or ctx.access._load()[1] != receipt.policy_digest):
                raise PermissionError("transfer admission expired or changed")


def admit_transfer(ctx, *, operation, job_id, intent, actor):
    """Admit one explicit job; never persist this object or inherit a general admin bypass."""
    from cyberthunder.control.principal import authorize
    principal = authorize(ctx, "admin", actor=actor)
    if getattr(ctx.settings, "auth_mode", "dev") == "dev":
        return None
    if operation not in _TRANSFERS or not isinstance(job_id, str) or not 1 <= len(job_id) <= 128:
        raise ValueError("invalid transfer declaration")
    policy = StepUpPolicy.from_settings(ctx.settings)
    now = freshness_clock(ctx).now()
    policy.require(principal, now=now)
    receipt = _TransferAdmission(ctx, principal, operation, job_id, _intent_digest(intent), ctx.access._load()[1],
        policy, (ctx.settings.auth_mode, getattr(ctx.settings, "security_mode", "range")),
        min(principal.expires_at, now + 3600))
    ctx.audit.append("authorization.transfer_admitted", principal.actor,
        {"operation": operation, "job_id": job_id, "intent_sha256": receipt.intent,
         "deadline": receipt.deadline, "step_up_max_age": policy.max_age})
    return receipt


def transfer_continuation(admission, *, operation, job_id, intent):
    if admission is None:
        return None
    return _TransferContinuation(admission, operation, job_id, _intent_digest(intent))


def require_transfer_operation(continuation, operation):
    if type(continuation) is not _TransferContinuation or continuation.operation != operation:
        raise PermissionError("invalid transfer operation")


def authorize_transfer(ctx, *, continuation, actor):
    if continuation is None:
        from cyberthunder.control.principal import authorize
        return authorize(ctx, "admin", actor=actor)
    return ctx.authorize("admin", actor=actor, step_up_continuation=continuation)
