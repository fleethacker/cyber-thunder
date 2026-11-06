"""Bounded authentication-event policy; application roles and resource grants are separate."""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
import re
import time

RISKY_ACTIONS = frozenset({"approve", "policy", "kill.release", "admin"})
ERROR = "insufficient_user_authentication"
DETAIL = "Fresh authentication with an accepted assurance context is required."
_ACR = re.compile(r'[\x21\x23-\x5b\x5d-\x7e]{1,128}\Z', re.ASCII)
REASONS = frozenset({"assurance_not_configured", "human_authentication_required", "invalid_authentication_time",
                     "future_authentication_time", "authentication_too_old", "assurance_not_accepted"})


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


def require_step_up(settings, principal, action: str) -> None:
    if settings.auth_mode != "dev" and action in RISKY_ACTIONS:
        StepUpPolicy.from_settings(settings).require(principal)
