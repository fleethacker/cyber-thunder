"""Request bodies for the HTTP API. Responses are the kernel's own to_dict() shapes (see docs/API.md),
so only inputs are modelled here. Unknown fields are ignored, so the UI may send back what it received."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

SCAN_TRIGGERS = ("manual", "scheduled", "stig_delta", "bulletin", "verify", "demo")


class NoteBody(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


class ReasonBody(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)


class ScanRequest(BaseModel):
    target_ids: list[str] | None = None
    modules: list[str] | None = None
    rule_filter: list[str] | None = None
    trigger: str | None = None


class ExplainBody(BaseModel):
    force: bool = False


class ExplainBatchBody(BaseModel):
    ids: list[str] | None = None


class ApplyBody(BaseModel):
    simulate_verify_fail: bool | None = None


class BulkBody(BaseModel):
    action: Literal["approve", "deny"]
    ids: list[str] = Field(min_length=1, max_length=500)
    note: str | None = Field(default=None, max_length=2000)


class PolicyBody(BaseModel):
    enabled: bool | None = None          # omitted: keep the current value
    reason: str | None = Field(default=None, max_length=2000)
    rules: list[dict] | None = None      # PolicyRule fields; validated against the dataclass


class EvaluateBody(BaseModel):
    proposal_id: str


class LinkBody(BaseModel):
    kbps: float | None = Field(default=None, gt=0)
    latency_ms: int | None = Field(default=None, ge=0)
    connected: bool | None = None


class PathBody(BaseModel):
    path: str


class QueueBody(BaseModel):
    kind: Literal["commander", "poam", "checklist"]
    scan_id: str | None = None
    host: str | None = None


class DemoToggleBody(BaseModel):
    simulate_verify_fail_next: bool
