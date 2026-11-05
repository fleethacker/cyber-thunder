"""Request bodies for the HTTP API. Responses are the kernel's own to_dict() shapes (see docs/API.md),
so only inputs are modelled here. Unknown fields are ignored, so the UI may send back what it received."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool

SCAN_TRIGGERS = ("manual", "scheduled", "stig_delta", "bulletin", "verify", "demo")


class NoteBody(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


class ApprovalBody(NoteBody):
    assessment_id: str | None = Field(default=None, max_length=36)
    assessment_note: str | None = Field(default=None, max_length=2000)


class ImpactBody(BaseModel):
    live: bool = True


class AssessmentReviewBody(BaseModel):
    assessment_id: str = Field(min_length=36, max_length=36)
    note: str | None = Field(default=None, max_length=2000)


class ReasonBody(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)


class KnownGoodBody(BaseModel):
    target_id: str
    reason: str = Field(min_length=1, max_length=2000)
    rule_id: str | None = None
    rule_version: str | None = None
    group_id: str | None = None
    object: str | None = None
    object_prefix: str | None = None
    expires_at: str | None = None


class KnownGoodFromFindingBody(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)
    scope: Literal["object", "object_prefix", "rule"] = "object"
    expires_at: str | None = None


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
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    mode: Literal["production", "test"] | None = None
    kbps: float | None = Field(default=None, gt=0, le=1000000)
    latency_ms: int | None = Field(default=None, ge=0, le=60000, strict=True)
    connected: StrictBool | None = None
    offline_override: StrictBool | None = None
    probe_enabled: StrictBool | None = None
    probe_endpoint: Literal["https://www.cyber.mil/", "https://dl.dod.cyber.mil/"] | None = None


class PathBody(BaseModel):
    path: str


class QueueBody(BaseModel):
    kind: Literal["commander", "poam", "checklist"]
    scan_id: str | None = None
    host: str | None = None


class DemoToggleBody(BaseModel):
    simulate_verify_fail_next: bool


class DiscoverBody(BaseModel):
    """A system already in the inventory. `target` is accepted as the same field."""
    system: str | None = None
    target: str | None = None


class ScanTargetBody(BaseModel):
    target: str | None = None
    modules: list[str] | None = None


class GenerateBody(BaseModel):
    """Scan results, a `{scan_id, target, finding_ids}` object, or the body returned by POST /scan."""
    results: dict | None = None


class ApplyChecklistsBody(BaseModel):
    targets: list[str] | None = None
    checklists: list[str] | None = None


class RollbackBody(BaseModel):
    targets: list[str] | None = None
    versions: list[str] | None = None
    version: str | list[str] | None = None


class TargetReportBody(BaseModel):
    target: str | None = None
