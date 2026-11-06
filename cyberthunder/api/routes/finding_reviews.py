"""Read review history and record scoped human decisions on current findings."""
from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from cyberthunder.api.errors import MappedRoute
from cyberthunder.api.util import ActorDep, CtxDep
from cyberthunder.findings.review import (
    MAX_REASON_LENGTH, MAX_SUPPORTING_EVIDENCE_LENGTH, ReviewConflict, ReviewService,
)

router = APIRouter(tags=["findings"], route_class=MappedRoute)


class ReviewBody(BaseModel):
    # Attribution comes only from the request principal inside ReviewService.
    # Reject client-supplied identity flags, actors and principal snapshots.
    model_config = ConfigDict(extra="forbid")

    disposition: StrictStr
    reason: StrictStr = Field(min_length=1, max_length=MAX_REASON_LENGTH)
    supporting_evidence: StrictStr = Field(default="", max_length=MAX_SUPPORTING_EVIDENCE_LENGTH)
    expires_at: StrictStr | None = Field(default=None, max_length=40)
    expected_revision: StrictInt = Field(ge=0)
    evidence_fingerprint: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")


def _finding(ctx, finding_id: str, scan_id: str | None = None):
    # Do not fall back to an old scan when the finding disappeared from the current picture.
    if scan_id is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", scan_id):
        raise ValueError("invalid scan_id")
    finding = next((f for f in ctx.store.load_findings(scan_id) if f.id == finding_id), None)
    if finding is None:
        raise KeyError(f"unknown finding {finding_id!r}")
    if getattr(getattr(ctx, "settings", None), "auth_mode", "dev") != "dev":
        from cyberthunder.security.resources import check_record
        check_record(ctx, finding, "read")
    return finding


@router.get("/findings/{finding_id}/review")
def get_review(finding_id: str, ctx=CtxDep, scan_id: str | None = None) -> dict:
    return ReviewService(ctx).history(_finding(ctx, finding_id, scan_id))


@router.put("/findings/{finding_id}/review")
def save_review(finding_id: str, body: ReviewBody, ctx=CtxDep, actor: str = ActorDep,
                scan_id: str | None = None) -> dict:
    if scan_id is not None:
        raise ValueError("historical review views are read-only; omit scan_id to review current evidence")
    try:
        return ReviewService(ctx).save(_finding(ctx, finding_id), actor=actor, **body.model_dump())
    except ReviewConflict as exc:
        raise HTTPException(409, str(exc)) from exc
