"""Workflow API: one pass from content that arrived over the link to a reversible change on a target.

Receive lists STIGs and CVE bulletins already on disk. Discover reads one in-scope system and returns the
targets that belong to it. Scan, explain, and propose stay read-only aside from the proposal record.
Apply and rollback only move fixes a person has already approved, and both stop when the kill switch is engaged.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter

from cyberthunder.api.errors import MappedRoute, feature, status_for
from cyberthunder.api.routes.scans import start_scan
from cyberthunder.api.routes.targets import TARGET_ID, discover_target
from cyberthunder.api.schemas import (
    ApplyChecklistsBody, DiscoverBody, GenerateBody, RollbackBody, ScanTargetBody, TargetReportBody,
)
from cyberthunder.api.util import ActorDep, CtxDep, get_finding, get_proposal, proposal_for, proposal_plus, run_background, to_plain
from cyberthunder.control.approvals import ProposalState
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.findings.schema import Finding, summarize, utcnow
from cyberthunder.ingest import bulletin as bulletins
from cyberthunder.ingest import delta as deltas
from cyberthunder.inventory.targets import Target

router = APIRouter(tags=["workflow"], route_class=MappedRoute)

EXPLAIN_CAP = 40
PROPOSE_CAP = 100
ROLLBACK_FROM = {ProposalState.APPLIED, ProposalState.VERIFIED, ProposalState.FAILED}
LIVE = {ProposalState.PROPOSED, ProposalState.APPROVED, ProposalState.APPLYING, ProposalState.APPLIED}

CVE_FIELDS = ("id", "title", "severity", "cves", "published", "source", "ingested_at", "hosts_affected", "findings", "scan_id")
STIG_FIELDS = ("id", "benchmark_id", "old_release", "new_release", "counts", "created_at", "filename", "sizes",
               "transfer", "full_import")


def _pick(rows: list[dict], fields: tuple[str, ...]) -> list[dict]:
    return [{k: row.get(k) for k in fields if k in row} for row in rows]


def _ids(values: list[str] | None, what: str) -> list[str]:
    if not values:
        raise ValueError(f"{what} is required")
    out: list[str] = []
    for raw in values:
        if not isinstance(raw, str):
            raise ValueError(f"{what} must be a list of strings")
        text = raw.strip()
        if text and text not in out:
            out.append(text)
    if not out:
        raise ValueError(f"{what} is empty")
    if len(out) > 200:
        raise ValueError(f"{what} is limited to 200 entries")
    return out


def _system_id(body: DiscoverBody) -> str:
    for raw in (body.system, body.target):
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
    raise ValueError("system is required: the inventory id of the system to discover")


def _version_ids(body: RollbackBody) -> list[str]:
    raw: list[str] = list(body.versions or [])
    if isinstance(body.version, str):
        raw.append(body.version)
    elif isinstance(body.version, list):
        raw.extend(body.version)
    return _ids(raw, "versions")


def _in_scope(ctx, target_id: str) -> Target:
    ctx.inventory.get(target_id)              # 404 when the id is not in the inventory
    return ctx.inventory.assert_in_scope(target_id)


def _targets_on_system(ctx, system: Target) -> list[Target]:
    """The system itself, plus other in-scope targets that name it as their system.

    An out-of-scope neighbour is left out of the working set. A member id that is not in the inventory
    is an error in the system record, so it is a 404."""
    ordered = [system.id]
    members = (system.options or {}).get("members") or []
    if isinstance(members, list):
        for mid in members:
            if isinstance(mid, str) and mid and mid not in ordered:
                ordered.append(mid)
    linked = []
    for other in ctx.inventory.all():
        if other.id in ordered:
            continue
        opt = other.options or {}
        if opt.get("system") == system.id or system.id in (other.tags or []):
            linked.append(other.id)
    found = [system]
    for tid in ordered[1:] + linked:
        other = ctx.inventory.get(tid)
        if other.in_scope:
            found.append(other)
    return found


def _row(target: str, *, ok: bool, errors: list[str] | None = None, skipped: list[dict] | None = None, **extra) -> dict:
    out = {"target": target, "ok": ok, "errors": errors or [], "skipped": skipped or []}
    out.update(extra)
    return out


def _error_text(exc: BaseException) -> str:
    mapped = status_for(exc)
    if mapped is not None:
        return mapped[1]
    return str(exc) or type(exc).__name__


# -- receive ----------------------------------------------------------------------------------
@router.get("/receive/cve")
def receive_cve(ctx=CtxDep) -> dict:
    return {"cves": _pick(bulletins.list_bulletins(ctx.store), CVE_FIELDS)}


@router.get("/receive/stig")
def receive_stig(ctx=CtxDep) -> dict:
    return {"stigs": _pick(deltas.list_deltas(ctx.store), STIG_FIELDS)}


# -- discover ---------------------------------------------------------------------------------
@router.post("/discover")
def discover(body: DiscoverBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    body = body or DiscoverBody()
    system = _in_scope(ctx, _system_id(body))
    facts = discover_target(system.id, ctx, actor)
    targets = []
    for t in _targets_on_system(ctx, system):
        record = t.to_dict()
        if t.id == system.id:
            record["facts"] = facts
        targets.append(record)
    return {"targets": targets}


# -- scan -------------------------------------------------------------------------------------
@router.post("/scan", status_code=202)
def scan_target(body: ScanTargetBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    body = body or ScanTargetBody()
    target = (body.target or "").strip()
    if not target:
        raise ValueError("target is required")
    run = start_scan(ctx, actor, target_ids=[target], modules=body.modules, trigger="manual")
    result = run.get("results", {}).get(target) or {}
    return {
        "target": target,
        "results": {
            target: _row(target, ok=result.get("status") not in ("error", "stopped"),
                         errors=list(result.get("errors") or []),
                         scan_id=run["id"], status=run["status"],
                         findings=result.get("findings", 0), open=result.get("open", 0)),
        },
    }


# -- generate ---------------------------------------------------------------------------------
def _result_refs(results: dict) -> tuple[str | None, str | None, list[str] | None]:
    if not isinstance(results, dict):
        raise ValueError("results must be an object with a scan_id, a target, or finding_ids")
    scan_id = results.get("scan_id") if isinstance(results.get("scan_id"), str) else None
    target = results.get("target") if isinstance(results.get("target"), str) else None
    raw_ids = results.get("finding_ids")
    ids: list[str] | None = None
    if raw_ids is not None:
        if not isinstance(raw_ids, list) or not all(isinstance(x, str) for x in raw_ids):
            raise ValueError("finding_ids must be a list of strings")
        ids = [x.strip() for x in raw_ids if x.strip()]
    nested = results.get("results")
    if isinstance(nested, dict):
        for tid, row in nested.items():
            if not isinstance(row, dict):
                continue
            if scan_id is None and isinstance(row.get("scan_id"), str):
                scan_id = row["scan_id"]
            if target is None and isinstance(tid, str):
                target = tid
            break
    scan_id = scan_id.strip() if isinstance(scan_id, str) and scan_id.strip() else None
    target = target.strip() if isinstance(target, str) and target.strip() else None
    return scan_id, target, ids


def _findings_from_results(ctx, results: dict) -> list[Finding]:
    scan_id, target, ids = _result_refs(results)
    if ids is None and scan_id is None and target is None:
        raise ValueError("results need a scan_id, a target, or finding_ids")
    if ids is not None:
        found = [get_finding(ctx, fid, scan_id) for fid in ids]
        if target:
            _in_scope(ctx, target)
            found = [f for f in found if f.host == target]
        return found
    if scan_id and ctx.store.load_scan_run(scan_id) is None:
        raise KeyError(f"unknown scan {scan_id!r}")
    if target:
        _in_scope(ctx, target)
    found = ctx.store.load_findings(scan_id) if scan_id else ctx.store.load_findings()
    if target:
        found = [f for f in found if f.host == target]
    return [f for f in found if f.is_open]


@router.post("/generate/explain")
def generate_explain(body: GenerateBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    del actor  # the route requires a named person; the explanation itself is recorded as the agent
    body = body or GenerateBody()
    if not body.results:
        raise ValueError("results are required")
    findings = _findings_from_results(ctx, body.results)
    chosen, left = findings[:EXPLAIN_CAP], max(len(findings) - EXPLAIN_CAP, 0)
    explanations = []
    with feature("explain"):
        for finding in chosen:
            explanations.append(to_plain(ctx.explain.explain(finding)))
    return {"explanations": explanations, "truncated": left}


@router.post("/generate/propose")
def generate_propose(body: GenerateBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    body = body or GenerateBody()
    if not body.results:
        raise ValueError("results are required")
    findings = _findings_from_results(ctx, body.results)[:PROPOSE_CAP]
    proposals, skipped = [], []
    with feature("remediation engine"):
        for finding in findings:
            fix = ctx.library.resolve(finding)
            if fix is None:
                skipped.append({"id": finding.id, "reason": f"no library fix for {finding.rule_version or finding.rule_id}"})
                continue
            existing = proposal_for(ctx, finding.id)
            if existing is not None and existing.state in LIVE:
                skipped.append({"id": finding.id, "reason": f"live proposal {existing.id} is {existing.state.value}"})
                continue
            created = ctx.engine.propose(finding, actor=actor, fix=fix)
            if created is None:
                skipped.append({"id": finding.id, "reason": f"no library fix for {finding.rule_version or finding.rule_id}"})
                continue
            proposals.append(proposal_plus(ctx, created))
    return {"proposals": proposals, "skipped": skipped}


# -- apply / rollback -------------------------------------------------------------------------
def _finding_tokens(ctx, proposal) -> set[str]:
    tokens = {proposal.id, proposal.fix_ref}
    try:
        finding = get_finding(ctx, proposal.finding_id)
    except KeyError:
        return {t for t in tokens if t}
    tokens.update(finding.citations)
    for value in (finding.id, finding.rule_id, finding.rule_version, finding.group_id, finding.fix_ref,
                  finding.scan_id, finding.benchmark_release):
        if value:
            tokens.add(value)
    return tokens


def _match(ctx, target: str, wanted: set[str], states: set[ProposalState]) -> list[tuple]:
    matched, seen = [], set()
    for proposal in ctx.gate.list():
        if proposal.host != target or proposal.state not in states:
            continue
        hit = _finding_tokens(ctx, proposal) & wanted
        if not hit or proposal.id in seen:
            continue
        seen.add(proposal.id)
        matched.append((proposal, sorted(hit)[0]))
    return matched


def _uncovered(ctx, target: str, wanted: list[str], groups: list[list[tuple]]) -> list[dict]:
    covered: set[str] = set()
    for group in groups:
        for proposal, _token in group:
            covered |= _finding_tokens(ctx, proposal) & set(wanted)
    return [{"id": token, "reason": f"no matching change on {target}"} for token in wanted if token not in covered]


def _await_change(ctx, pid: str, work, name: str) -> dict:
    run_background(work, name)
    proposal = get_proposal(ctx, pid)
    return {"proposal_id": pid, "state": proposal.state.value, "version": pid}


@router.post("/apply")
def apply_checklists(body: ApplyChecklistsBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    body = body or ApplyChecklistsBody()
    targets = _ids(body.targets, "targets")
    checklists = _ids(body.checklists, "checklists")
    for tid in targets:
        _in_scope(ctx, tid)
    ctx.killswitch.guard("workflow.apply", actor)
    wanted = set(checklists)
    results = {}
    for tid in targets:
        applied, errors, skipped = [], [], []
        approved = _match(ctx, tid, wanted, {ProposalState.APPROVED})
        waiting = _match(ctx, tid, wanted, {ProposalState.PROPOSED})
        already = _match(ctx, tid, wanted, {ProposalState.APPLYING, ProposalState.APPLIED, ProposalState.VERIFIED})
        for proposal, token in waiting:
            skipped.append({"id": token, "reason": f"proposal {proposal.id} is {proposal.state.value}; approve it before apply"})
        for proposal, token in already:
            skipped.append({"id": token, "reason": f"proposal {proposal.id} is already {proposal.state.value}"})
        skipped.extend(_uncovered(ctx, tid, checklists, [approved, waiting, already]))
        for proposal, _token in approved:
            pid = proposal.id

            def work(proposal_id: str = pid) -> None:
                with feature("remediation engine"):
                    ctx.engine.execute(proposal_id, actor=actor)

            try:
                applied.append(_await_change(ctx, pid, work, f"apply-{pid}"))
            except KillSwitchEngaged:
                raise
            except Exception as exc:  # noqa: BLE001  one fix failing is recorded on the target, not the whole call
                errors.append(f"{pid}: {_error_text(exc)}")
        results[tid] = _row(tid, ok=not errors and bool(applied), applied=applied, skipped=skipped, errors=errors)
    return {"results": results}


@router.post("/rollback")
def rollback_versions(body: RollbackBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    body = body or RollbackBody()
    targets = _ids(body.targets, "targets")
    version_list = _version_ids(body)
    versions = set(version_list)
    for tid in targets:
        _in_scope(ctx, tid)
    ctx.killswitch.guard("workflow.rollback", actor)
    results = {}
    for tid in targets:
        rolled, errors = [], []
        matched = _match(ctx, tid, versions, ROLLBACK_FROM)
        skipped = _uncovered(ctx, tid, version_list, [matched])
        for proposal, token in matched:
            pid = proposal.id

            def work(proposal_id: str = pid) -> None:
                with feature("remediation engine"):
                    ctx.engine.rollback(proposal_id, actor=actor)

            try:
                item = _await_change(ctx, pid, work, f"rollback-{pid}")
                item["version"] = token
                rolled.append(item)
            except KillSwitchEngaged:
                raise
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{pid}: {_error_text(exc)}")
        results[tid] = _row(tid, ok=not errors and bool(rolled), rolled_back=rolled, skipped=skipped, errors=errors)
    return {"results": results}


# -- reports per target -----------------------------------------------------------------------
def _report_path(ctx, target_id: str) -> Path:
    if not TARGET_ID.match(target_id):
        raise ValueError(f"target id {target_id!r} is not a plain name")
    return ctx.store.root / "reports" / f"{target_id}.json"


def _checklist_for(ctx, target_id: str) -> tuple[dict | None, str | None]:
    svc = getattr(ctx, "reports", None)
    if svc is None or not hasattr(svc, "checklist_cklb"):
        return None, None
    try:
        doc = svc.checklist_cklb(None, target_id)
    except Exception as exc:  # noqa: BLE001  a missing checklist does not block the target report
        return None, str(exc) or type(exc).__name__
    return to_plain(doc), None


def _build_report(ctx, target_id: str, actor: str) -> dict:
    from cyberthunder.report import history
    target = ctx.inventory.get(target_id)
    history.import_existing(ctx)
    findings = [f for f in ctx.store.load_findings() if f.host == target_id]
    checklist, checklist_error = _checklist_for(ctx, target_id)
    doc = {
        "report_id": ctx.store.new_id("report-"),
        "target": target.to_dict(),
        "generated_at": utcnow(),
        "generated_by": actor,
        "findings": len(findings),
        "open": sum(1 for f in findings if f.is_open),
        "summary": summarize(findings),
        "checklist": checklist,
        "checklist_error": checklist_error,
    }
    history.save(ctx, "target", doc, "json", report_id=doc["report_id"], targets=[target_id], actor=actor,
                 generated_at=doc["generated_at"], scan_id=ctx.store.latest_scan_id())
    ctx.store.write_json(_report_path(ctx, target_id), doc)
    ctx.audit.append("report.render", actor, {"kind": "target", "target": target_id, "findings": len(findings),
                                              "open": doc["open"]}, subject=target_id)
    return doc


@router.get("/reports/{target_id}")
def get_target_report(target_id: str, ctx=CtxDep) -> dict:
    ctx.inventory.get(target_id)  # 404 for an unknown target; fixed report paths are registered first
    doc = ctx.store.read_json(_report_path(ctx, target_id))
    if not doc:
        raise KeyError(f"no report for {target_id!r}; POST /reports with {{\"target\": \"{target_id}\"}} to write one")
    return doc


@router.post("/reports")
def post_target_report(body: TargetReportBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    body = body or TargetReportBody()
    target = (body.target or "").strip()
    if not target:
        raise ValueError("target is required")
    return _build_report(ctx, target, actor)
