"""Read-only, account-scoped explanation of retained observations after incomplete scans."""
from __future__ import annotations

from cyberthunder.findings.current import timestamp
from cyberthunder.security.resources import object_scopes, visible_record

_TERMINAL = {"done", "partial", "error", "skipped", "timed_out", "stopped", "cancelled"}
_COLLECTORS = {"manual", "scheduled", "stig_delta", "verify", "demo"}
_CHECK_SOURCES = {"native", "openscap", "windows-stig", "windows-scap", "evaluate-stig",
                  "kubernetes", "containers", "cisco_ios"}
_REASONS = {
    "target_unavailable": "The later scan could not collect this target; this earlier observation was not reassessed.",
    "target_not_started": "The later scan ended without completing this target's assessment; this earlier observation was not reassessed.",
    "partial_collection": "The later scan collected only partial results and did not reassess this observation.",
    "retained_incomplete_observation": "The later scan recorded that an incomplete result was withheld to preserve this earlier unresolved observation. It was not revalidated.",
    "omitted_observation": "The later scan did not produce a new observation for this finding. Incomplete coverage retained the earlier evidence without revalidation.",
}


def _mapping(value) -> dict:
    return value if isinstance(value, dict) else {}


def _module(finding: dict) -> str | None:
    provenance = _mapping(finding.get("collection_provenance"))
    # Independent image-survey evidence is outside the host scanner's authority.
    if provenance.get("producer") == "cluster_vulnerabilities":
        return None
    source = finding.get("source")
    if source in _CHECK_SOURCES:
        return "check"
    if source == "hunt":
        return "hunt"
    if source in {"cve", "trivy"}:
        return "cve"
    return None


def _scope(run: dict, host: str):
    scopes = object_scopes(run)
    if not isinstance(scopes, list):
        return None
    matching = [s for s in scopes if s.get("target_id") == host]
    return matching[0] if len(matching) == 1 else None


def _relevant(run: dict, finding: dict, module: str) -> bool:
    modules = run.get("modules")
    if (run.get("trigger") not in _COLLECTORS or not isinstance(modules, list)
            or module not in modules):
        return False
    rules = run.get("rule_filter")
    identifiers = {finding.get("rule_id"), finding.get("rule_version"), finding.get("group_id")}
    identifiers.update(r.get("id") for r in finding.get("references", []) if isinstance(r, dict) and isinstance(r.get("id"), str))
    return rules is None or (isinstance(rules, list) and all(isinstance(r, str) for r in rules)
                             and (not rules or bool(identifiers & set(rules))))


class ReassessmentView:
    """Request-local index. Only fully readable runs participate, including mixed-target runs.

    No inventory-derived relabeling, persistence, confidence or review calculation occurs here.
    A named scan bounds history; later runs cannot decorate a historical observation.
    """

    def __init__(self, ctx, *, scan_id: str | None = None):
        self.ctx = ctx
        self.runs = {r["id"]: r for r in ctx.store.list_scan_runs() if visible_record(ctx, r)}
        self.scan_id = scan_id
        self.cutoff = timestamp(self.runs.get(scan_id, {}).get("started_at")) if scan_id else None
        self.by_target: dict[str, list[tuple]] = {}
        self.observations: dict[str, list] = {}
        for run in self.runs.values():
            started = timestamp(run.get("started_at"))
            if started is None or run.get("status") not in _TERMINAL:
                continue
            if scan_id and (self.cutoff is None or started > self.cutoff):
                continue
            for host in run.get("targets", []):
                self.by_target.setdefault(host, []).append((started, run))
        for runs in self.by_target.values():
            runs.sort(key=lambda item: (item[0], item[1]["id"]), reverse=True)

    def assess(self, finding: dict) -> dict:
        return self.assess_many([finding])[0]

    def assess_many(self, findings: list[dict]) -> list[dict]:
        # Loading observations can wait for storage while grants or inventory change.
        # Recheck every run that influenced the answer after those reads, including
        # earlier rows, origin/cutoff and tied candidates. Drop revoked history and
        # derive the entire page again, so later reads cannot leave earlier badges stale.
        while True:
            used: set[str] = set()
            results = [self._assess(finding, used) for finding in findings]
            for finding, result in zip(findings, results):
                if not visible_record(self.ctx, finding):
                    result.update(status="unknown", reason="history_unavailable", latest_attempt=None,
                                  explanation="Reassessment history cannot be established from the available observation metadata.")
                    result["observation"] = {"observed_at": None, "source": None, "scan_id": None}
            revoked = [sid for sid in used if not visible_record(self.ctx, self.runs[sid])]
            if not revoked:
                return results
            for sid in revoked:
                self.runs.pop(sid)

    def _assess(self, finding: dict, used: set[str]) -> dict:
        provenance = _mapping(finding.get("collection_provenance"))
        observed_at = provenance.get("observed_at", finding.get("collected_at"))
        observed, collected = timestamp(observed_at), timestamp(finding.get("collected_at"))
        scope = object_scopes(finding)
        origin = self.runs.get(finding.get("scan_id"), {})
        if not visible_record(self.ctx, origin):
            origin = {}
        if origin and scope and _scope(origin, finding["host"]) == scope:
            used.add(origin["id"])
        result = {"version": 1, "status": "unknown", "reason": "history_unavailable",
                  "explanation": "Reassessment history cannot be established from the available observation metadata.",
                  "observation": {"observed_at": observed_at if observed else None,
                                  "source": finding.get("source"),
                                  "scan_id": origin.get("id") if scope and _scope(origin, finding["host"]) == scope else None},
                  "latest_attempt": None, "view": "scan" if self.scan_id else "current"}
        if not visible_record(self.ctx, finding):
            # Defense in depth for callers other than the already-filtered findings routes.
            result["observation"] = {"observed_at": None, "source": None, "scan_id": None}
            return result
        module = _module(finding)
        if (not scope or observed is None or collected is None or module is None
                or self.scan_id and (self.cutoff is None or self.scan_id not in self.runs
                                     or not visible_record(self.ctx, self.runs[self.scan_id]))):
            return result
        if self.scan_id:
            used.add(self.scan_id)
        anchor = max(observed, collected)
        origin_at = timestamp(origin.get("started_at"))
        if origin_at and _scope(origin, finding["host"]) == scope:
            anchor = max(anchor, origin_at)
        candidates = [(at, run) for at, run in self.by_target.get(finding["host"], [])
                      if run["id"] in self.runs and at > anchor and run["id"] != finding.get("scan_id")
                      and _scope(run, finding["host"]) == scope and _relevant(run, finding, module)
                      and visible_record(self.ctx, run)]
        result.update(status="no_known_gap", reason="no_later_incomplete_attempt",
                      explanation="No later incomplete assessment is recorded in the available history for this observation. This does not establish its current state.")
        if not candidates:
            return result
        used.update(run["id"] for at, run in candidates if at == candidates[0][0])
        if len(candidates) > 1 and candidates[0][0] == candidates[1][0]:
            result.update(status="unknown", reason="ambiguous_order",
                          explanation="The latest target scans have the same start time; their order cannot be established.")
            return result
        started, run = candidates[0]
        sid = run["id"]
        if sid not in self.observations:
            self.observations[sid] = self.ctx.store.load_findings(sid)
        # A fresh observation is affirmative evidence even within a partial run. A carried
        # forward row (old scan_id/time), or an ID reused for another scope, is not.
        for fresh in self.observations[sid]:
            fresh_observed = timestamp(_mapping(fresh.collection_provenance).get("observed_at", fresh.collected_at))
            fresh_collected = timestamp(fresh.collected_at)
            if (fresh.id == finding["id"] and fresh.host == finding["host"]
                    and fresh.source == finding["source"] and fresh.rule_id == finding["rule_id"]
                    and fresh.authorization_scope == scope and fresh.scan_id == sid
                    and fresh_collected is not None and fresh_collected >= started
                    and fresh_observed is not None and fresh_observed >= started
                    and visible_record(self.ctx, fresh)):
                result.update(reason="newer_observation", explanation="A later scan recorded another observation for this finding. This view retains the selected observation.")
                return result
        target = _mapping(_mapping(run.get("results")).get(finding["host"]))
        status = target.get("status")
        scheduling = _mapping(run.get("scheduling"))
        unavailable = finding["host"] in (scheduling.get("unavailable_targets") or [])
        partial = finding["host"] in (scheduling.get("partial_targets") or [])
        retained = _mapping(scheduling.get("retained_incomplete_observations")).get(finding["host"])
        retained = isinstance(retained, list) and finding["id"] in retained
        incomplete = (run.get("coverage_incomplete") is True
                      or scheduling.get("omitted_observations") == "retain_without_revalidation")
        if (status in {"pending", "skipped", "stopped", "cancelled"}
                or not target and (incomplete or run.get("status") != "done")):
            reason = "target_not_started"
        elif unavailable or status in {"error", "timed_out"}:
            reason = "target_unavailable"
        elif retained:
            reason = "retained_incomplete_observation"
        elif partial or status == "partial":
            reason = "partial_collection"
        elif incomplete:
            reason = "omitted_observation"
        else:
            result.update(status="unknown", reason="coverage_unavailable",
                          explanation="The later scan did not record this observation and does not establish why it was omitted.")
            return result
        result.update(status="not_reassessed", reason=reason, explanation=_REASONS[reason],
                      latest_attempt={"scan_id": sid, "started_at": run["started_at"],
                                      "finished_at": run.get("finished_at") if timestamp(run.get("finished_at")) else None,
                                      "target_status": status if status in _TERMINAL | {"pending", "running"} else None})
        return result
