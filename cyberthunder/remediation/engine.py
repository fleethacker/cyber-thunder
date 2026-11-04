"""Remediation engine: the only code path that changes an asset.

Semantics (every edge is written to the audit log by the ApprovalGate or explicitly here):

  propose(finding)          resolve a FixEntry from the library; create a Proposal in PROPOSED with the
                            fix preview, rollback plan, blast-radius tags, citations and the current
                            explanation (or a deterministic template if none yet). Never executes anything.
  auto_propose(findings)    propose for every open finding that has a library entry and no live proposal.
                            If an AutomationPolicy is enabled, evaluate each proposal and, when eligible,
                            approve it with actor "policy:<signed_by>" (the gate refuses actor "agent").
  execute(proposal_id)      requires state APPROVED. In order:
                              1. inventory.assert_in_scope(target)          (ScopeViolation -> audit 'action.blocked', raise)
                              2. gate.start_apply(..)                       (kill switch guard happens inside the gate)
                              3. adapter.capture_before_state(..)           -> stored under store.snapshot_dir(proposal_id)
                              4. adapter.apply(..)                          -> ApplyResult
                              5. gate.applied(..) or gate.failed(..)
                              6. adapter.verify(..)                         -> VerifyResult (rule re-check + health)
                                 simulate_verify_fail=True forces a failed verify (demo only; it is audited as such)
                              7. verified -> gate.verified(..)
                                 failed   -> gate.failed(..) then automatic rollback: adapter.rollback(..) -> gate.rolled_back(..)
                            Every adapter call's inputs/outputs are summarised into the audit record for that edge.
  rollback(proposal_id)     manual rollback of an APPLIED or VERIFIED proposal: gate.rolled_back is kill-switch guarded.
  diff(proposal_id)         before/after evidence for the UI (captured files, verify evidence, outputs).

Rules: no shell text originates from the model; payloads come only from FixEntry. Any exception during
apply/verify leaves the proposal in FAILED (or ROLLED_BACK if rollback succeeded) with the error recorded.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Iterable

from cyberthunder.control import policy as policy_mod
from cyberthunder.control.approvals import TRANSITIONS, IllegalTransition, Proposal, ProposalState
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.findings.schema import Finding
from cyberthunder.inventory.targets import ScopeViolation
from cyberthunder.remediation import snapshot
from cyberthunder.remediation.library import FixEntry
from cyberthunder.remediation.models import BeforeState, HealthResult, VerifyResult

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext

log = logging.getLogger(__name__)

TERMINAL = {"denied", "cancelled", "verified", "rolled_back"}
NOTE_CHARS = 300


class EngineError(RuntimeError):
    pass


def _short(text: str | None, n: int = NOTE_CHARS) -> str:
    t = (text or "").strip().replace("\r", "")
    return t if len(t) <= n else t[: n - 3] + "..."


def _tag_value(tags: Iterable[str], key: str) -> str | None:
    """Tags are plain strings: `fix:disruption=medium`, `fix:reboot` (true) or `fix:reboot=false`."""
    prefix = key + "="
    for t in tags or ():
        if t.startswith(prefix):
            return t[len(prefix):]
        if t == key:
            return "true"
    return None


def dynamic_ssg_fix(finding: Finding) -> FixEntry | None:
    """Wrap the ComplianceAsCode fix script carried in the scanner content as a library entry.

    The payload is the fix text from the benchmark the scanner evaluated, never anything a model or an
    operator typed. It is shown verbatim to the approver like every other library entry. Blast-radius
    hints come from the finding tags `fix:disruption=<low|medium|high>` and `fix:reboot`.
    """
    if not finding.fix_script:
        return None
    last = finding.rule_id.replace("\\", "/").rstrip("/").split("/")[-1]
    disruption = (_tag_value(finding.tags, "fix:disruption") or "low").lower()
    if disruption not in ("low", "medium", "high"):
        disruption = "low"
    reboot = (_tag_value(finding.tags, "fix:reboot") or "").lower() in ("1", "true", "yes")
    return FixEntry(
        fix_ref=f"ssg:{last}", title=finding.title, asset_type=finding.asset_type or "linux",
        applies_to=[finding.rule_id], kind="script", payload=finding.fix_script, disruption=disruption,
        reboot=reboot, rollback_kind="restore_files", before_state={"files": ["/etc"]},
        verify={"rule_ids": [finding.rule_id]}, citations=list(finding.citations), source="ssg",
        notes="fix script from the scanner's benchmark content",
    )


class RemediationEngine:
    def __init__(self, ctx: "AppContext"):
        self.ctx = ctx
        self._findings: dict[str, Finding] = {}     # findings proposed in this process, by id

    # -- lookups -----------------------------------------------------------------------
    def _finding(self, finding_id: str) -> Finding | None:
        f = self.ctx.store.get_finding(finding_id)
        return f or self._findings.get(finding_id)

    def _resolve(self, finding: Finding) -> FixEntry | None:
        entry = self.ctx.library.resolve(finding)
        if entry is None:
            entry = dynamic_ssg_fix(finding)
            if entry is not None:
                self.ctx.library.add(entry)
        return entry

    def _fix_for(self, p: Proposal, finding: Finding | None) -> FixEntry:
        """The fix to run for a proposal. It must be exactly what the approver saw, or nothing runs."""
        entry = self.ctx.library.get(p.fix_ref)
        if entry is None and finding is not None:
            dyn = dynamic_ssg_fix(finding)
            if dyn is not None and dyn.fix_ref == p.fix_ref:
                self.ctx.library.add(dyn)
                entry = dyn
        if entry is None:
            raise EngineError(f"fix {p.fix_ref!r} is not in the remediation library")
        if entry.preview_text() != p.fix_preview:
            self.ctx.audit.append("action.blocked", "agent",
                                  {"action": "execute", "reason": "fix payload differs from what was approved",
                                   "fix_ref": p.fix_ref}, subject=p.id, outcome="blocked")
            raise EngineError(f"fix {p.fix_ref!r} changed since it was approved; propose and approve it again")
        return entry

    def _explanation(self, finding_id: str):
        explain = getattr(self.ctx, "explain", None)
        if explain is None:
            return None
        try:
            return explain.get(finding_id)
        except Exception:  # noqa: BLE001  the explanation is optional; never block a proposal on it
            return None

    @staticmethod
    def _template_risk(finding: Finding) -> str:
        cat = finding.severity.cat if finding.severity.cat != "-" else finding.severity.value.upper()
        cite = finding.citations[0] if finding.citations else "no identifier"
        return (f"{cat} finding on {finding.host}: {finding.title}. Until it is fixed the asset does not meet "
                f"the cited requirement ({cite}); the proposed library fix needs human approval before it runs.")

    # -- proposals ---------------------------------------------------------------------
    def propose(self, finding: Finding, *, actor: str = "agent", fix: FixEntry | None = None) -> Proposal | None:
        existing = self.proposal_for_finding(finding.id)
        if existing is not None and existing.state.value not in TERMINAL:
            return existing
        entry = fix or self._resolve(finding)
        if entry is None:
            return None
        finding.fix_ref = entry.fix_ref
        self._findings[finding.id] = finding
        exp = self._explanation(finding.id)
        if exp is not None and getattr(exp, "risk", None):
            risk = f"{exp.risk} {getattr(exp, 'impact', '') or ''}".strip()
        else:
            risk = self._template_risk(finding)
        p = self.ctx.gate.propose(actor=actor, finding_id=finding.id, host=finding.host, title=finding.title,
                                  fix_ref=entry.fix_ref, fix_preview=entry.preview_text(),
                                  rollback_plan=entry.rollback_plan_text(), risk=risk,
                                  citations=list(finding.citations[:8]))
        if p.history:
            p.history[0]["meta"] = {"risk_tags": entry.risk_tags(), "severity": finding.severity.value,
                                    "asset_type": entry.asset_type or finding.asset_type}
            self._persist_gate()
        snapshot.save_result(self.ctx.store.snapshot_dir(p.id), "fix", entry)
        return p

    def _persist_gate(self) -> None:
        save = getattr(self.ctx.gate, "_save", None)
        if callable(save):
            save()

    def auto_propose(self, findings: Iterable[Finding], *, actor: str = "agent") -> list[Proposal]:
        """Propose fixes for open findings. Returns only the proposals created by this call."""
        created: list[Proposal] = []
        for f in findings:
            if not f.is_open:
                continue
            prior = self.proposal_for_finding(f.id)
            p = self.propose(f, actor=actor)
            if p is None or (prior is not None and prior.id == p.id):
                continue
            created.append(p)
            self._apply_policy(p, f)
        return created

    def _apply_policy(self, p: Proposal, finding: Finding) -> None:
        pol = self.ctx.policy
        if not pol.enabled:
            return
        if self.ctx.killswitch.is_engaged():
            self.ctx.audit.append("policy.skipped", "agent", {"reason": "kill switch engaged", "fix_ref": p.fix_ref},
                                  subject=p.id, outcome="blocked")
            return
        fix = self.ctx.library.get(p.fix_ref)
        try:
            target = self.ctx.inventory.get(p.host)
        except KeyError:
            target = None
        if fix is None or target is None:
            self.ctx.audit.append("policy.skipped", "agent",
                                  {"reason": "fix or target not found", "fix_ref": p.fix_ref, "host": p.host},
                                  subject=p.id, outcome="blocked")
            return
        decision = policy_mod.evaluate(pol, fix, finding, target)
        if not decision.auto_eligible:
            self.ctx.audit.append("policy.evaluate", "agent", {"decision": decision.to_dict(), "fix_ref": p.fix_ref},
                                  subject=p.id, outcome="declined")
            return
        self.ctx.gate.approve(p.id, actor=f"policy:{pol.signed_by}", note=decision.reasons[0])
        self.ctx.audit.append("policy.auto_approve", f"policy:{pol.signed_by}",
                              {"decision": decision.to_dict(), "fix_ref": p.fix_ref, "policy_version": pol.version},
                              subject=p.id)

    def proposal_for_finding(self, finding_id: str) -> Proposal | None:
        """Most recent non-terminal proposal for a finding, else most recent of any state, else None."""
        live = [p for p in self.ctx.gate.list() if p.finding_id == finding_id]
        if not live:
            return None
        open_ = [p for p in live if p.state.value not in TERMINAL]
        return (open_ or live)[-1]

    # -- execution ---------------------------------------------------------------------
    def _target(self, p: Proposal, action: str, actor: str):
        try:
            return self.ctx.inventory.assert_in_scope(p.host)
        except ScopeViolation as e:
            self.ctx.audit.append("action.blocked", actor, {"action": action, "target": p.host, "reason": str(e)},
                                  subject=p.id, outcome="blocked")
            raise

    def _adapter(self, target):
        try:
            return self.ctx.adapter_for(target)
        except KeyError as e:
            raise EngineError(str(e)) from None

    def _audit_step(self, p: Proposal, step: str, details: dict, outcome: str = "ok") -> None:
        self.ctx.audit.append(f"remediation.{step}", "agent", details, subject=p.id, outcome=outcome)

    @staticmethod
    def _copy_files(transport, snap, paths: list[str], *, after: bool) -> list[str]:
        """Best-effort read-only copies of captured files so the diff view has both sides."""
        got = []
        for rp in paths:
            dest = snapshot.file_copy(snap, rp, after=after)
            if not after and dest.exists():
                got.append(rp)
                continue
            try:
                data = transport.read_file(rp)
            except Exception:  # noqa: BLE001  a directory or unreadable path; the adapter's own capture covers it
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            got.append(rp)
        return got

    @staticmethod
    def _close(transport, target) -> None:
        if transport is None:
            return
        try:
            transport.close()
        except Exception:  # noqa: BLE001
            log.warning("transport close failed for %s", target.id)

    def execute(self, proposal_id: str, *, actor: str, simulate_verify_fail: bool = False) -> Proposal:
        gate = self.ctx.gate
        p = gate.get(proposal_id)
        if p.state is not ProposalState.APPROVED:
            gate.start_apply(proposal_id, actor)            # records the rejection and raises IllegalTransition
        target = self._target(p, "execute", actor)
        finding = self._finding(p.finding_id)
        if finding is None:
            raise EngineError(f"finding {p.finding_id} not found in any scan")
        fix = self._fix_for(p, finding)
        adapter = self._adapter(target)
        snap = self.ctx.store.snapshot_dir(p.id)

        gate.start_apply(p.id, actor, before_state_ref=str(snap))     # kill switch guard happens inside the gate
        transport = None
        before: BeforeState | None = None
        applied = False
        try:
            transport = self.ctx.transport_for(target)
            before = adapter.capture_before_state(target, transport, fix, finding, snap)
            snapshot.save_before_state(snap, before)
            copied = self._copy_files(transport, snap, list(before.files), after=False)
            self._audit_step(p, "before_state", {"fix_ref": fix.fix_ref, "files": before.files[:50],
                                                 "copied": len(copied), "dir": str(snap)})
            self.ctx.killswitch.guard(f"remediation.apply:{p.id}", actor)
            ar = adapter.apply(target, transport, fix, finding, before)
            snapshot.save_result(snap, "apply", ar)
            if not ar.ok:
                gate.failed(p.id, "agent", note=f"apply failed: {_short(ar.output)}")
                self._auto_rollback(p, target, adapter, transport, fix, before, "apply reported failure")
                return gate.get(p.id)
            applied = True
            gate.applied(p.id, "agent", note=f"applied {fix.fix_ref} on {target.id}; changed={ar.changed}; "
                                             f"{_short(ar.output, 160)}")
            self._copy_files(transport, snap, list(before.files), after=True)

            if simulate_verify_fail:
                vr = VerifyResult(ok=False, rule_passed=False, health=HealthResult(ok=True),
                                  evidence="verification failure simulated for demonstration")
            else:
                vr = adapter.verify(target, transport, fix, finding)
            snapshot.save_result(snap, "verify", vr)
            self._audit_step(p, "verify", {"ok": vr.ok, "rule_passed": vr.rule_passed, "health": vr.health.ok,
                                           "evidence": _short(vr.evidence), "simulated": simulate_verify_fail},
                             outcome="ok" if vr.ok else "failed")
            if vr.ok:
                gate.verified(p.id, "agent", note=f"rule passes and health ok: {_short(vr.evidence, 200)}")
                return gate.get(p.id)
            why = "simulated verify failure" if simulate_verify_fail else "verify failed"
            gate.failed(p.id, "agent", note=f"{why}: rule_passed={vr.rule_passed} health={vr.health.ok}; "
                                            f"{_short(vr.evidence, 200)}")
            self._auto_rollback(p, target, adapter, transport, fix, before, why)
            return gate.get(p.id)
        except KillSwitchEngaged as e:
            # the guard has already audited the block; stop here and do not touch the host again
            if gate.get(p.id).state in (ProposalState.APPLYING, ProposalState.APPLIED):
                gate.failed(p.id, "agent", note=f"stopped by kill switch: {e}")
            raise
        except (IllegalTransition, PermissionError):
            raise
        except Exception as e:  # noqa: BLE001
            log.exception("execute %s failed", p.id)
            if gate.get(p.id).state in (ProposalState.APPLYING, ProposalState.APPLIED):
                gate.failed(p.id, "agent", note=f"error during {'verify' if applied else 'apply'}: {_short(str(e))}")
            if before is not None and transport is not None:
                self._auto_rollback(p, target, adapter, transport, fix, before, f"error: {_short(str(e), 120)}")
            else:
                self._audit_step(p, "error", {"error": _short(str(e)),
                                              "rollback": "nothing was captured or changed"}, outcome="error")
            return gate.get(p.id)
        finally:
            self._close(transport, target)

    def _auto_rollback(self, p: Proposal, target, adapter, transport, fix: FixEntry, before: BeforeState,
                       reason: str) -> None:
        try:
            self.ctx.killswitch.guard(f"proposal.rolled_back:{p.id}", "agent")
            rr = adapter.rollback(target, transport, fix, before)
            snapshot.save_result(self.ctx.store.snapshot_dir(p.id), "rollback", rr)
        except KillSwitchEngaged:
            self.ctx.audit.append("proposal.rollback_error", "agent", {"reason": reason, "error": "kill switch engaged"},
                                  subject=p.id, outcome="error")
            return
        except Exception as e:  # noqa: BLE001
            log.exception("rollback %s failed", p.id)
            self.ctx.audit.append("proposal.rollback_error", "agent", {"reason": reason, "error": _short(str(e))},
                                  subject=p.id, outcome="error")
            return
        if rr.ok:
            self._copy_files(transport, self.ctx.store.snapshot_dir(p.id), list(before.files), after=True)
            self.ctx.gate.rolled_back(p.id, "agent", note=f"automatic rollback after {reason}: {_short(rr.output, 200)}")
        else:
            self.ctx.audit.append("proposal.rollback_error", "agent", {"reason": reason, "output": _short(rr.output)},
                                  subject=p.id, outcome="error")

    def rollback(self, proposal_id: str, *, actor: str) -> Proposal:
        gate = self.ctx.gate
        p = gate.get(proposal_id)
        if ProposalState.ROLLED_BACK not in TRANSITIONS[p.state]:
            gate.rolled_back(proposal_id, actor)             # records the rejection and raises IllegalTransition
        target = self._target(p, "rollback", actor)
        snap = self.ctx.store.snapshot_dir(p.id)
        before = snapshot.load_before_state(snap)
        if before is None:
            raise EngineError(f"no before-state captured for {p.id}; roll back by hand from the runbook")
        fix = self._fix_for(p, self._finding(p.finding_id))
        adapter = self._adapter(target)
        self.ctx.killswitch.guard(f"proposal.rolled_back:{p.id}", actor)
        transport = self.ctx.transport_for(target)
        try:
            rr = adapter.rollback(target, transport, fix, before)
            snapshot.save_result(snap, "rollback", rr)
            if not rr.ok:
                self.ctx.audit.append("proposal.rollback_error", actor, {"reason": "manual", "output": _short(rr.output)},
                                      subject=p.id, outcome="error")
                raise EngineError(f"rollback of {p.id} failed: {_short(rr.output)}")
            self._copy_files(transport, snap, list(before.files), after=True)
            return gate.rolled_back(p.id, actor, note=f"manual rollback by {actor}: {_short(rr.output, 200)}")
        finally:
            self._close(transport, target)

    def diff(self, proposal_id: str) -> dict:
        p = self.ctx.gate.get(proposal_id)
        snap = self.ctx.store.snapshot_dir(p.id)
        fix = self.ctx.library.get(p.fix_ref)
        before = snapshot.load_before_state(snap)
        files = []
        for rp in (before.files if before else []):
            b = snapshot.read_text(snapshot.file_copy(snap, rp))
            a = snapshot.read_text(snapshot.file_copy(snap, rp, after=True))
            if b is None and a is None:
                continue
            files.append({"path": rp, "before_excerpt": b, "after_excerpt": a, "diff": snapshot.text_diff(b, a, rp)})
        return {
            "proposal": p.to_dict(),
            "fix": fix.to_dict() if fix else snapshot.load_result(snap, "fix"),
            "before_state": before.to_dict() if before else None,
            "apply": snapshot.load_result(snap, "apply"),
            "verify": snapshot.load_result(snap, "verify"),
            "rollback": snapshot.load_result(snap, "rollback"),
            "files": files,
        }
