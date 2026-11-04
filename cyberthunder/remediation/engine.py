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

from typing import TYPE_CHECKING, Iterable

from cyberthunder.control.approvals import Proposal
from cyberthunder.findings.schema import Finding
from cyberthunder.remediation.library import FixEntry

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext


class EngineError(RuntimeError):
    pass


class RemediationEngine:
    def __init__(self, ctx: "AppContext"):
        self.ctx = ctx

    # -- proposals ---------------------------------------------------------------------
    def propose(self, finding: Finding, *, actor: str = "agent", fix: FixEntry | None = None) -> Proposal | None:
        raise NotImplementedError("remediation engine not built yet")

    def auto_propose(self, findings: Iterable[Finding], *, actor: str = "agent") -> list[Proposal]:
        raise NotImplementedError

    def proposal_for_finding(self, finding_id: str) -> Proposal | None:
        """Most recent non-terminal proposal for a finding, else most recent of any state, else None."""
        live = [p for p in self.ctx.gate.list() if p.finding_id == finding_id]
        if not live:
            return None
        terminal = {"denied", "cancelled", "verified", "rolled_back"}
        open_ = [p for p in live if p.state.value not in terminal]
        return (open_ or live)[-1]

    # -- execution ---------------------------------------------------------------------
    def execute(self, proposal_id: str, *, actor: str, simulate_verify_fail: bool = False) -> Proposal:
        raise NotImplementedError

    def rollback(self, proposal_id: str, *, actor: str) -> Proposal:
        raise NotImplementedError

    def diff(self, proposal_id: str) -> dict:
        raise NotImplementedError
