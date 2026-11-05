"""Conservative ordering when scanner observations and rollback events overlap."""
from dataclasses import replace

import pytest

from cyberthunder.control.approvals import Proposal, ProposalState
from cyberthunder.findings.current import CurrentFindings
from cyberthunder.findings.schema import Finding, Status

ROLLBACK = "2026-11-05T12:00:00+00:00"


def observation(status="not_a_finding", collected_at="2026-11-05T11:00:00Z", **kwargs):
    return Finding(host="host", source="scanner", rule_id="rule", title="Rule", severity="high",
                   status=status, collected_at=collected_at, evidence="scanner's unchanged evidence", **kwargs)


def reverted(finding, ts=ROLLBACK):
    return Proposal(finding_id=finding.id, host=finding.host, title=finding.title, fix_ref="fix",
                    fix_preview="apply", rollback_plan="restore", risk="risk", state=ProposalState.ROLLED_BACK,
                    history=[{"state": "verified", "ts": "2026-11-04T12:00:00Z"},
                             {"state": "rolled_back", "ts": ts}])


@pytest.mark.parametrize("collected_at,expected", [
    ("2026-11-05T11:59:59Z", "not_reviewed"),
    (ROLLBACK, "not_reviewed"),
    ("2026-11-05T07:00:00-05:00", "not_reviewed"),
    ("2026-11-05T12:00:00.000001Z", "not_a_finding"),
    ("2026-11-05T12:00:01Z", "not_a_finding"),
    ("2026-11-05T12:00:01", "not_reviewed"),
    ("invalid", "not_reviewed"),
    (None, "not_reviewed"),
])
def test_observation_must_be_strictly_after_rollback(collected_at, expected):
    finding = observation(collected_at=collected_at)
    before = finding.to_dict()
    result = CurrentFindings([reverted(finding)]).assess(finding)
    assert result.finding.status.value == expected
    assert finding.to_dict() == before
    assert result.finding.evidence == finding.evidence
    assert result.needs_rescan is (expected == "not_reviewed")


@pytest.mark.parametrize("status", list(Status))
def test_only_prior_clean_results_become_unknown(status):
    finding = observation(status=status)
    result = CurrentFindings([reverted(finding)]).assess(finding)
    expected = Status.NOT_REVIEWED if status in (Status.NOT_A_FINDING, Status.NOT_APPLICABLE) else status
    assert result.finding.status == expected and result.needs_rescan


@pytest.mark.parametrize("ts", [None, "", "invalid", "2026-11-05T12:00:00"])
def test_unknown_rollback_time_never_establishes_current_pass(ts):
    finding = observation(collected_at="2026-11-06T12:00:00Z")
    assert CurrentFindings([reverted(finding, ts)]).assess(finding).needs_rescan


def test_reimporting_old_observation_is_not_fresh_evidence():
    finding = observation(collected_at="2026-11-06T12:00:00Z",
                          collection_provenance={"observed_at": "2026-11-04T12:00:00Z"})
    result = CurrentFindings([reverted(finding)]).assess(finding)
    assert result.finding.status == Status.NOT_REVIEWED


def test_other_host_or_finding_is_unaffected():
    finding = observation()
    p = reverted(finding)
    for other in (replace(p, host="other"), replace(p, finding_id="other")):
        result = CurrentFindings([other]).assess(finding)
        assert result.finding == finding and result.rollback is None


def test_new_proposal_cannot_hide_rollback_or_restore_a_stale_pass():
    finding = observation()
    p = reverted(finding)
    newer = replace(p, id="newer", state=ProposalState.VERIFIED,
                    history=[{"state": "verified", "ts": "2026-11-05T13:00:00Z"}])
    views = CurrentFindings([p, newer])
    assert views.assess(finding).finding.status == Status.NOT_REVIEWED
    old_failure = replace(finding, status=Status.OPEN)
    assert views.assess(old_failure).remediated["proposal_id"] == newer.id
    fresh_failure = replace(old_failure, collected_at="2026-11-05T14:00:00Z")
    assert views.assess(fresh_failure).finding.status == Status.OPEN
    assert views.assess(fresh_failure).remediated is None


@pytest.mark.parametrize("state", [ProposalState.PROPOSED, ProposalState.FAILED, ProposalState.DENIED])
def test_newer_unverified_proposal_does_not_revive_an_older_closure(state):
    finding = observation(status="open")
    verified = replace(reverted(finding), state=ProposalState.VERIFIED,
                       history=[{"state": "verified", "ts": ROLLBACK}])
    newer = replace(verified, id="newer", state=state, history=[])
    assert CurrentFindings([verified, newer]).assess(finding).finding.status == Status.OPEN


def test_unmatched_mutation_is_explicitly_uncertain_even_with_unreadable_result():
    finding = observation()
    proposal = reverted(finding)
    current = CurrentFindings([proposal], {proposal.id: {"ok": False, "finished_at": None}})
    current.rollbacks[(finding.id, finding.host)].append(
        {"proposal_id": proposal.id, "ok": None, "finished_at": None, "uncertain": True, "attempt_id": "attempt"})
    view = current.assess(finding)
    assert view.finding.status == Status.NOT_REVIEWED and view.needs_rescan
    assert view.rollback["uncertain"] and view.rollback["ok"] is None
