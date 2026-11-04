import json
import os
import tempfile
import unittest
from pathlib import Path

from cyberthunder.audit.chain import AuditLog, verify_file
from cyberthunder.control.approvals import ApprovalGate, IllegalTransition, ProposalState
from cyberthunder.control.killswitch import KillSwitch, KillSwitchEngaged


class TestAuditChain(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.path = Path(self.td.name) / "audit.jsonl"

    def tearDown(self):
        self.td.cleanup()

    def _fill(self, n=4):
        log = AuditLog(self.path, node="test")
        for i in range(n):
            log.append(f"act{i}", "agent", {"i": i})
        return log

    def test_append_and_verify(self):
        log = self._fill()
        self.assertEqual(len(log), 4)
        r = log.verify()
        self.assertTrue(r.ok, str(r))
        self.assertEqual(r.count, 4)
        self.assertEqual(r.head, log.head)
        recs = list(log.records())
        self.assertEqual(recs[0]["prev_hash"], "0" * 64)
        self.assertEqual(recs[1]["prev_hash"], recs[0]["hash"])

    def test_reopen_continues_chain(self):
        self._fill(2)
        log2 = AuditLog(self.path, node="test")
        rec = log2.append("later", "sailor1")
        self.assertEqual(rec["seq"], 3)
        self.assertTrue(verify_file(self.path).ok)

    def test_modified_record_detected(self):
        self._fill()
        lines = self.path.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[1])
        rec["actor"] = "attacker"
        lines[1] = json.dumps(rec, sort_keys=True)
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r = verify_file(self.path)
        self.assertFalse(r.ok)
        self.assertEqual(r.bad_seq, 2)
        self.assertIn("modified", r.reason)

    def test_deleted_record_detected(self):
        self._fill()
        lines = self.path.read_text(encoding="utf-8").splitlines()
        del lines[2]
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r = verify_file(self.path)
        self.assertFalse(r.ok)
        self.assertEqual(r.bad_seq, 3)

    def test_truncated_tail_is_still_consistent_prefix(self):
        # Removing the LAST record cannot be caught by the chain alone; the head hash must be
        # published out-of-band (UI banner / report footer). Document that behaviour here.
        log = self._fill()
        head_before = log.head
        lines = self.path.read_text(encoding="utf-8").splitlines()[:-1]
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r = verify_file(self.path)
        self.assertTrue(r.ok)
        self.assertNotEqual(r.head, head_before)


class TestKillSwitch(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.audit = AuditLog(Path(self.td.name) / "audit.jsonl", node="test")
        self.ks = KillSwitch(Path(self.td.name) / "state", self.audit)
        os.environ.pop("CT_KILL", None)

    def tearDown(self):
        os.environ.pop("CT_KILL", None)
        self.td.cleanup()

    def test_default_clear(self):
        self.assertFalse(self.ks.is_engaged())
        self.ks.guard("noop")  # must not raise

    def test_engage_blocks_and_logs(self):
        self.ks.engage("sailor1", "demo")
        self.assertTrue(self.ks.is_engaged())
        with self.assertRaises(KillSwitchEngaged):
            self.ks.guard("apply:fix-1")
        actions = [r["action"] for r in self.audit.records()]
        self.assertEqual(actions, ["killswitch.engage", "action.blocked"])
        self.ks.release("sailor1")
        self.assertFalse(self.ks.is_engaged())
        self.ks.guard("apply:fix-1")

    def test_sentinel_and_env(self):
        self.ks.sentinel.touch()
        self.assertEqual(self.ks.status()["via"][:8], "sentinel")
        self.ks.release("sailor1")
        self.assertFalse(self.ks.sentinel.exists())
        os.environ["CT_KILL"] = "1"
        self.assertEqual(self.ks.status()["via"], "env:CT_KILL")

    def test_corrupt_state_file_fails_closed(self):
        self.ks.state_file.write_text("{not json", encoding="utf-8")
        self.assertTrue(self.ks.is_engaged())


class TestApprovalGate(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        root = Path(self.td.name)
        self.audit = AuditLog(root / "audit.jsonl", node="test")
        self.ks = KillSwitch(root / "state", self.audit)
        self.store = root / "proposals.json"
        self.gate = ApprovalGate(self.store, self.audit, self.ks)
        os.environ.pop("CT_KILL", None)

    def tearDown(self):
        self.td.cleanup()

    def _propose(self):
        return self.gate.propose(finding_id="abc", host="acd-target-01", title="Disable SSH root login",
                                 fix_ref="ssg:sshd_disable_root_login", fix_preview="PermitRootLogin no",
                                 rollback_plan="restore sshd_config from before-state", risk="CAT II ...",
                                 citations=["RHEL-09-255045", "CCI-000366"])

    def test_happy_path(self):
        p = self._propose()
        self.assertEqual(p.state, ProposalState.PROPOSED)
        self.gate.approve(p.id, "sailor1", "ok")
        self.gate.start_apply(p.id, before_state_ref="snap-1")
        self.gate.applied(p.id)
        self.gate.verified(p.id, note="rescan pass")
        p = self.gate.get(p.id)
        self.assertEqual(p.state, ProposalState.VERIFIED)
        self.assertEqual(p.decided_by, "sailor1")
        self.assertEqual(p.before_state_ref, "snap-1")
        self.assertEqual([h["state"] for h in p.history],
                         ["proposed", "approved", "applying", "applied", "verified"])
        self.assertTrue(self.audit.verify().ok)

    def test_agent_cannot_approve(self):
        p = self._propose()
        with self.assertRaises(PermissionError):
            self.gate.approve(p.id, "agent")
        with self.assertRaises(PermissionError):
            self.gate.deny(p.id, "LLM")
        self.assertEqual(self.gate.get(p.id).state, ProposalState.PROPOSED)
        self.assertEqual(list(self.audit.records())[-1]["outcome"], "rejected")

    def test_cannot_apply_without_approval(self):
        p = self._propose()
        with self.assertRaises(IllegalTransition):
            self.gate.start_apply(p.id)
        with self.assertRaises(IllegalTransition):
            self.gate.applied(p.id)

    def test_deny_is_terminal(self):
        p = self._propose()
        self.gate.deny(p.id, "sailor1", "not now")
        with self.assertRaises(IllegalTransition):
            self.gate.approve(p.id, "sailor1")

    def test_killswitch_blocks_apply_and_rollback(self):
        p = self._propose()
        self.gate.approve(p.id, "sailor1")
        self.ks.engage("sailor2", "stop everything")
        with self.assertRaises(KillSwitchEngaged):
            self.gate.start_apply(p.id)
        self.assertEqual(self.gate.get(p.id).state, ProposalState.APPROVED)
        self.ks.release("sailor2")
        self.gate.start_apply(p.id)
        self.gate.failed(p.id, note="verify failed")
        self.ks.engage("sailor2")
        with self.assertRaises(KillSwitchEngaged):
            self.gate.rolled_back(p.id)
        self.ks.release("sailor2")
        self.gate.rolled_back(p.id)
        self.assertEqual(self.gate.get(p.id).state, ProposalState.ROLLED_BACK)

    def test_persistence(self):
        p = self._propose()
        self.gate.approve(p.id, "sailor1")
        g2 = ApprovalGate(self.store, self.audit, self.ks)
        self.assertEqual(g2.get(p.id).state, ProposalState.APPROVED)
        self.assertEqual(len(g2.list(ProposalState.APPROVED)), 1)


if __name__ == "__main__":
    unittest.main()
