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

    def test_truncated_tail_is_caught_by_the_head_checkpoint(self):
        # The chain alone cannot see the LAST record removed; the <log>.head checkpoint written on every
        # append can. Without the checkpoint file the log still reads as a consistent prefix.
        log = self._fill()
        head_before = log.head
        lines = self.path.read_text(encoding="utf-8").splitlines()[:-1]
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r = verify_file(self.path)
        self.assertFalse(r.ok)
        self.assertEqual(r.checkpoint, "truncated")
        self.path.with_name(self.path.name + ".head").unlink()
        r = verify_file(self.path)
        self.assertTrue(r.ok)
        self.assertEqual(r.checkpoint, "missing")
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

    def test_one_live_proposal_per_finding_under_the_lock(self):
        kw = dict(finding_id="abc", host="acd-target-01", title="t", fix_ref="ssg:x", fix_preview="p",
                  rollback_plan="r", risk="k", citations=[])
        first = self.gate.propose(one_live_per_finding=True, **kw)
        again = self.gate.propose(one_live_per_finding=True, **kw)
        self.assertEqual(first.id, again.id)                                  # still live: handed back
        other = ApprovalGate(self.store, self.audit, self.ks)                  # another process, same file
        self.assertEqual(other.propose(one_live_per_finding=True, **kw).id, first.id)
        self.assertEqual(len(self.gate.list()), 1)
        self.gate.deny(first.id, "sailor1", "no")
        fresh = self.gate.propose(one_live_per_finding=True, **kw)
        self.assertNotEqual(fresh.id, first.id)                               # terminal: a new one is made
        self.assertEqual(len(self.gate.list()), 2)
        self.assertEqual(len({p.id for p in (fresh, self.gate.propose(**kw))}), 2)   # without the flag: as before
        self.assertFalse(list(self.store.parent.glob("*.tmp")))              # the per-process temp file is gone
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


class _GateFixture(unittest.TestCase):
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


class _KillFixture(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.audit = AuditLog(Path(self.td.name) / "audit.jsonl", node="test")
        self.ks = KillSwitch(Path(self.td.name) / "state", self.audit)
        os.environ.pop("CT_KILL", None)

    def tearDown(self):
        os.environ.pop("CT_KILL", None)
        self.td.cleanup()


class _AuditFixture(unittest.TestCase):
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


class TestHumanOnlyActors(_GateFixture):
    MACHINE_SPELLINGS = [" agent", "agent:planner", "llm-1", "AGENT\t", "system", "agent-svc", "", "   "]

    def test_machine_spellings_cannot_approve_or_deny(self):
        p = self._propose()
        for actor in self.MACHINE_SPELLINGS:
            with self.assertRaises(PermissionError, msg=repr(actor)):
                self.gate.approve(p.id, actor)
            with self.assertRaises(PermissionError, msg=repr(actor)):
                self.gate.deny(p.id, actor)
        self.assertEqual(self.gate.get(p.id).state, ProposalState.PROPOSED)
        self.assertEqual(list(self.audit.records())[-1]["outcome"], "rejected")

    def test_forged_policy_actor_is_refused_without_a_signed_policy(self):
        p = self._propose()
        for actor in ("policy:nobody", "Policy:CO"):
            with self.assertRaises(PermissionError, msg=actor):
                self.gate.approve(p.id, actor)
        self.assertEqual(self.gate.get(p.id).state, ProposalState.PROPOSED)

    def test_human_names_still_approve_and_are_stripped(self):
        p = self._propose()
        self.gate.approve(p.id, "  it1.jones ")
        self.assertEqual(self.gate.get(p.id).decided_by, "it1.jones")

    def test_approve_by_policy_needs_an_enabled_human_signed_policy(self):
        from cyberthunder.control.policy import AutomationPolicy
        p = self._propose()
        machine = AutomationPolicy(enabled=True, signed_by="agent")
        with self.assertRaises(PermissionError):
            self.gate.approve_by_policy(p.id, machine)
        with self.assertRaises(PermissionError):
            self.gate.approve_by_policy(p.id, AutomationPolicy(enabled=False, signed_by="cdr.ops"))
        self.assertEqual(self.gate.get(p.id).state, ProposalState.PROPOSED)
        pol = AutomationPolicy()
        pol.sign("cdr.ops", "standing approval")
        self.assertEqual(self.gate.approve_by_policy(p.id, pol).decided_by, "policy:cdr.ops")


class TestGateAcrossProcesses(_GateFixture):
    """Two gates on one proposals file stand in for the API server and a CLI command."""

    def _other(self):
        return ApprovalGate(self.store, self.audit, self.ks)

    def test_decisions_from_both_contexts_survive(self):
        x, y = self._propose(), self._propose()
        cli = self._other()
        cli.deny(x.id, "sailor2", "not on this ship")
        self.gate.approve(y.id, "sailor1")
        fresh = self._other()
        self.assertEqual(fresh.get(x.id).state, ProposalState.DENIED)
        self.assertEqual(fresh.get(y.id).state, ProposalState.APPROVED)
        # the stale context sees the other process's denial and cannot approve over it
        with self.assertRaises(IllegalTransition):
            self.gate.approve(x.id, "sailor1")

    def test_stale_context_cannot_apply_twice(self):
        p = self._propose()
        self.gate.approve(p.id, "sailor1")
        other = self._other()
        self.gate.start_apply(p.id)
        with self.assertRaises(IllegalTransition):
            other.start_apply(p.id)

    def test_audit_failure_leaves_proposal_unchanged(self):
        p = self._propose()
        real = self.audit.append

        def flaky(action, *a, **kw):
            if action == "proposal.approved":
                raise TimeoutError("audit log lock busy")
            return real(action, *a, **kw)

        self.audit.append = flaky
        try:
            with self.assertRaises(TimeoutError):
                self.gate.approve(p.id, "sailor1")
        finally:
            self.audit.append = real
        self.assertEqual(self.gate.get(p.id).state, ProposalState.PROPOSED)
        self.assertIsNone(self.gate.get(p.id).decided_by)
        self.assertEqual(self._other().get(p.id).state, ProposalState.PROPOSED)
        with self.assertRaises(IllegalTransition):
            self.gate.start_apply(p.id)

    def test_failed_and_rolled_back_edges_carry_their_outcome(self):
        p = self._propose()
        self.gate.approve(p.id, "sailor1")
        self.gate.start_apply(p.id)
        self.gate.failed(p.id, note="apply failed")
        self.gate.rolled_back(p.id)
        out = {r["action"]: r["outcome"] for r in self.audit.records()}
        self.assertEqual(out["proposal.failed"], "failed")
        self.assertEqual(out["proposal.rolled_back"], "reverted")
        self.assertEqual(out["proposal.approved"], "ok")


class TestKillSwitchAuthority(_KillFixture):
    def test_machine_cannot_release(self):
        self.ks.engage("sailor1", "drill")
        for actor in ("agent", " agent", "llm-1", "policy:cdr", ""):
            with self.assertRaises(PermissionError, msg=repr(actor)):
                self.ks.release(actor, "I want to continue")
        self.assertTrue(self.ks.is_engaged())
        last = list(self.audit.records())[-1]
        self.assertEqual((last["action"], last["outcome"]), ("killswitch.release", "rejected"))

    def test_release_while_env_holds_is_partial(self):
        self.ks.engage("sailor1")
        os.environ["CT_KILL"] = "1"
        data = self.ks.release("sailor1", "drill over")
        self.assertTrue(data["engaged"])
        self.assertTrue(self.ks.is_engaged())
        last = list(self.audit.records())[-1]
        self.assertEqual(last["outcome"], "partial")
        self.assertEqual(last["details"]["still_engaged_via"], "env:CT_KILL")

    def test_machine_may_still_engage(self):
        self.ks.engage("agent", "anomaly")
        self.assertTrue(self.ks.is_engaged())


class TestPolicySigner(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        os.environ.pop("CT_KILL", None)

    def tearDown(self):
        self.td.cleanup()

    def test_sign_refuses_machine(self):
        from cyberthunder.control.policy import AutomationPolicy
        for actor in ("agent", "llm-1", "policy:cdr", ""):
            with self.assertRaises(PermissionError, msg=actor):
                AutomationPolicy().sign(actor, "auto")

    def test_evaluate_refuses_machine_signer(self):
        from types import SimpleNamespace
        from cyberthunder.control.policy import AutomationPolicy, PolicyRule, evaluate
        pol = AutomationPolicy(enabled=True, signed_by="agent", rules=[PolicyRule(name="any", max_disruption="high")])
        d = evaluate(pol, SimpleNamespace(), SimpleNamespace(), SimpleNamespace(in_scope=True))
        self.assertFalse(d.auto_eligible)
        self.assertIn("not a named person", d.reasons[0])

    def test_context_refuses_machine_signed_policy(self):
        from cyberthunder.config import Settings
        from cyberthunder.context import AppContext
        from cyberthunder.control.policy import AutomationPolicy, PolicyRule
        ctx = AppContext(Settings.from_env(state_dir=str(Path(self.td.name) / "state")))
        pol = AutomationPolicy(enabled=True, signed_by="agent", rules=[PolicyRule(name="any")])
        with self.assertRaises(PermissionError):
            ctx.save_policy(pol, "agent")
        with self.assertRaises(PermissionError):
            ctx.save_policy(pol, "cdr.ops")      # human saving, but the policy itself names a machine signer
        self.assertFalse(ctx.store.policy.exists())
        last = list(ctx.audit.records())[-1]
        self.assertEqual((last["action"], last["outcome"]), ("policy.rejected", "rejected"))

    def test_cli_refuses_policy_actor(self):
        from cyberthunder import cli
        from cyberthunder.config import Settings
        from cyberthunder.context import AppContext
        state = str(Path(self.td.name) / "state")
        ctx = AppContext(Settings.from_env(state_dir=state))
        p = ctx.gate.propose(finding_id="f", host="h", title="t", fix_ref="x", fix_preview="x",
                             rollback_plan="x", risk="x")
        rc = cli.main(["--state-dir", state, "--actor", "policy:CO", "proposals", "approve", p.id])
        self.assertEqual(rc, 2)
        self.assertEqual(ctx.gate.get(p.id).state, ProposalState.PROPOSED)


class TestAuditTruncation(_AuditFixture):
    def test_tail_truncation_detected_by_checkpoint(self):
        self._fill(5)
        lines = self.path.read_text(encoding="utf-8").splitlines()[:-3]
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r = verify_file(self.path)
        self.assertFalse(r.ok)
        self.assertEqual(r.checkpoint, "truncated")
        self.assertTrue(str(r).startswith("TRUNCATED"), str(r))

    def test_checkpoint_matches_on_clean_log(self):
        self._fill(3)
        r = verify_file(self.path)
        self.assertTrue(r.ok, str(r))
        self.assertEqual(r.checkpoint, "matches")
        self.assertIn("checkpoint matches", str(r))


class TestInventoryAcrossProcesses(unittest.TestCase):
    def setUp(self):
        from cyberthunder.inventory.targets import Inventory, Target
        self.td = tempfile.TemporaryDirectory()
        self.path = Path(self.td.name) / "targets.yaml"
        inv = Inventory(self.path, [Target(id="sim-linux-01", name="a", asset_type="linux", transport="fixture"),
                                    Target(id="sim-linux-02", name="b", asset_type="linux", transport="fixture")])
        inv.save()
        self.Inventory = Inventory

    def tearDown(self):
        self.td.cleanup()

    def test_scope_out_elsewhere_holds_and_survives_a_stale_save(self):
        from cyberthunder.inventory.targets import ScopeViolation
        api = self.Inventory.load(self.path)
        api.assert_in_scope("sim-linux-01")
        cli = self.Inventory.load(self.path)
        cli.update("sim-linux-01", in_scope=False)
        cli.save()
        with self.assertRaises(ScopeViolation):
            api.assert_in_scope("sim-linux-01")
        # the long-lived process scans another host and saves; the scope-out must stay
        api.get("sim-linux-02").last_scan = "2026-11-04T10:00:00Z"
        api.save()
        fresh = self.Inventory.load(self.path)
        self.assertFalse(fresh.get("sim-linux-01").in_scope)
        self.assertEqual(fresh.get("sim-linux-02").last_scan, "2026-11-04T10:00:00Z")

    def test_stale_save_does_not_undo_a_scope_out_it_never_read(self):
        api = self.Inventory.load(self.path)
        api.get("sim-linux-02").notes = "touched"
        cli = self.Inventory.load(self.path)
        cli.update("sim-linux-01", in_scope=False)
        cli.save()
        api.save()      # no read in between
        self.assertFalse(self.Inventory.load(self.path).get("sim-linux-01").in_scope)


class TestCitationIds(unittest.TestCase):
    def test_stig_ids_with_alphabetic_middle_segment(self):
        from cyberthunder.findings.schema import extract_references
        refs = extract_references(["WN11-SO-000010 CISC-ND-000010 CNTR-K8-000360 RHEL-09-255045 "
                                   "CVE-2024-6387 V-257777 CCI-000366"])
        by = {(r.system, r.id) for r in refs}
        for sid in ("WN11-SO-000010", "CISC-ND-000010", "CNTR-K8-000360", "RHEL-09-255045"):
            self.assertIn(("stig_id", sid), by)
        self.assertIn(("cve", "CVE-2024-6387"), by)
        self.assertIn(("group", "V-257777"), by)
        self.assertFalse(any(r.system == "stig_id" and r.id.startswith(("CVE", "CCI")) for r in refs))


class TestSSHCredentialRef(unittest.TestCase):
    def _target(self, ref):
        from cyberthunder.inventory.targets import Target
        return Target(id="h", name="h", asset_type="linux", transport="ssh", address="192.0.2.10", credential_ref=ref)

    def tearDown(self):
        os.environ.pop("CT_CRED_RANGE_LINUX", None)

    def test_bare_env_name_is_not_a_password(self):
        from cyberthunder.transport.ssh import SSHTransport
        self.assertTrue(os.environ.get("PATH"))
        t = SSHTransport.from_target(self._target("PATH"))
        self.assertIsNone(t._password)

    def test_ct_cred_is_used(self):
        from cyberthunder.transport.ssh import SSHTransport
        os.environ["CT_CRED_RANGE_LINUX"] = "range-test-value"
        self.assertEqual(SSHTransport.from_target(self._target("RANGE_LINUX"))._password, "range-test-value")

    def test_malformed_ref_is_refused(self):
        from cyberthunder.transport.base import TransportError
        from cyberthunder.transport.ssh import SSHTransport
        with self.assertRaises(TransportError):
            SSHTransport.from_target(self._target("no such/ref $(x)"))


if __name__ == "__main__":
    unittest.main()
