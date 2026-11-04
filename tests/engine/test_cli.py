import json

from cyberthunder.cli import main

from . import fakes
from .conftest import HOST


def test_cli_scan_propose_apply_diff_rollback(make_ctx, state_dir, capsys):
    ctx = make_ctx(auto_propose=False)                        # writes the inventory
    base = ["--state-dir", str(state_dir), "--actor", "it1.jones"]

    assert main(base + ["scan", "--targets", HOST, "--wait", "--no-propose"]) == 0
    out = capsys.readouterr().out
    assert HOST in out and "done" in out

    assert main(base + ["scans", "list"]) == 0
    scan_id = capsys.readouterr().out.split()[0]
    assert main(base + ["scans", "show", scan_id, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["id"] == scan_id

    finding = next(f for f in ctx.store.load_findings(scan_id) if f.rule_id == fakes.RULE_ROOT_LOGIN)
    assert main(base + ["propose", finding.id]) == 0
    pid = capsys.readouterr().out.split()[0]

    assert main(base + ["apply", pid]) == 2                   # not approved yet
    assert "refused" in capsys.readouterr().err

    assert main(base + ["proposals", "approve", pid, "--note", "ok"]) == 0
    capsys.readouterr()
    assert main(base + ["apply", pid]) == 0
    out = capsys.readouterr().out
    assert "proposal.verified" in out and f"{pid}: verified" in out
    assert "PermitRootLogin no" in fakes.HOSTS[HOST]["files"][fakes.SSHD]

    assert main(base + ["diff", pid]) == 0
    assert "+PermitRootLogin no" in capsys.readouterr().out

    assert main(base + ["rollback", pid]) == 0
    assert f"{pid}: rolled_back" in capsys.readouterr().out
    assert "PermitRootLogin yes" in fakes.HOSTS[HOST]["files"][fakes.SSHD]

    assert main(base + ["audit", "verify"]) == 0


def test_cli_apply_simulated_failure(make_ctx, state_dir, capsys):
    ctx = make_ctx(auto_propose=False)
    base = ["--state-dir", str(state_dir), "--actor", "it1.jones"]
    assert main(base + ["scan", "--targets", HOST, "--no-propose"]) == 0
    # one writer at a time: the audit log caches its head, so open a fresh context after the CLI wrote
    ctx = make_ctx()
    f = next(x for x in ctx.store.load_findings() if x.rule_id == fakes.RULE_ROOT_LOGIN)
    p = ctx.engine.propose(f)
    ctx.gate.approve(p.id, "it1.jones")
    capsys.readouterr()
    assert main(base + ["apply", p.id, "--simulate-verify-fail"]) == 1
    out = capsys.readouterr().out
    assert "proposal.failed" in out and "proposal.rolled_back" in out and "simulated" in out
    assert main(base + ["propose", "no-such-finding"]) == 2
