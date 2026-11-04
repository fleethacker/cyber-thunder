"""Inventory CLI: every mutation lands in the audit log and the chain still verifies."""
import json

import pytest

from cyberthunder.audit.chain import verify_file
from cyberthunder.cli import main


@pytest.fixture
def run(state_dir, capsys):
    def _run(*argv):
        rc = main(["--state-dir", str(state_dir), "--actor", "sailor1", *argv])
        out = capsys.readouterr()
        return rc, out.out, out.err
    _run.state_dir = state_dir
    return _run


def _audit(state_dir):
    path = state_dir / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _add(run, tid="web1", *extra):
    return run("targets", "add", "--id", tid, "--name", "Web One", "--type", "linux", "--transport", "ssh",
               "--address", "10.0.0.5", "--port", "22", "--username", "ops", "--credential-ref", "web1",
               "--tag", "dmz", "--tag", "prod", "--option", "critical_services=sshd", "--option", "retries=3", *extra)


def test_add_and_list(run):
    rc, out, _ = _add(run)
    assert rc == 0 and "web1" in out
    rc, out, _ = run("targets", "list")
    assert rc == 0
    assert "web1" in out and "10.0.0.5:22" in out and "dmz,prod" in out and "in" in out
    recs = [r for r in _audit(run.state_dir) if r["action"] == "inventory.add"]
    assert len(recs) == 1 and recs[0]["actor"] == "sailor1" and recs[0]["details"]["target"] == "web1"
    assert verify_file(run.state_dir / "audit.jsonl").ok


def test_list_empty(run):
    rc, out, _ = run("targets", "list")
    assert rc == 0 and "no targets" in out


def test_add_duplicate_and_bad_option_refused(run):
    assert _add(run)[0] == 0
    rc, _, err = _add(run)
    assert rc == 2 and "already exists" in err
    rc, _, err = run("targets", "add", "--id", "x", "--type", "linux", "--option", "novalue")
    assert rc == 2 and "key=value" in err


def test_update_merges_options_and_audits_before_after(run):
    _add(run)
    rc, out, _ = run("targets", "update", "web1", "--address", "10.0.0.9", "--option", "retries=5")
    assert rc == 0
    rec = [r for r in _audit(run.state_dir) if r["action"] == "inventory.update"][-1]
    assert rec["details"]["before"]["address"] == "10.0.0.5"
    assert rec["details"]["after"]["address"] == "10.0.0.9"
    # reload from disk through a fresh context: options merged, not replaced
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext
    t = AppContext(Settings.from_env(state_dir=run.state_dir)).inventory.get("web1")
    assert t.address == "10.0.0.9" and t.options == {"critical_services": "sshd", "retries": 5}
    assert verify_file(run.state_dir / "audit.jsonl").ok


def test_update_unknown_target_refused(run):
    assert run("targets", "update", "nope", "--name", "x")[0] == 2
    assert not [r for r in _audit(run.state_dir) if r["action"] == "inventory.update"]


def test_scope_change_is_audited_with_reason(run):
    _add(run)
    rc, out, _ = run("targets", "scope", "web1", "out", "--reason", "owner pulled it from the exercise")
    assert rc == 0 and "in -> out" in out
    rec = [r for r in _audit(run.state_dir) if r["action"] == "scope.change"][-1]
    assert rec["details"] == {"target": "web1", "before": True, "after": False,
                              "reason": "owner pulled it from the exercise"}
    rc, out, _ = run("targets", "list")
    assert "OUT" in out
    assert verify_file(run.state_dir / "audit.jsonl").ok


def test_scope_requires_reason_and_known_target(run):
    _add(run)
    assert run("targets", "scope", "web1", "out", "--reason", "  ")[0] == 2
    assert run("targets", "scope", "ghost", "in", "--reason", "x")[0] == 2
    assert not [r for r in _audit(run.state_dir) if r["action"] == "scope.change"]


def test_out_of_scope_flag_on_add(run):
    _add(run, "web2", "--out-of-scope")
    rc, out, _ = run("targets", "list")
    assert "OUT" in out


def test_remove(run):
    _add(run)
    rc, out, _ = run("targets", "remove", "web1")
    assert rc == 0
    assert "no targets" in run("targets", "list")[1]
    assert [r for r in _audit(run.state_dir) if r["action"] == "inventory.remove"]
    assert run("targets", "remove", "web1")[0] == 2
    assert verify_file(run.state_dir / "audit.jsonl").ok


def test_discover_refuses_out_of_scope(run):
    _add(run, "web3", "--out-of-scope")
    rc, _, err = run("targets", "discover", "web3")
    assert rc == 2 and "out of scope" in err


def test_import_nessus_without_parser_says_so(run, tmp_path, monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "cyberthunder.parsers.nessus", None)  # forces ImportError
    f = tmp_path / "scan.nessus"
    f.write_text("<x/>", encoding="utf-8")
    rc, _, err = run("targets", "import-nessus", str(f))
    assert rc == 1 and "not available" in err


def test_import_nessus_adds_hosts_out_of_scope(run, tmp_path, monkeypatch):
    import sys
    import types
    mod = types.ModuleType("cyberthunder.parsers.nessus")
    mod.parse_nessus_hosts = lambda path: [{"name": "dc01", "ip": "10.1.1.2", "os": "Windows Server 2019"},
                                           {"name": "sw1", "ip": "10.1.1.3", "os": "Cisco IOS"}]
    monkeypatch.setitem(sys.modules, "cyberthunder.parsers.nessus", mod)
    rc, out, _ = run("targets", "import-nessus", str(tmp_path / "x.nessus"))
    assert rc == 0 and "imported 2 of 2" in out
    listing = run("targets", "list")[1]
    assert "dc01" in listing and "windows" in listing and "OUT" in listing
    assert [r for r in _audit(run.state_dir) if r["action"] == "inventory.import"]
    assert verify_file(run.state_dir / "audit.jsonl").ok
