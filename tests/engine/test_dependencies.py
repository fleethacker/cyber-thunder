"""Dependency collection contracts on both state backends, entirely with offline fixtures."""
from copy import deepcopy
import json

import pytest

from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.findings.schema import Finding
from cyberthunder.inventory.targets import ScopeViolation, Target
from cyberthunder.remediation import dependencies as dep, dependencies_io as io
from cyberthunder.remediation.dependencies_services import systemd_command, windows_command
from cyberthunder.remediation.engine import EngineError, fix_digest
from cyberthunder.remediation.library import FixEntry, FixLibrary
from cyberthunder.transport.fixture import FixtureTransport

from .test_plan import forbid_side_effects, persist, stored_state

ACTOR = "Joshua"
HOST = "dependency-host"
SYSTEMD = """Id=sshd.service
LoadState=loaded
ActiveState=active
Requires=network.target sshd-keygen.target
Wants=system.slice
RequiredBy=application.service
WantedBy=multi-user.target
Environment=PASSWORD=do-not-share
ExecStart=/bin/secret --token=do-not-share
"""
WINDOWS = {"name": "WinRM", "status": "Running", "required": [{"name": "RpcSs", "status": "Running"}],
           "dependents": [{"name": "ManagementApp", "status": "Running"}],
           "password": "do-not-share", "command_line": "do-not-share"}


def seed(ctx, tmp_path, *, asset="linux", services=None, output=None, fix=None, tags=None):
    names = services if services is not None else (["sshd"] if asset == "linux" else ["WinRM"])
    root = tmp_path / "dependency-fixtures"
    root.mkdir(exist_ok=True)
    ctx.inventory.add(Target(HOST, "Dependency fixture", asset, transport="fixture",
                             address="192.0.2.99", username="private-user", credential_ref="private-ref",
                             options={"fixture_dir": str(root), "critical_services": names,
                                      "credential": "private-option"}))
    ctx.inventory.save()
    if fix is None:
        fix = FixEntry("dependency:test", "Dependency test", asset, ["dependency:rule"],
                       kind="powershell" if asset == "windows" else "script",
                       payload="must-not-execute --secret=payload-private",
                       restarts_services=names, reboot=True, reversible=False,
                       before_state={"files": ["/etc/ssh/sshd_config"], "commands": {"untrusted": "must-not-execute"}},
                       verify={"commands": {"untrusted": "must-not-execute"}})
    ctx.library = FixLibrary([fix])
    finding = Finding(host=HOST, source="fixture", rule_id=fix.applies_to[0], title="Dependency test",
                      severity="high", status="open", asset_type=asset, fix_ref=fix.fix_ref, tags=tags or [])
    persist(ctx, [finding], "dependencies-scan")
    proposal = ctx.engine.propose(finding, actor=ACTOR)
    entries = []
    if asset == "linux" and names == ["sshd"]:
        entries = [{"match": systemd_command("sshd.service"), "stdout": SYSTEMD if output is None else output}]
    elif asset == "windows" and names == ["WinRM"]:
        entries = [{"match": windows_command("WinRM"), "stdout": json.dumps(WINDOWS) if output is None else output}]
    (root / "commands.json").write_text(json.dumps(entries), encoding="utf-8")
    return proposal, fix, root, finding


def wire(ctx, monkeypatch, root):
    calls = []
    transport = FixtureTransport(root)
    transport.closed = False
    monkeypatch.setattr(transport, "close", lambda: setattr(transport, "closed", True))
    forbid_side_effects(monkeypatch, ctx)
    monkeypatch.setattr(ctx, "transport_for", lambda target: transport)
    original = io.read_command

    def observe(t, command, *, timeout, guard):
        assert 0 < timeout <= io.CALL_TIMEOUT
        calls.append(command)
        return original(t, command, timeout=timeout, guard=guard)

    monkeypatch.setattr(io, "read_command", observe)
    return calls, transport


def test_systemd_relations_risks_sanitization_and_read_only(ctx, tmp_path, monkeypatch):
    proposal, fix, root, _ = seed(ctx, tmp_path)
    before, audit_start = stored_state(ctx), len(ctx.audit)
    calls, transport = wire(ctx, monkeypatch, root)
    result = dep.collect_dependencies(ctx.engine, proposal.id, actor=" Joshua ")
    assert stored_state(ctx) == before and transport.closed
    assert not (root / "missing.log").exists()
    assert calls == ["systemctl show --no-pager --property=Id,LoadState,ActiveState,Requires,Wants,RequiredBy,WantedBy -- sshd.service"]
    assert set(result) == {"version", "generated_at", "proposal_id", "target_id", "target_binding_sha256", "fix_sha256",
                           "evidence_sha256", "mode", "complete", "evidence", "dependencies", "risks", "unknowns",
                           "required_checks", "rollback_limits"}
    assert result["fix_sha256"] == fix_digest(fix)
    assert result["target_binding_sha256"] == dep.target_binding_sha256(ctx.inventory.get(HOST))
    assert result["evidence_sha256"] == dep.evidence_digest(result)
    assert result["mode"] == "live" and result["complete"] is False
    edges = {(e["from"], e["to"], e["relation"]) for e in result["dependencies"]}
    assert ("sshd.service", "network.target", "requires") in edges
    assert ("application.service", "sshd.service", "requires") in edges
    assert ("multi-user.target", "sshd.service", "wants") in edges
    assert {r["id"].rsplit("-", 1)[0] for r in result["risks"]} >= {
        "management-access", "declared-disruption", "rollback-limit", "service-dependents", "critical-service"}
    ids = {e["id"] for e in result["evidence"]}
    assert all(set(r["evidence_ids"]) <= ids and r["deterministic"] for r in result["risks"])
    assert all(set(e["evidence_ids"]) <= ids for e in result["dependencies"])
    evidence = next(e for e in result["evidence"] if e["kind"] == "systemd")
    assert evidence["source"] == "simulated-fixture:systemd"
    records = list(ctx.audit.records())[audit_start:]
    assert len(records) == 1 and records[0]["actor"] == ACTOR
    assert records[0]["action"] == "remediation.dependencies"
    text = json.dumps([result, records])
    for private in ("do-not-share", "payload-private", "private-user", "private-ref", "private-option", "192.0.2.99", "Environment", "ExecStart"):
        assert private not in text
    assert "authenticated identity" in " ".join(result["unknowns"])
    assert "not a full list" in " ".join(result["rollback_limits"])


def test_windows_required_and_dependent_service_status(ctx, tmp_path, monkeypatch):
    proposal, _, root, _ = seed(ctx, tmp_path, asset="windows")
    calls, _ = wire(ctx, monkeypatch, root)
    result = dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)
    facts = next(e["facts"] for e in result["evidence"] if e["kind"] == "windows-service")
    assert facts == {k: WINDOWS[k] for k in ("name", "status", "required", "dependents")}
    assert any(e["from"] == "ManagementApp" and e["to"] == "WinRM" for e in result["dependencies"])
    assert len(calls) == 1 and "Get-Service -Name 'WinRM'" in calls[0]
    assert "Select-Object -First 33" in calls[0]
    assert "do-not-share" not in json.dumps(result)


@pytest.mark.parametrize("live", [False, True])
@pytest.mark.parametrize("problem", ["actor", "kill", "scope", "missing", "fix", "asset"])
def test_preflight_guards_do_not_open_transport(ctx, tmp_path, monkeypatch, problem, live):
    proposal, fix, _, _ = seed(ctx, tmp_path)
    if problem == "kill":
        monkeypatch.setenv("CT_KILL", "1")
    elif problem == "scope":
        ctx.inventory.get(HOST).in_scope = False
    elif problem == "missing":
        ctx.inventory.remove(HOST)
    elif problem == "fix":
        fix.before_state["files"].append("changed")
    elif problem == "asset":
        ctx.inventory.get(HOST).asset_type = "windows"
    forbid_side_effects(monkeypatch, ctx)
    with pytest.raises((PermissionError, KillSwitchEngaged, EngineError)):
        dep.collect_dependencies(ctx.engine, proposal.id, actor="agent" if problem == "actor" else ACTOR, live=live)


@pytest.mark.parametrize("when", ["factory", "read", "close"])
@pytest.mark.parametrize("change", ["scope", "kill", "address", "options", "fix"])
def test_mid_collection_guard_discards_packet(ctx, tmp_path, monkeypatch, when, change):
    proposal, fix, root, _ = seed(ctx, tmp_path)
    calls = []
    transport = FixtureTransport(root)

    def mutate():
        target = ctx.inventory.get(HOST)
        if change == "scope":
            target.in_scope = False
        elif change == "kill":
            monkeypatch.setenv("CT_KILL", "1")
        elif change == "address":
            target.address = "192.0.2.100"
        elif change == "options":
            target.options["context"] = "changed-context"
        else:
            fix.payload += "changed"

    def factory(target):
        if when == "factory":
            mutate()
        return transport

    original = io.read_command

    def read(*args, **kwargs):
        calls.append(args[1])
        if when == "read":
            mutate()
        return original(*args, **kwargs)

    monkeypatch.setattr(ctx, "transport_for", factory)
    monkeypatch.setattr(io, "read_command", read)
    if when == "close":
        monkeypatch.setattr(transport, "close", mutate)
    with pytest.raises((ScopeViolation, KillSwitchEngaged, EngineError)):
        dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)
    assert len(calls) == (0 if when == "factory" else 1)
    assert not any(r["action"] == "remediation.dependencies" for r in ctx.audit.records())


@pytest.mark.parametrize("asset,bad", [("linux", "sshd;touch /tmp/pwn"), ("linux", "--all"),
                                      ("linux", "sshd.service\nwhoami"), ("linux", "a" * 256),
                                      ("windows", "WinRM';Remove-Item C:\\*;#"), ("windows", "*")])
def test_service_name_injection_never_reaches_transport(ctx, tmp_path, monkeypatch, asset, bad):
    proposal, _, _, _ = seed(ctx, tmp_path, asset=asset, services=[bad])
    forbid_side_effects(monkeypatch, ctx)
    result = dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)
    assert bad not in json.dumps(result)
    assert not result["dependencies"]
    assert any("invalid" in s for s in result["unknowns"])


@pytest.mark.parametrize("asset,output", [("linux", "Id=sshd.service\n"), ("linux", SYSTEMD.replace("active", "surprise")),
                                         ("linux", SYSTEMD.replace("network.target", "x;evil")),
                                         ("linux", "x" * (io.MAX_OUTPUT + 1)), ("windows", "not json"),
                                         ("windows", '{"name":"different","status":"Running"}'),
                                         ("windows", '{"name":"WinRM","status":"Running","required":{},"dependents":[]}')])
def test_failed_or_invalid_reads_stay_unknown(ctx, tmp_path, monkeypatch, asset, output):
    proposal, _, root, _ = seed(ctx, tmp_path, asset=asset, output=output)
    wire(ctx, monkeypatch, root)
    result = dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)
    assert not result["dependencies"] and not result["complete"]
    assert any("invalid" in s or "failed" in s for s in result["unknowns"])
    assert all(e["kind"] == "declared-fix" for e in result["evidence"])


@pytest.mark.parametrize("mode", ["stored", "simulated", "unsupported", "legacy", "missing_fixture"])
def test_unknown_modes_and_missing_fixture_never_write(ctx, tmp_path, monkeypatch, mode):
    proposal, _, root, _ = seed(ctx, tmp_path, asset="cisco_ios" if mode == "unsupported" else "linux")
    if mode == "simulated":
        ctx.inventory.get(HOST).transport = "simulated"
        ctx.inventory.save()
    if mode == "legacy":
        ctx.gate.get(proposal.id).history[0]["meta"].pop("fix_sha256", None)
        ctx.gate._save()
    if mode == "missing_fixture":
        (root / "commands.json").write_text("[]", encoding="utf-8")
    before = stored_state(ctx)
    wire(ctx, monkeypatch, root)
    if mode in {"stored", "simulated", "unsupported"}:
        monkeypatch.setattr(ctx, "transport_for", lambda t: pytest.fail("unexpected transport"))
    result = dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR, live=mode != "stored")
    assert result["unknowns"] and not result["complete"]
    assert not (root / "missing.log").exists() and stored_state(ctx) == before
    if mode == "stored":
        assert result["mode"] == "stored" and not result["dependencies"]
    if mode == "legacy":
        assert any("Legacy" in s for s in result["unknowns"])


def test_missing_current_finding_does_not_infer_live_state(ctx, tmp_path, monkeypatch):
    proposal, _, root, _ = seed(ctx, tmp_path)
    persist(ctx, [], "missing-current", offset=10)
    wire(ctx, monkeypatch, root)
    result = dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR, live=False)
    assert any("matching current finding" in s for s in result["unknowns"])


def test_saved_fix_binding_and_packet_digest(ctx, tmp_path, monkeypatch):
    proposal, fix, root, _ = seed(ctx, tmp_path)
    ctx.library = FixLibrary()
    wire(ctx, monkeypatch, root)
    result = dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)
    assert result["fix_sha256"] == fix_digest(fix)
    modified = deepcopy(result)
    modified["evidence"][0]["facts"]["reboot"] = False
    assert dep.evidence_digest(modified) != result["evidence_sha256"]


def test_configuration_file_rotation_invalidates_packet(ctx, tmp_path, monkeypatch):
    proposal, _, root, _ = seed(ctx, tmp_path)
    path = tmp_path / "connection-config"
    path.write_text("private-original", encoding="utf-8")
    ctx.inventory.get(HOST).options["key_file"] = str(path)
    ctx.inventory.save()
    original = io.read_command

    def read(*args, **kwargs):
        result = original(*args, **kwargs)
        path.write_text("private-rotated", encoding="utf-8")
        return result

    monkeypatch.setattr(io, "read_command", read)
    with pytest.raises(EngineError, match="configuration changed"):
        dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)


def test_service_and_dependency_limits(ctx, tmp_path, monkeypatch):
    names = [f"app{n}.service" for n in range(8)]
    proposal, _, root, _ = seed(ctx, tmp_path, services=names)
    entries = []
    for name in names[:4]:
        output = SYSTEMD.replace("sshd.service", name).replace("application.service", " ".join(f"dep{n}.service" for n in range(40)))
        entries.append({"match": systemd_command(name), "stdout": output})
    (root / "commands.json").write_text(json.dumps(entries), encoding="utf-8")
    calls, _ = wire(ctx, monkeypatch, root)
    result = dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)
    assert len(calls) == 4
    assert all(len(e["facts"]["RequiredBy"]) == 32 for e in result["evidence"] if e["kind"] == "systemd")
    assert any("first four" in s for s in result["unknowns"])
    assert any("32 entries" in s for s in result["unknowns"])
