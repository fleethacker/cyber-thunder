"""ZT-22: real lifecycle services, credential bindings, and captured output boundaries."""
from __future__ import annotations

import base64
import io
import json
import logging
import os
import shlex
import socket
import subprocess
import time
from dataclasses import replace
from types import SimpleNamespace
from urllib.parse import quote

from fastapi.testclient import TestClient
import pytest

from cyberthunder.adapters import load_all, registry
from cyberthunder.api.app import create_app
from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.control.access import ACTIONS
from cyberthunder.control.principal import Principal, operation_scope, principal_scope
from cyberthunder.discovery.models import DiscoveryScope
from cyberthunder.inventory.targets import Target
from cyberthunder.remediation.library import FixLibrary
from cyberthunder.transport.base import TransportError
from cyberthunder.transport.trust import key_fingerprint
from tests.engine.fakes import FakeLinuxAdapter, FakeTransport, RULE_ROOT_LOGIN, SSHD, seed_state
from tests.explain.helpers import FakeBackend, canned

from tests.security.canary_helpers import CanaryLeak, CanaryProbe


# Synthetic fixture credential. Never a real account, session, or network secret.
CANARY = "ct-canary-ZT22-8f5a19B+/=%?&"
REFERENCE = "LIFECYCLE_CANARY"
HOST = "canary-host"
ADDRESS = "192.0.2.7"


@pytest.mark.parametrize("encoding", ["plain", "base64-envelope", "base64url", "percent", "nested", "utf16"])
def test_probe_detects_deliberately_planted_leak(tmp_path, encoding):
    # Encode a larger document so searching only base64(CANARY) cannot pass.
    document = json.dumps({"diagnostic": "credential=" + CANARY}).encode()
    payloads = {
        "plain": document,
        "base64-envelope": base64.b64encode(document),
        "base64url": base64.urlsafe_b64encode(document).rstrip(b"="),
        "percent": "".join(f"%{b:02x}" for b in document).encode(),
        "nested": quote(base64.b64encode(document).decode(), safe="").encode(),
        "utf16": base64.b64encode(("password=" + CANARY).encode("utf-16le")),
    }
    (tmp_path / "deliberate-leak.bin").write_bytes(payloads[encoding])
    probe = CanaryProbe(CANARY)
    probe.tree(tmp_path)
    with pytest.raises(CanaryLeak, match="state file") as caught:
        probe.assert_clean()
    if CANARY in str(caught.value) or base64.b64encode(CANARY.encode()).decode() in str(caught.value):
        pytest.fail("the detector must not echo its credential")


def test_probe_detects_sqlite_overflow_value(tmp_path):
    import sqlite3

    path = tmp_path / "planted.db"
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA page_size=512")
        db.execute("CREATE TABLE diagnostic(value TEXT)")
        db.execute("INSERT INTO diagnostic VALUES (?)", ("padding" * 1000 + CANARY,))
    probe = CanaryProbe(CANARY)
    probe.tree(tmp_path)
    with pytest.raises(CanaryLeak, match="table 0 row 0 column 0"):
        probe.assert_clean()


def test_probe_allows_public_references_and_identity():
    probe = CanaryProbe(CANARY)
    probe.add("public metadata", {"credential_ref": REFERENCE, "subject": "fixture-operator"})
    probe.assert_clean()


class MemoryKey:
    def asbytes(self):
        return b"fixture-host-public-key"


class MemorySFTP:
    def __init__(self, state):
        self.state = state

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def open(self, path, mode):
        files = self.state["files"]
        if mode == "rb":
            return io.BytesIO(files[path].encode())
        assert mode == "wb"

        class StagedFile(io.BytesIO):
            def close(self):
                files[path] = self.getvalue().decode()
                super().close()

        return StagedFile()


class MemorySSH:
    """Replace only Paramiko I/O; SSHTransport still resolves/binds/guards secrets."""
    def __init__(self, harness):
        self.harness = harness
        self.policy = None
        self.transport = SimpleNamespace(auth_handler=SimpleNamespace(password=None))
        harness.clients.append(self)

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, hostname, **kwargs):
        self.policy.missing_host_key(self, hostname, MemoryKey())
        if kwargs["password"] != CANARY:
            raise AssertionError("credential binding did not reach the authentication sink")
        assert kwargs["username"] == "fixture-account"
        assert kwargs["allow_agent"] is False and kwargs["look_for_keys"] is False
        self.transport.auth_handler.password = kwargs["password"]
        self.harness.authentications += 1
        if self.harness.reject_auth:
            # A real library can include a rejected password in its exception.
            raise RuntimeError("fixture authentication rejection: " + CANARY)

    def get_transport(self):
        return self.transport

    def exec_command(self, command, **_):
        assert self.transport.auth_handler.password is None
        self.harness.probe.add("remote command", command)
        parts = shlex.split(command)
        if parts[:4] == ["sudo", "-n", "sh", "-c"]:
            command = parts[4]
            parts = shlex.split(command)
        if parts[0] == "install":
            assert len(parts) == 7 and parts[3:6] == ["&&", "rm", "-f"]
            assert parts[1] == parts[6] and parts[1].startswith("/tmp/.ct-")
            self.harness.state["files"][parts[2]] = self.harness.state["files"].pop(parts[1])
            code, stdout, stderr = 0, "", ""
        else:
            result = FakeTransport(self.harness.state).run(command)
            code, stdout, stderr = result.exit_code, result.stdout, result.stderr
        out, err = io.BytesIO(stdout.encode()), io.BytesIO(stderr.encode())
        out.channel = SimpleNamespace(recv_exit_status=lambda: code)
        return None, out, err

    def open_sftp(self):
        return MemorySFTP(self.harness.state)

    def close(self):
        pass


class LifecycleAdapter(FakeLinuxAdapter):
    transports = ("ssh",)

    def discover(self, target, transport):
        transport.check_output("fake-dump")
        return super().discover(target, transport)

    def verify(self, target, transport, fix, finding):
        # Fail the actual rule re-check without changing the post-apply baseline:
        # automatic rollback still has to verify drift and restore the saved file.
        result = super().verify(target, transport, fix, finding)
        assert result.rule_passed is True and result.health.ok
        result.ok = False
        result.rule_passed = False
        result.evidence = "fixture independent rule re-check failed"
        return result


@pytest.fixture
def lifecycle(state_dir, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv("CT_CRED_" + REFERENCE, CANARY)
    principal = Principal("https://identity.example.test", "fixture-operator", "Fixture operator",
                          kind="human", roles=("analyst", "approver", "admin", "auditor"),
                          expires_at=time.time() + 300, auth_time=int(time.time()), acr="urn:ct:test:strong")
    proposer = replace(principal, subject="fixture-proposer", display_name="Fixture proposer",
                       roles=("analyst",))
    path = state_dir / "auth" / "access.json"
    path.parent.mkdir(mode=0o700)
    path.write_text(json.dumps({"version": 1, "entries": [{
        "issuer": account.issuer, "subject": account.subject,
        "node_actions": sorted(ACTIONS),
        "grants": [{"target_ids": [HOST], "actions": sorted(ACTIONS - {"read.all"}),
                    "credential": {"username": "fixture-account", "credential_ref": REFERENCE,
                                   "sudo": True, "options": {}}}],
    } for account in (principal, proposer)]}), encoding="utf-8")
    path.chmod(0o600)

    # Fleet authentication uses the protected mounted provider. Keep its input
    # outside application output so the probe can inspect every state artifact.
    # The environment canary above still checks child-process sanitization.
    secret_root = state_dir.parent / "credential-inputs"
    secret_root.mkdir(mode=0o700)
    secret_path = secret_root / "password"
    secret_path.write_text(CANARY, encoding="utf-8")
    secret_path.chmod(0o600)
    registry_path = path.parent / "credential-sources.json"
    registry_path.write_text(json.dumps({"version": 1, "sources": {REFERENCE: {
        "provider": "mounted", "root": str(secret_root), "key": secret_path.name,
    }}}), encoding="utf-8")
    registry_path.chmod(0o600)

    load_all()
    monkeypatch.setattr(registry, "_adapters", dict(registry._adapters))
    adapter = LifecycleAdapter()
    registry.register(adapter)
    harness = SimpleNamespace(state=seed_state(), probe=CanaryProbe(CANARY), authentications=0,
                              reject_auth=False, children=[], clients=[], principal=principal, proposer=proposer)
    monkeypatch.setattr("paramiko.SSHClient", lambda: MemorySSH(harness))

    def no_network(*_, **__):
        raise AssertionError("this fixture must not open a network connection")

    class Child:
        def __init__(self, args, **kwargs):
            assert isinstance(args, list) and "nmap" in args[-1]
            assert kwargs.get("timeout") is None  # subprocess.run owns the timeout
            self.args, self.returncode = args, 0
            effective_env = dict(os.environ) if kwargs.get("env") is None else dict(kwargs["env"])
            harness.children.append(args)
            harness.probe.add(f"child {len(harness.children)} argv", args)
            harness.probe.add(f"child {len(harness.children)} environment", effective_env)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def communicate(self, input=None, timeout=None):
            assert timeout and timeout <= 300
            return ('<nmaprun><host><status state="up"/><address addr="' + ADDRESS +
                    '" addrtype="ipv4"/><ports><port protocol="tcp" portid="22">'
                    '<state state="open"/><service name="ssh" product="fixture"/>'
                    '</port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>', "")

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr(subprocess, "Popen", Child)
    monkeypatch.setattr("cyberthunder.discovery.sources.nmap.find_nmap", lambda: "nmap")
    # Keep the real credential factory and guarded SSHTransport. Only expose the
    # remote fixture state used by the existing lifecycle adapter's rule checks.
    import cyberthunder.context as context_module
    original_factory = context_module.make_transport

    def transport_factory(*args, **kwargs):
        transport = original_factory(*args, **kwargs)
        transport.state = harness.state
        return transport

    monkeypatch.setattr(context_module, "make_transport", transport_factory)
    ctx = AppContext(Settings(state_dir=state_dir, auth_mode="oidc", security_mode="fleet",
                              credential_sources=str(registry_path),
                              step_up_acr_values=("urn:ct:test:strong",),
                              llm_backend="template", auto_propose=False, explain_precompute=False))
    ctx.library = FixLibrary.from_adapters(registry)
    ctx.inventory.add(Target(HOST, "Fixture host", "linux", "ssh", address=ADDRESS,
                             options={"host_key_sha256": key_fingerprint(MemoryKey())}))
    ctx.inventory.save()
    backend = FakeBackend([canned("valid")])
    ctx.explain.backend = backend
    harness.ctx, harness.backend = ctx, backend

    class Validator:
        def validate(self, token):
            if token != CANARY:
                raise ValueError("invalid fixture token")
            return {"iss": principal.issuer, "sub": principal.subject, "name": principal.display_name,
                    "ct_roles": list(principal.roles), "ct_kind": principal.kind, "exp": principal.expires_at,
                    "auth_time": principal.auth_time, "acr": principal.acr}

    monkeypatch.setattr("cyberthunder.api.auth.make_validator", lambda *_: Validator())
    with TestClient(create_app(ctx)) as client:
        harness.client = client
        # TestClient creates asyncio's internal socket pair before this guard on
        # Windows. Application work starts only after all network calls are denied.
        with monkeypatch.context() as network_guard:
            network_guard.setattr(socket.socket, "connect", no_network)
            network_guard.setattr(socket.socket, "connect_ex", no_network)
            network_guard.setattr(socket, "create_connection", no_network)
            yield harness


def test_lifecycle_keeps_credentials_out_of_outputs(lifecycle, caplog):
    h = lifecycle
    ctx, principal, probe = h.ctx, h.principal, h.probe

    def request(method, path, *, expected=200, **kwargs):
        response = h.client.request(method, "/api/v1" + path,
                                    headers={"Authorization": "Bearer " + CANARY}, **kwargs)
        probe.add(f"API {method} {path} body", response.content)
        probe.add(f"API {method} {path} headers", dict(response.headers))
        assert response.status_code == expected, f"unexpected status for {method} {path}: {response.status_code}"
        return response

    # Real SSH account binding, request identity, adapter discover, and audit.
    assert request("POST", f"/targets/{HOST}/discover").json()["hostname"] == HOST
    with principal_scope(h.proposer):
        scan = ctx.scanner.start([HOST], background=False, requested_by=h.proposer.actor)
        assert scan.status == "done" and not scan.error
        assert not scan.results[HOST].errors
        finding = next(f for f in ctx.store.load_findings(scan.id) if f.rule_id == RULE_ROOT_LOGIN)
        explanation = ctx.explain.explain(finding)
        assert explanation.validated and not explanation.fallback and h.backend.prompts
        proposal = ctx.engine.propose(finding, actor=h.proposer.actor)
        assert proposal is not None and proposal.state.value == "proposed"
        assert proposal.proposed_by == h.proposer.actor != principal.actor
    approved = request("POST", f"/proposals/{proposal.id}/approve",
                       json={"note": "Fixture change reviewed"}).json()
    assert approved["state"] == "approved" and approved["decided_by"] == principal.actor
    original = h.state["files"][SSHD]
    with principal_scope(principal):
        result = ctx.engine.execute(proposal.id, actor=principal.actor)
    assert result.state.value == "rolled_back"
    assert h.state["files"][SSHD] == original
    transitions = [row["state"] for row in result.history]
    assert "applied" in transitions and "failed" in transitions and transitions[-1] == "rolled_back"

    # A third-party authentication error contains the synthetic credential. The
    # actual SSH transport must sanitize it before API errors, logs, or audit.
    h.reject_auth = True
    request("POST", f"/targets/{HOST}/discover", expected=503)
    with principal_scope(principal), operation_scope("discover"):
        with ctx.transport_for(ctx.inventory.get(HOST)) as transport:
            with pytest.raises(TransportError) as caught:
                transport.check_output("fake-dump")
        probe.add("public transport exception", str(caught.value))
    h.reject_auth = False
    assert h.authentications >= 5
    assert all(client.transport.auth_handler.password is None for client in h.clients)

    for path in ("/whoami", "/targets", "/findings", "/proposals", f"/proposals/{proposal.id}/diff",
                 "/audit", "/audit/verify", "/status", f"/reports/commander?format=md&scan_id={scan.id}",
                 f"/reports/poam.csv?scan_id={scan.id}", "/reports/history"):
        request("GET", path)
    queued = request("POST", "/reports/queue", json={"kind": "commander", "scan_id": scan.id}).json()
    assert queued["queued"] is True
    # Inspect pending artifacts before sync can move them, then inspect synced
    # artifacts again below. No output directory or credential policy is omitted.
    probe.tree(ctx.store.root)
    with principal_scope(principal):
        synced = ctx.ingest.outbox.sync(force=True, actor=principal.actor)
        probe.add("outbox sync result", synced)
        assert synced["sent"] == 1
    assert request("GET", "/outbox").json()["pending"] == []

    # Real local scanner path, with only the process creation boundary replaced.
    # The environment is inspected as the OS child would receive it, including
    # inheritance when subprocess.run passes env=None.
    with principal_scope(principal), operation_scope("discover"):
        ctx.discovery.set_scopes([DiscoveryScope(cidr=ADDRESS + "/32", allow_public=True)],
                                 principal.actor, "Only this documentation address; all I/O is fixture-backed")
        discovered = ctx.discovery.sweep(mode="quick", actor=principal.actor, background=False)
        assert discovered.status == "finished" and not discovered.errors
        assert len(h.children) == 2
        assert len(ctx.inventory.all()) == 1  # discovery never accepts an observation
    stream = request("GET", "/audit/stream?max_seconds=0.01")
    assert "event:" in stream.text and "data:" in stream.text
    assert ctx.audit.verify().ok
    actions = {row["action"] for row in ctx.audit.records()}
    assert {"credential.use", "discovery.finish", "report.render", "report.queue",
            "proposal.approved", "remediation.verify"} <= actions
    probe.add("model prompts", h.backend.prompts)
    probe.add("DEBUG logs", caplog.text)
    probe.tree(ctx.store.root)
    probe.assert_clean()
