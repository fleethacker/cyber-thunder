"""Signed device grants over loopback TLS against the actual verified API."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ssl
import threading
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient
import jwt
import pytest

from cyberthunder.api.app import create_app
from cyberthunder.client.api import perform
from cyberthunder.client.auth import ClientAuth
from cyberthunder.client.errors import ClientError
from cyberthunder.client.store import TokenStore
from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.control.access import AccessPolicy
from cyberthunder.control.principal import Principal, principal_scope
from cyberthunder.findings.schema import Finding
from cyberthunder.inventory.targets import Target
from cyberthunder.remediation.library import FixEntry
from tests.security.test_oidc import jwk


@pytest.fixture
def integrated(state_dir, tmp_path, certificates, signing_keys, profile_factory, monkeypatch):
    ca, certificate_files = certificates
    state = SimpleNamespace(subject="alice", changes={}, counter=0, refresh={}, api=None, requests=[], code="fixture-device")
    def issue():
        state.counter += 1
        now = int(time.time())
        roles = ["analyst", "approver"] if state.subject == "builder" else ["analyst"] if state.subject == "alice" else ["approver"]
        claims = {"iss": state.issuer, "sub": state.subject, "name": "Fixture human", "aud": "ct-api", "azp": "ct-human",
                  "iat": now-1, "exp": now+300, "ct_kind": "human", "ct_roles": roles,
                  "auth_time": state.auth_time, "acr": "urn:test:strong", "amr": ["fixture"], **state.changes}
        access = jwt.encode(claims, signing_keys["rsa"], algorithm="RS256", headers={"kid": "rsa"})
        refresh = "fixture-refresh-" + str(state.counter)
        state.refresh[refresh] = state.subject
        return {"token_type": "Bearer", "access_token": access, "refresh_token": refresh, "expires_in": 300}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def respond(self, status, body):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        def route(self):
            length = int(self.headers.get("Content-Length", "0"))
            assert length <= 65536
            raw = self.rfile.read(length)
            state.requests.append((self.command, urlsplit(self.path).path))
            if self.path.startswith("/api/v1/"):
                assert state.api is not None
                forwarded = {key: value for key, value in self.headers.items() if key.lower() in {"authorization", "content-type"}}
                response = state.api.request(self.command, self.path, content=raw, headers=forwarded)
                self.respond(response.status_code, response.json())
            elif self.path == "/jwks":
                self.respond(200, {"keys": [jwk(signing_keys["rsa"])]})
            elif self.path == "/device":
                assert parse_qs(raw.decode())["client_id"] == ["ct-human"]
                self.respond(200, {"device_code": state.code, "user_code": "FIXTURE-CODE", "expires_in": 60,
                                   "interval": 1, "verification_uri": state.url + "/verify"})
            elif self.path == "/token":
                body = parse_qs(raw.decode())
                assert body["client_id"] == ["ct-human"] and "client_secret" not in body
                if body["grant_type"] == ["urn:ietf:params:oauth:grant-type:device_code"]:
                    assert body["device_code"] == [state.code]
                else:
                    assert body["grant_type"] == ["refresh_token"]
                    state.subject = state.refresh.pop(body["refresh_token"][0])
                self.respond(200, issue())
            elif self.path == "/revoke":
                body = parse_qs(raw.decode())
                state.refresh.pop(body.get("token", [None])[0], None)
                self.respond(200, {})
            else:
                self.respond(404, {})
        do_GET = route
        do_POST = route

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(*map(str, certificate_files["valid"]))
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    worker.start()
    state.url = f"https://127.0.0.1:{server.server_port}"
    state.issuer, state.auth_time = state.url + "/issuer", int(time.time())
    monkeypatch.setenv("SSL_CERT_FILE", str(ca))  # Only the server's existing JWKS validator uses this fixture trust.
    profile = profile_factory(state.url, ca_file=str(ca))
    ctx = AppContext(Settings(state_dir=state_dir, auth_mode="dev", llm_backend="template",
                              auto_propose=False, explain_precompute=False))
    try:
        for tid in ("alpha", "beta"):
            ctx.inventory.add(Target(tid, tid, "linux", transport="simulated", simulated=True, environment=tid))
        ctx.inventory.save()
        ctx.store.save_scan_run({"id": "fixture-both", "targets": ["alpha", "beta"], "status": "done"})
        findings = [Finding(host=tid, source="fixture", rule_id="fixture-setting", title="Fixture change", severity="high",
                            status="open", asset_type="linux") for tid in ("alpha", "beta")]
        ctx.store.save_findings("fixture-both", findings)
        ctx.library.add(FixEntry("fixture:setting", "Fixture change", "linux", ["fixture-setting"], payload="reviewed fixture"))
        policy_path = state_dir / "auth" / "access.json"
        policy_path.parent.mkdir(mode=0o700)
        policy_path.write_text(json.dumps({"version": 1, "entries": [
            {"issuer": state.issuer, "subject": subject, "node_actions": ["kill.engage"],
             "grants": [{"target_ids": targets, "actions": actions}]}
            for subject, targets, actions in [
                ("alice", ["alpha"], ["read", "scan"]),
                ("bob", ["beta"], ["read", "approve", "deny", "cancel", "apply", "verify", "rollback", "plan", "review"]),
                ("carol", ["beta"], ["read", "approve", "plan", "review"]),
                ("builder", ["alpha", "beta"], ["read", "propose", "approve"])] ]}))
        policy_path.chmod(0o600)
        ctx.settings.auth_mode = "oidc"
        ctx.settings.oidc_issuer, ctx.settings.oidc_audience = state.issuer, "ct-api"
        ctx.settings.oidc_jwks_url, ctx.settings.oidc_authorized_party = state.url + "/jwks", "ct-human"
        ctx.settings.step_up_acr_values = ("urn:test:strong",)
        ctx.access = AccessPolicy(policy_path)
        ctx.gate.authorizer = ctx.authorize
        ctx.killswitch.authorizer = ctx.authorize
        builder = Principal(state.issuer, "builder", "Builder", kind="human", roles=("analyst", "approver"),
                            expires_at=time.time()+300, auth_time=state.auth_time, acr="urn:test:strong")
        with principal_scope(builder):
            proposals = {tid: ctx.engine.propose(ctx.store.get_finding(f.id), actor=builder.actor)
                         for tid, f in zip(("alpha", "beta"), findings)}
        with TestClient(create_app(ctx)) as api:
            state.api = api
            auth = ClientAuth(profile, store=TokenStore(profile.digest, root=tmp_path / "client-private"))
            yield auth, state, ctx, proposals
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
        assert not worker.is_alive()
        ctx.store.close()


def args(group, operation, **values):
    return SimpleNamespace(group=group, operation=operation, **values)


def login(auth, state, subject):
    auth.logout()
    state.subject = subject
    return auth.login(lambda *_: None)


def test_signed_device_identity_scope_and_accepted_scan(integrated):
    auth, state, ctx, _ = integrated
    assert login(auth, state, "alice")["identity"]["sub"] == "alice"
    # Separate client instances share the native lock: only one redeems the old
    # refresh credential, and both use the rotated, API-verified session.
    from concurrent.futures import ThreadPoolExecutor
    with auth.store.locked():
        record = auth.store.load()
        record["session"]["expires_at"] = time.time()+10
        auth.store.save(record)
    def read_targets(_):
        other = ClientAuth(auth.profile, store=TokenStore(auth.profile.digest, root=auth.store.root))
        try:
            return perform(other, args("targets", "list"))
        except ClientError as error:
            if error.code != "client_store_busy":
                raise
            return None
    before = state.counter
    with ThreadPoolExecutor(max_workers=2) as pool:
        reads = list(pool.map(read_targets, range(2)))
    assert state.counter == before+1 and any(item is not None for item in reads)
    # Three bounded HTTPS requests during refresh may exceed the store's
    # five-second contention limit. After both callers finish, explicitly issue
    # a new read for a busy caller; production commands never retry themselves.
    reads = [item if item is not None else read_targets(None) for item in reads]
    assert all(item is not None for item in reads)
    assert state.counter == before+1 and all(code == 0 for _, code in reads)
    result, code = perform(auth, args("targets", "list"))
    assert code == 0 and [t["id"] for t in result["result"]["targets"]] == ["alpha"]
    result, _ = perform(auth, args("findings", "list", host=None, scan_id=None, status=None, severity=None, limit=200, offset=0))
    assert "beta" not in json.dumps(result)
    with pytest.raises(ClientError) as denied:
        perform(auth, args("scans", "start", target=["beta"], module=["check"]))
    assert denied.value.status == 403
    result, code = perform(auth, args("scans", "start", target=["alpha"], module=["check"]))
    assert code == 4 and result["status"] == "accepted_pending" and result["operation_id"]
    ctx.scanner.join(result["operation_id"], timeout=15)
    assert not ctx.scanner.is_running(result["operation_id"])


@pytest.mark.parametrize("changes", [{"azp": "other-client"}, {"aud": "other-api"}, {"iss": "https://other.test"},
                                     {"ct_kind": "workload"}, {"exp": 1}])
def test_signed_wrong_identity_is_not_persisted(integrated, changes):
    auth, state, _, _ = integrated
    state.changes = changes
    with pytest.raises(ClientError): auth.login(lambda *_: None)
    with auth.store.locked(): assert auth.store.load()["phase"] == "empty"


def test_decisions_preserve_sod_partial_quorum_stepup_and_kill(integrated):
    auth, state, ctx, proposals = integrated
    pid = proposals["beta"].id
    approve = args("decisions", "approve", id=pid, assessment_id=None)
    note = {"assessment_note": "Fixture operator explicitly reviewed missing assessment"}
    login(auth, state, "builder")
    with pytest.raises(ClientError) as self_vote: perform(auth, approve, note)
    assert self_vote.value.status in {403, 409}
    login(auth, state, "bob")
    unknown_assessment = args("decisions", "approve", id=pid, assessment_id="00000000-0000-0000-0000-000000000000")
    with pytest.raises(ClientError) as no_assessment: perform(auth, unknown_assessment, {})
    assert no_assessment.value.status == 409
    result, code = perform(auth, approve, note)
    assert code == 4 and result["result"]["state"] == "proposed" and result["operation_id"] == pid
    with pytest.raises(ClientError) as duplicate: perform(auth, approve, note)
    assert duplicate.value.status in {403, 409}
    login(auth, state, "carol")
    result, code = perform(auth, approve, note)
    assert code == 0 and result["result"]["state"] == "approved"
    login(auth, state, "bob")
    with auth.access():
        p = Principal(state.issuer, "bob", "Bob", kind="human", roles=("approver",),
                      expires_at=time.time()+300, auth_time=state.auth_time, acr="urn:test:strong")
        with principal_scope(p): ctx.killswitch.engage(p.actor, "fixture emergency stop")
    with pytest.raises(ClientError) as stopped: perform(auth, args("decisions", "apply", id=pid))
    assert stopped.value.status == 423
    auth.logout()
    state.auth_time = int(time.time())-600
    auth.login(lambda *_: None)
    with pytest.raises(ClientError) as stale: perform(auth, approve, note)
    assert stale.value.status == 401 and stale.value.code == "insufficient_user_authentication"
    assert stale.value.challenge["reason"] == "authentication_too_old"


def test_original_ownership_and_bearer_logout_limit(integrated):
    auth, state, ctx, proposals = integrated
    login(auth, state, "bob")
    with auth.store.locked(): copied = auth.store.load()["session"]["access_token"]
    result, code = auth.logout()
    assert code == 0 and result["provider_revocation"] == "acknowledged"
    assert state.api.get("/api/v1/whoami", headers={"Authorization": "Bearer " + copied}).status_code == 200
    login(auth, state, "bob")
    target = ctx.inventory.get("beta")
    target.environment = "reassigned"
    ctx.inventory.save()
    with pytest.raises(ClientError) as moved: perform(auth, args("decisions", "show", id=proposals["beta"].id))
    assert moved.value.status == 403
