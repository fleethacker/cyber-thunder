"""Browser sessions against an isolated HTTPS provider with real signatures."""

from base64 import b64decode, urlsafe_b64encode
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar, copy_context
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import gc
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import secrets
import ssl
import threading
import time
import traceback
import weakref
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
import jwt
import pytest
from starlette.datastructures import Headers

from cyberthunder.api.session_routes import install_sessions
from cyberthunder.security import sessions
from cyberthunder.security._oidc_cache import write_cache
from cyberthunder.security.oidc import AuthenticationError, OIDCConfig, OIDCValidator
from cyberthunder.security.sessions import CSRFError, LOGIN_COOKIE, SESSION_COOKIE, SessionConfig, SessionService

ISSUER = "https://identity.example.test/tenant"
ORIGIN = "https://console.example.test"
CLIENT = "browser-client"
API_AUDIENCE = "cyber-thunder-api"


@pytest.fixture(scope="session")
def crypto(tmp_path_factory):
    folder = tmp_path_factory.mktemp("browser-identity-certificates")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Session fixture CA")])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                   .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                   .sign(key, hashes.SHA256()))
    cert_path, key_path = folder / "ca.pem", folder / "server.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    return cert_path, key_path, {
        "rsa": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "ec": ec.generate_private_key(ec.SECP256R1()),
        "rogue": rsa.generate_private_key(public_exponent=65537, key_size=2048),
    }


class Provider:
    def __init__(self, keys):
        self.keys = keys
        self.codes = {}
        self.refreshes = {}
        self.posts = []
        self.gets = []
        self.nonces = []
        self.access_changes = {}
        self.id_changes = {}
        self.response_changes = {}
        self.signer = "rsa"
        self.http_status = 200
        self.http_headers = {}
        self.raw_response = None
        self.slow = False
        self.reuse_refresh = False
        self.refresh_id = False
        self.expires_in = 300
        self.expected_basic = None
        self.omit_length = False

    def authorize(self, url):
        query = {name: values[0] for name, values in parse_qs(urlsplit(url).query).items()}
        assert query["response_type"] == "code"
        assert query["code_challenge_method"] == "S256"
        assert query["client_id"] == CLIENT
        assert query["redirect_uri"] == ORIGIN + "/auth/callback"
        assert query["response_mode"] == "query"
        assert "openid" in query["scope"].split()
        code = secrets.token_urlsafe(24)
        self.codes[code] = query
        self.nonces.append(query["nonce"])
        return urlencode({"code": code, "state": query["state"], "iss": ISSUER})

    def jwks(self):
        values = []
        for kid in ("rsa", "ec"):
            key = self.keys[kid]
            algorithm = jwt.algorithms.RSAAlgorithm if kid == "rsa" else jwt.algorithms.ECAlgorithm
            value = json.loads(algorithm.to_jwk(key.public_key()))
            value.update(kid=kid, alg="RS256" if kid == "rsa" else "ES256")
            values.append(value)
        return {"keys": values}

    def signed(self, claims):
        return jwt.encode(claims, self.keys[self.signer], algorithm="ES256" if self.signer == "ec" else "RS256",
                          headers={"kid": "rsa" if self.signer == "rogue" else self.signer})

    def exchange(self, form, authorization):
        if self.expected_basic is not None:
            assert authorization == self.expected_basic
            assert "client_id" not in form and "client_secret" not in form
        else:
            assert authorization is None and form["client_id"] == CLIENT
        initial = form["grant_type"] == "authorization_code"
        if initial:
            query = self.codes.pop(form["code"])
            assert form["redirect_uri"] == query["redirect_uri"]
            challenge = urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(b"=").decode()
            assert challenge == query["code_challenge"]
            nonce = query["nonce"]
        else:
            assert form["grant_type"] == "refresh_token"
            nonce = self.refreshes.pop(form["refresh_token"])
        now = int(time.time())
        base = {"iss": ISSUER, "sub": "operator-123", "iat": now - 1, "exp": now + 300}
        access = self.signed({**base, "aud": API_AUDIENCE, "azp": CLIENT, **self.access_changes})
        at_hash = urlsafe_b64encode(hashlib.sha256(access.encode()).digest()[:16]).rstrip(b"=").decode()
        identity = self.signed({**base, "aud": CLIENT, "nonce": nonce, "at_hash": at_hash, **self.id_changes})
        refresh = form["refresh_token"] if self.reuse_refresh and not initial else secrets.token_urlsafe(32)
        self.refreshes[refresh] = nonce
        response = {"token_type": "Bearer", "access_token": access, "refresh_token": refresh,
                    "expires_in": self.expires_in, **self.response_changes}
        if initial or self.refresh_id:
            response.setdefault("id_token", identity)
        return response


@pytest.fixture
def provider(crypto, monkeypatch):
    cert, key, signing_keys = crypto
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    state = Provider(signing_keys)
    stop = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            state.gets.append(self.path)
            body = json.dumps(state.jwks()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            try:
                data = self.rfile.read(min(int(self.headers["Content-Length"]), 65536))
                form = {name: values[0] for name, values in parse_qs(data.decode()).items()}
                state.posts.append((self.path, form, dict(self.headers)))
                if state.slow:
                    self.connection.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                    while not stop.wait(0.03):
                        self.connection.sendall(b"x")
                    return
                if state.raw_response is not None:
                    body = state.raw_response
                elif state.http_status != 200:
                    body = b'{"error":"provider-private-error"}'
                else:
                    try:
                        body = json.dumps(state.exchange(form, self.headers.get("Authorization"))).encode()
                    except (AssertionError, KeyError):
                        self.send_error(400)
                        return
                self.send_response(state.http_status)
                headers = {"Content-Type": "application/json", **state.http_headers}
                if not state.omit_length:
                    headers.setdefault("Content-Length", str(len(body)))
                for name, value in headers.items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(body)
            except OSError:
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    worker.start()
    state.url = f"https://127.0.0.1:{server.server_port}"
    yield state
    stop.set()
    server.shutdown()
    server.server_close()
    worker.join(2)
    assert not worker.is_alive()


def seed_cache(config, provider):
    now = int(time.time())
    write_cache(config.cache_path, json.dumps({
        "version": 1, "issuer": config.issuer, "audience": config.audience,
        "authorized_party": config.authorized_party, "jwks_url": config.jwks_url,
        "fetched_at": now, "observed_at": now, "jwks": provider.jwks(),
    }).encode())


@pytest.fixture
def configured(provider, tmp_path):
    identity = OIDCConfig(ISSUER, CLIENT, provider.url + "/jwks", tmp_path / "identity.json")
    access = OIDCConfig(ISSUER, API_AUDIENCE, provider.url + "/jwks", tmp_path / "access.json", authorized_party=CLIENT)
    seed_cache(identity, provider)
    seed_cache(access, provider)
    config = SessionConfig(ISSUER, CLIENT, provider.url + "/authorize", provider.url + "/token",
                           ORIGIN + "/auth/callback", identity)
    return config, access


@pytest.fixture
def service(configured):
    config, access = configured
    return SessionService(config, OIDCValidator(access))


def begin(service, provider, headers=None):
    url, cookie = service.start_login(headers or {})
    return provider.authorize(url), {"Cookie": f"{LOGIN_COOKIE}={cookie}"}


def authenticated(service, provider):
    query, headers = begin(service, provider)
    cookie = service.complete_login(query, headers)
    return {"Cookie": f"{SESSION_COOKIE}={cookie}"}


def fail(call):
    with pytest.raises(AuthenticationError) as error:
        call()
    assert str(error.value) == "Authentication failed"
    assert error.value.__suppress_context__
    assert "provider-private-error" not in "".join(traceback.format_exception(error.value))


@pytest.mark.parametrize("signer", ["rsa", "ec"])
def test_complete_pkce_flow_real_https_jwks_and_signatures(configured, provider, signer):
    config, access = configured
    config.id_token_config.cache_path.unlink()
    access.cache_path.unlink()
    provider.signer = signer
    service = SessionService(config, OIDCValidator(access))
    headers = authenticated(service, provider)
    claims = service.resolve_session(headers)
    assert claims["sub"] == "operator-123" and claims["aud"] == API_AUDIENCE
    assert len(provider.posts) == 1 and provider.gets == ["/jwks", "/jwks"]
    _, info = service.session_info(headers)
    service.csrf_check("PATCH", {**headers, "Origin": ORIGIN, "X-CSRF-Token": info["csrf_token"]})
    assert service.resolve_session({}) is None


@pytest.mark.parametrize("changes", [
    {"authorization_endpoint": "http://identity.test/authorize"},
    {"token_endpoint": "https://user:password@identity.test/token"},
    {"token_endpoint": "https://*.identity.test/token"},
    {"redirect_uri": ORIGIN + "/auth/callback?next=elsewhere"},
    {"redirect_uri": ORIGIN + "/other"}, {"redirect_uri": "http://console.example.test/auth/callback"},
    {"redirect_uri": ORIGIN + "/auth/callback#fragment"}, {"client_id": ""},
    {"client_secret_ref": "bad-name"}, {"scope": "profile"}, {"scope": "openid openid"},
    {"scope": "openid\nprofile"}, {"idle_timeout_s": True}, {"idle_timeout_s": 0},
    {"absolute_timeout_s": 30}, {"absolute_timeout_s": 86401}, {"login_timeout_s": 601},
    {"max_sessions": 0}, {"max_pending": 257},
])
def test_invalid_configuration(configured, changes):
    with pytest.raises(AuthenticationError):
        replace(configured[0], **changes)


def test_verifier_issuer_client_audience_and_cache_separation(configured):
    config, access = configured
    for changed in (replace(access, audience=CLIENT), replace(access, authorized_party=None),
                    replace(access, issuer="https://other.example.test"),
                    replace(access, cache_path=config.id_token_config.cache_path)):
        with pytest.raises(AuthenticationError):
            SessionService(config, OIDCValidator(changed))
    with pytest.raises(AuthenticationError):
        replace(config, id_token_config=access)


@pytest.mark.parametrize("mutation", ["missing-state", "wrong-state", "duplicate-state", "wrong-issuer", "error", "missing-code", "unknown-field"])
def test_callback_failures_consume_state_without_exchange(service, provider, mutation):
    query, headers = begin(service, provider)
    values = {name: items[0] for name, items in parse_qs(query).items()}
    if mutation == "missing-state":
        values.pop("state")
    elif mutation == "wrong-state":
        values["state"] = secrets.token_urlsafe(32)
    elif mutation == "wrong-issuer":
        values["iss"] = "https://other.example.test"
    elif mutation == "error":
        values["error"] = "provider-private-error"
    elif mutation == "missing-code":
        values.pop("code")
    elif mutation == "unknown-field":
        values["access_token"] = "injected-value"
    changed = urlencode(values) + ("&state=" + values["state"] if mutation == "duplicate-state" else "")
    fail(lambda: service.complete_login(changed, headers))
    fail(lambda: service.complete_login(query, headers))
    assert not provider.posts


def test_state_requires_browser_cookie_and_is_single_use(service, provider):
    query, headers = begin(service, provider)
    fail(lambda: service.complete_login(query, {}))
    session_id = service.complete_login(query, headers)
    assert session_id
    fail(lambda: service.complete_login(query, headers))
    assert len(provider.posts) == 1


def test_concurrent_callbacks_redeem_exactly_once(service, provider):
    query, headers = begin(service, provider)

    def redeem(_):
        try:
            return service.complete_login(query, headers)
        except AuthenticationError:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(redeem, range(8)))
    assert sum(result is not None for result in outcomes) == 1
    assert len(provider.posts) == 1 and len(service._sessions) == 1


def test_swapped_browser_transaction_cookies_fail(service, provider):
    first, first_headers = begin(service, provider)
    second, second_headers = begin(service, provider)
    fail(lambda: service.complete_login(first, second_headers))
    fail(lambda: service.complete_login(second, first_headers))
    assert not provider.posts


@pytest.mark.parametrize("changes,target", [
    ({"nonce": "wrong"}, "id"), ({"nonce": None}, "id"), ({"nonce": []}, "id"),
    ({"aud": "other-client"}, "id"), ({"sub": "other-person"}, "id"),
    ({"iss": "https://other.example.test"}, "id"), ({"at_hash": "wrong"}, "id"),
    ({"aud": CLIENT}, "access"), ({"aud": [API_AUDIENCE, CLIENT]}, "access"),
    ({"aud": [CLIENT, API_AUDIENCE], "azp": CLIENT}, "id"),
    ({"azp": "other-client"}, "access"), ({"iss": "https://other.example.test"}, "access"),
])
def test_signed_identity_and_access_binding_rejections(service, provider, changes, target):
    if target == "id":
        provider.id_changes = changes
    else:
        provider.access_changes = changes
    query, headers = begin(service, provider)
    fail(lambda: service.complete_login(query, headers))
    assert not service._sessions
    fail(lambda: service.complete_login(query, headers))
    assert len(provider.posts) == 1


def test_invalid_signature(service, provider):
    provider.signer = "rogue"
    query, headers = begin(service, provider)
    fail(lambda: service.complete_login(query, headers))
    assert not service._sessions


@pytest.mark.parametrize("changes", [
    {"token_type": "MAC"}, {"token_type": None}, {"access_token": None},
    {"access_token": "x" * 16385}, {"refresh_token": "x" * 8193},
    {"refresh_token": None}, {"id_token": None}, {"expires_in": True},
    {"expires_in": "300"}, {"expires_in": 0}, {"expires_in": 3601},
    {"scope": "openid admin"}, {"error": "provider-private-error"},
])
def test_bad_token_response_fails_closed(service, provider, changes):
    provider.response_changes = changes
    query, headers = begin(service, provider)
    fail(lambda: service.complete_login(query, headers))
    assert not service._sessions


def test_session_fixation_rotates_identifier_and_csrf(service, provider):
    old_headers = authenticated(service, provider)
    old_id = old_headers["Cookie"].split("=", 1)[1]
    _, old_info = service.session_info(old_headers)
    query, login_headers = begin(service, provider, old_headers)
    new_id = service.complete_login(query, {"Cookie": old_headers["Cookie"] + "; " + login_headers["Cookie"]})
    assert old_id != new_id
    fail(lambda: service.resolve_session(old_headers))
    new_headers = {"Cookie": f"{SESSION_COOKIE}={new_id}"}
    _, new_info = service.session_info(new_headers)
    assert old_info["csrf_token"] != new_info["csrf_token"]


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "TRACE", "CUSTOM", "post"])
def test_all_unsafe_methods_need_origin_and_session_csrf(service, provider, method):
    headers = authenticated(service, provider)
    _, info = service.session_info(headers)
    for extra in ({}, {"Origin": ORIGIN}, {"X-CSRF-Token": info["csrf_token"]},
                  {"Origin": "https://evil.example.test", "X-CSRF-Token": info["csrf_token"]},
                  {"Origin": "null", "X-CSRF-Token": info["csrf_token"]},
                  {"Origin": ORIGIN, "X-CSRF-Token": "wrong"},
                  {"Origin": ORIGIN, "X-CSRF-Token": info["csrf_token"], "Sec-Fetch-Site": "same-site"}):
        with pytest.raises(CSRFError):
            service.csrf_check(method, {**headers, **extra})
    service.csrf_check(method, {**headers, "Origin": ORIGIN, "X-CSRF-Token": info["csrf_token"]})
    assert service.resolve_session(headers)


def test_csrf_not_transferable_between_sessions(service, provider):
    first, second = authenticated(service, provider), authenticated(service, provider)
    _, info = service.session_info(first)
    with pytest.raises(CSRFError):
        service.csrf_check("POST", {**second, "Origin": ORIGIN, "X-CSRF-Token": info["csrf_token"]})


def test_duplicate_cookie_origin_and_authorization_headers_rejected(service, provider):
    headers = authenticated(service, provider)
    _, info = service.session_info(headers)
    bad = {"Cookie": headers["Cookie"] + "; " + headers["Cookie"]}
    fail(lambda: service.resolve_session(bad))
    fail(lambda: service.resolve_session({**headers, "Authorization": "Bearer ambiguous"}))
    doubled = Headers(raw=[(b"cookie", headers["Cookie"].encode()), (b"cookie", headers["Cookie"].encode())])
    fail(lambda: service.resolve_session(doubled))
    duplicate_origin = Headers(raw=[(b"cookie", headers["Cookie"].encode()),
                                   (b"origin", ORIGIN.encode()), (b"origin", ORIGIN.encode()),
                                   (b"x-csrf-token", info["csrf_token"].encode())])
    with pytest.raises(CSRFError):
        service.csrf_check("POST", duplicate_origin)


def advance(monkeypatch, seconds):
    wall, mono = time.time(), time.monotonic()
    monkeypatch.setattr(sessions.time, "time", lambda: wall + seconds)
    monkeypatch.setattr(sessions.time, "monotonic", lambda: mono + seconds)


def test_idle_absolute_expiry_and_no_restart_persistence(configured, provider, monkeypatch):
    config, access = configured
    service = SessionService(replace(config, idle_timeout_s=30, absolute_timeout_s=60), OIDCValidator(access))
    headers = authenticated(service, provider)
    fail(lambda: SessionService(config, OIDCValidator(access)).resolve_session(headers))
    advance(monkeypatch, 31)
    fail(lambda: service.resolve_session(headers))
    headers = authenticated(service, provider)
    advance(monkeypatch, 20)
    assert service.resolve_session(headers)
    advance(monkeypatch, 20)
    assert service.resolve_session(headers)
    advance(monkeypatch, 21)
    fail(lambda: service.resolve_session(headers))


def test_pending_expiration_and_restart(configured, provider, monkeypatch):
    config, access = configured
    service = SessionService(replace(config, login_timeout_s=30), OIDCValidator(access))
    query, headers = begin(service, provider)
    fail(lambda: SessionService(config, OIDCValidator(access)).complete_login(query, headers))
    advance(monkeypatch, 31)
    fail(lambda: service.complete_login(query, headers))
    assert not provider.posts


def test_clock_rollback_invalidates_all_state(service, provider, monkeypatch):
    headers = authenticated(service, provider)
    query, pending = begin(service, provider)
    wall = time.time()
    monkeypatch.setattr(sessions.time, "time", lambda: wall - 61)
    fail(lambda: service.resolve_session(headers))
    assert not service._sessions and not service._pending
    monkeypatch.setattr(sessions.time, "time", lambda: wall + 1)
    fail(lambda: service.complete_login(query, pending))


def test_system_suspend_expires_session_and_transaction(configured, provider, monkeypatch):
    config, access = configured
    service = SessionService(replace(config, idle_timeout_s=60, absolute_timeout_s=60,
                                     login_timeout_s=30), OIDCValidator(access))
    headers = authenticated(service, provider)
    query, pending = begin(service, provider)
    wall, mono = time.time(), time.monotonic()
    monkeypatch.setattr(sessions.time, "time", lambda: wall + 61)
    monkeypatch.setattr(sessions.time, "monotonic", lambda: mono)
    fail(lambda: service.resolve_session(headers))
    fail(lambda: service.complete_login(query, pending))
    assert len(provider.posts) == 1


@pytest.mark.parametrize("idle_timeout", [30, 120])
def test_scheduler_pause_after_wall_sample_is_not_clock_rollback(configured, provider, monkeypatch, idle_timeout):
    config, access = configured
    service = SessionService(replace(config, idle_timeout_s=idle_timeout), OIDCValidator(access))
    headers = authenticated(service, provider)
    _, guard = service.resolve_session_with_lease(headers)
    wall, mono, elapsed = service._wall, service._mono, service._elapsed
    sample = {"mono": mono + 1}

    def wall_before_pause():
        # The wall value is captured, then the thread is descheduled for 90s
        # before it can read monotonic again. Time must advance through the
        # pause, but this is not a backward wall-clock correction.
        sample["mono"] = mono + 91
        return wall + 1

    monkeypatch.setattr(sessions.time, "monotonic", lambda: sample["mono"])
    monkeypatch.setattr(sessions.time, "time", wall_before_pause)
    if idle_timeout == 30:
        with pytest.raises(PermissionError):
            guard()
        assert not service._sessions and not service._lease_index
    else:
        assert guard() is None
        assert service._sessions and service._lease_index
    assert not service._clock_failed
    assert service._elapsed == pytest.approx(elapsed + 91)
    assert service._wall == pytest.approx(wall + 91)
    # The next normal sample sees wall time at the end of the pause.
    monkeypatch.setattr(sessions.time, "time", lambda: wall + 91)
    if idle_timeout == 120:
        assert guard() is None


def test_reversed_monotonic_sample_bracket_latches_rejection(service, monkeypatch):
    wall, mono = service._wall, service._mono
    sample = {"mono": mono + 2}

    def reversed_sample():
        sample["mono"] = mono + 1
        return wall + 2

    monkeypatch.setattr(sessions.time, "monotonic", lambda: sample["mono"])
    monkeypatch.setattr(sessions.time, "time", reversed_sample)
    with pytest.raises(AuthenticationError):
        service._now()
    assert service._clock_failed


def test_token_expiry_rechecked_after_verification(service, provider, monkeypatch):
    provider.expires_in = 1
    headers = authenticated(service, provider)
    wall, mono = time.time(), time.monotonic()
    elapsed = {"value": 0}
    monkeypatch.setattr(sessions.time, "time", lambda: wall + elapsed["value"])
    monkeypatch.setattr(sessions.time, "monotonic", lambda: mono + elapsed["value"])
    original = service.access_validator.validate

    def delayed_validation(encoded):
        result = original(encoded)
        elapsed["value"] = 2
        return result

    monkeypatch.setattr(service.access_validator, "validate", delayed_validation)
    fail(lambda: service.resolve_session(headers))
    assert not service._sessions


def test_optional_refresh_absence_requires_login_at_access_expiry(service, provider, monkeypatch):
    original = provider.exchange

    def no_refresh(form, authorization):
        response = original(form, authorization)
        response.pop("refresh_token")
        return response

    monkeypatch.setattr(provider, "exchange", no_refresh)
    provider.expires_in = 1
    headers = authenticated(service, provider)
    advance(monkeypatch, 2)
    fail(lambda: service.resolve_session(headers))
    assert len(provider.posts) == 1 and not service._sessions


def test_capacity_and_login_rate_are_bounded(configured, provider):
    config, access = configured
    service = SessionService(replace(config, max_sessions=1, max_pending=1), OIDCValidator(access))
    query, headers = begin(service, provider)
    fail(lambda: service.start_login({}))
    session_id = service.complete_login(query, headers)
    query, headers = begin(service, provider)
    fail(lambda: service.complete_login(query, headers))
    assert len(service._sessions) == 1 and len(provider.posts) == 1
    assert service.resolve_session({"Cookie": f"{SESSION_COOKIE}={session_id}"})
    other = SessionService(config, OIDCValidator(access))
    for _ in range(20):
        other.start_login({})
    fail(lambda: other.start_login({}))
    assert len(other._pending) == 20


def test_refresh_rotation_concurrency_and_identity_revalidation(service, provider, monkeypatch):
    provider.expires_in = 1
    headers = authenticated(service, provider)
    before = next(iter(service._sessions.values())).refresh_token
    provider.expires_in = 300
    provider.refresh_id = True
    advance(monkeypatch, 2)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: service.resolve_session(headers), range(8)))
    assert all(item["sub"] == "operator-123" for item in results)
    assert len(provider.posts) == 2
    assert next(iter(service._sessions.values())).refresh_token != before


@pytest.mark.parametrize("attack", ["reuse-refresh", "changed-subject", "changed-nonce", "provider-error", "bad-signature"])
def test_refresh_failure_destroys_local_session(service, provider, monkeypatch, attack):
    provider.expires_in = 1
    headers = authenticated(service, provider)
    if attack == "reuse-refresh":
        provider.reuse_refresh = True
    elif attack == "changed-subject":
        provider.access_changes["sub"] = "other-person"
    elif attack == "changed-nonce":
        provider.refresh_id = True
        provider.id_changes["nonce"] = "wrong"
    elif attack == "provider-error":
        provider.http_status = 400
    elif attack == "bad-signature":
        provider.signer = "rogue"
    advance(monkeypatch, 2)
    fail(lambda: service.resolve_session(headers))
    assert not service._sessions
    fail(lambda: service.resolve_session(headers))
    assert len(provider.posts) == 2


def test_refresh_cannot_extend_absolute_expiration(configured, provider, monkeypatch):
    config, access = configured
    service = SessionService(replace(config, idle_timeout_s=60, absolute_timeout_s=60), OIDCValidator(access))
    provider.expires_in = 1
    headers = authenticated(service, provider)
    advance(monkeypatch, 40)
    assert service.resolve_session(headers)
    advance(monkeypatch, 21)
    fail(lambda: service.resolve_session(headers))
    assert len(provider.posts) == 2


def test_confidential_secret_reference_is_basic_only_and_not_logged(configured, provider, monkeypatch, caplog):
    config, access = configured
    secret = "fixture-client-credential:+/ value"
    monkeypatch.setenv("CT_CRED_BROWSER", secret)
    from base64 import b64encode
    from urllib.parse import quote_plus
    provider.expected_basic = "Basic " + b64encode((quote_plus(CLIENT) + ":" + quote_plus(secret)).encode()).decode()
    provider.expires_in = 1
    service = SessionService(replace(config, client_secret_ref="BROWSER"), OIDCValidator(access))
    caplog.set_level("DEBUG")
    headers = authenticated(service, provider)
    _, form, request_headers = provider.posts[0]
    assert "client_secret" not in form and "client_id" not in form
    assert b64decode(request_headers["Authorization"].split()[1]).decode().endswith(quote_plus(secret))
    assert secret not in caplog.text
    assert next(iter(service._sessions.values())).access_token not in caplog.text
    advance(monkeypatch, 2)
    provider.expires_in = 300
    assert service.resolve_session(headers)
    assert len(provider.posts) == 2
    assert "client_secret" not in provider.posts[1][1] and "client_id" not in provider.posts[1][1]


def test_missing_secret_fails_before_http(configured, provider, monkeypatch):
    config, access = configured
    monkeypatch.delenv("CT_CRED_BROWSER", raising=False)
    service = SessionService(replace(config, client_secret_ref="BROWSER"), OIDCValidator(access))
    query, headers = begin(service, provider)
    fail(lambda: service.complete_login(query, headers))
    assert not provider.posts


@pytest.mark.parametrize("attack", ["redirect", "oversize", "oversize-unframed", "gzip", "html", "duplicate-json", "invalid-json", "error"])
def test_token_http_is_bounded_and_has_no_redirects(service, provider, attack):
    if attack == "redirect":
        provider.http_status = 302
        provider.http_headers["Location"] = provider.url + "/credential-sink"
    elif attack.startswith("oversize"):
        provider.raw_response = b" " * 65537
        provider.omit_length = attack.endswith("unframed")
    elif attack == "gzip":
        provider.http_headers["Content-Encoding"] = "gzip"
    elif attack == "html":
        provider.http_headers["Content-Type"] = "text/html"
    elif attack == "duplicate-json":
        provider.raw_response = b'{"access_token":"a","access_token":"b"}'
    elif attack == "invalid-json":
        provider.raw_response = b"provider-private-error"
    elif attack == "error":
        provider.http_status = 500
    query, headers = begin(service, provider)
    fail(lambda: service.complete_login(query, headers))
    assert len(provider.posts) == 1 and not service._sessions


def test_http_total_deadline_and_no_proxy_use(service, provider, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy-user:proxy-credential@127.0.0.1:1")
    monkeypatch.setattr(sessions, "HTTP_TIMEOUT_S", 1)
    provider.slow = True
    query, headers = begin(service, provider)
    started = time.monotonic()
    fail(lambda: service.complete_login(query, headers))
    assert 0.8 <= time.monotonic() - started < 3
    assert len(provider.posts) == 1


@pytest.mark.parametrize("attack", ["untrusted-ca", "wrong-host"])
def test_token_endpoint_tls_verification(configured, provider, monkeypatch, tmp_path, attack):
    config, access = configured
    if attack == "untrusted-ca":
        monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "absent.pem"))
        monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path / "absent"))
    else:
        config = replace(config, token_endpoint=config.token_endpoint.replace("127.0.0.1", "localhost"))
    service = SessionService(config, OIDCValidator(access))
    query, headers = begin(service, provider)
    fail(lambda: service.complete_login(query, headers))
    assert not provider.posts


@pytest.fixture
def browser(configured):
    config, access = configured
    ctx = SimpleNamespace(settings=SimpleNamespace(auth_mode="oidc"), session_config=config,
                          session_status_identity=lambda claims: {
                              "principal": {"actor": claims["sub"], "roles": ["reader"], "verified": True,
                                            "access_token": "must-not-leak"}, "permissions": ["scan.read"]})
    app = FastAPI()
    service = install_sessions(app, ctx, OIDCValidator(access))
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        yield client, service, ctx


def browser_login(client, provider):
    response = client.get("/auth/login")
    assert response.status_code == 303
    query = provider.authorize(response.headers["location"])
    return client.get("/auth/callback?" + query)


def test_routes_cookies_status_logout_and_no_token_exposure(browser, provider):
    client, service, ctx = browser
    assert client.get("/auth/status").json() == {"mode": "oidc", "authenticated": False, "login_available": True, "permissions": []}
    response = browser_login(client, provider)
    assert response.status_code == 303 and response.headers["location"] == ORIGIN + "/"
    for cookie in response.headers.get_list("set-cookie"):
        assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie and "Path=/" in cookie
        assert "Domain=" not in cookie
    status = client.get("/auth/status")
    body = status.json()
    assert body["authenticated"] and body["principal"]["actor"] == "operator-123"
    assert body["permissions"] == ["scan.read"] and "access_token" not in body["principal"]
    item = next(iter(service._sessions.values()))
    assert item.access_token not in status.text and item.refresh_token not in status.text
    assert item.access_token not in response.headers["set-cookie"]
    assert status.headers["cache-control"] == "no-store" and status.headers["referrer-policy"] == "no-referrer"
    bad = client.post("/auth/logout")
    assert bad.status_code == 403 and "set-cookie" not in bad.headers
    assert client.get("/auth/status").json()["authenticated"]
    result = client.post("/auth/logout", headers={"Origin": ORIGIN, "X-CSRF-Token": body["csrf_token"]})
    assert result.status_code == 204 and not service._sessions
    assert all("Max-Age=0" in value for value in result.headers.get_list("set-cookie"))
    assert not client.get("/auth/status").json()["authenticated"]


def test_fixed_redirects_ignore_host_forwarded_and_reject_next(browser, provider):
    client, service, _ = browser
    assert client.get("/auth/login?next=https://evil.example.test").status_code == 401
    initial = client.get("/auth/login", headers={"Host": "evil.example.test", "X-Forwarded-Host": "evil.example.test"})
    params = parse_qs(urlsplit(initial.headers["location"]).query)
    assert params["redirect_uri"] == [ORIGIN + "/auth/callback"]
    query = provider.authorize(initial.headers["location"])
    # Supply the issued binding cookie explicitly; the spoofed host never picks a return URL.
    cookie = initial.headers["set-cookie"].split(";", 1)[0]
    callback = client.get("/auth/callback?" + query, headers={"Cookie": cookie, "Host": "evil.example.test"})
    assert callback.status_code == 303 and callback.headers["location"] == ORIGIN + "/"


def test_callback_error_safe_status_and_failed_projection(browser, provider):
    client, service, ctx = browser
    provider.id_changes["nonce"] = "wrong"
    response = browser_login(client, provider)
    assert response.status_code == 401 and response.json() == {"detail": "Authentication failed"}
    assert not client.get("/auth/status").json()["authenticated"]
    provider.id_changes.clear()
    assert browser_login(client, provider).status_code == 303
    ctx.session_status_identity = lambda claims: {"principal": {}, "permissions": "invalid"}
    body = client.get("/auth/status").json()
    assert not body["authenticated"] and "csrf_token" not in body


def test_callback_query_is_redacted_even_when_decoding_fails(browser):
    client, _, _ = browser
    endpoint = next(route.endpoint for route in client.app.routes if route.path == "/auth/callback")
    request = Request({"type": "http", "method": "GET", "scheme": "https", "path": "/auth/callback",
                       "query_string": b"\xffprovider-private-query", "headers": []})
    response = endpoint(request)
    assert response.status_code == 401 and request.scope["query_string"] == b""
    assert b"provider-private-query" not in response.body


def logout_headers(service, headers):
    _, info = service.session_info(headers)
    return {**headers, "Origin": ORIGIN, "X-CSRF-Token": info["csrf_token"]}


def test_guard_contains_no_credentials_and_fingerprint_cannot_authenticate(service, provider, monkeypatch):
    headers = authenticated(service, provider)
    headers["X-Unrelated-Private"] = "never-capture-this-request-value"
    claims, lease = service.resolve_session_with_lease(headers)
    other = service.session_guard(headers)
    item = next(iter(service._sessions.values()))
    cookie = headers["Cookie"].split("=", 1)[1]
    assert claims["sub"] == "operator-123" and len(lease.fingerprint) == 64
    assert lease.fingerprint == other.fingerprint
    assert lease.fingerprint == hashlib.sha256(b"ct-session-lease-v1\0" + cookie.encode()).hexdigest()
    assert isinstance(lease._service, weakref.ReferenceType)
    assert not hasattr(lease, "__dict__")
    for secret in (cookie, item.access_token, item.refresh_token, headers["X-Unrelated-Private"]):
        assert secret not in repr(lease) and secret != lease.fingerprint
    headers.clear()
    before = item.last_used
    monkeypatch.setattr(service, "_exchange", lambda *a: pytest.fail("Guard performed token exchange"))
    monkeypatch.setattr(service.access_validator, "validate", lambda *a: pytest.fail("Guard revalidated JWT"))
    assert lease() is None and other() is None
    assert item.last_used == before
    fail(lambda: service.resolve_session({"Cookie": f"{SESSION_COOKIE}={lease.fingerprint}"}))


def test_background_context_guard_rejects_next_command_after_logout(service, provider):
    headers = authenticated(service, provider)
    claims, lease = service.resolve_session_with_lease(headers)
    validity = ContextVar("fixture-session-validity")
    validity.set(lease)
    before_logout = threading.Event()
    after_logout = threading.Event()
    commands = []

    def job():
        validity.get()()
        commands.append("before logout")
        before_logout.set()
        assert after_logout.wait(3)
        validity.get()()
        commands.append("after logout")

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(copy_context().run, job)
        try:
            assert before_logout.wait(3)
            service.logout(logout_headers(service, headers))
        finally:
            after_logout.set()
        with pytest.raises(PermissionError, match="^The browser session is no longer authorized$"):
            future.result(timeout=3)
    assert commands == ["before logout"]
    assert not service._sessions and not service._lease_index
    with pytest.raises(PermissionError):
        lease()
    assert claims["exp"] > time.time()


def test_compatibility_guard_raises_after_logout(service, provider):
    headers = authenticated(service, provider)
    assert service.resolve_session(headers)
    guard = service.session_guard(headers)
    assert guard() is None
    service.logout(logout_headers(service, headers))
    with pytest.raises(PermissionError):
        guard()
    assert service.resolve_session_with_lease({}) is None


def test_replacement_login_revokes_old_guard(service, provider):
    headers = authenticated(service, provider)
    _, old_guard = service.resolve_session_with_lease(headers)
    query, binding = begin(service, provider, headers)
    new_cookie = service.complete_login(query, {"Cookie": headers["Cookie"] + "; " + binding["Cookie"]})
    with pytest.raises(PermissionError):
        old_guard()
    _, new_guard = service.resolve_session_with_lease({"Cookie": f"{SESSION_COOKIE}={new_cookie}"})
    assert new_guard() is None and old_guard.fingerprint != new_guard.fingerprint
    assert len(service._lease_index) == len(service._sessions) == 1


def test_guard_checks_do_not_extend_idle_timeout(configured, provider, monkeypatch):
    config, access = configured
    service = SessionService(replace(config, idle_timeout_s=30), OIDCValidator(access))
    headers = authenticated(service, provider)
    _, guard = service.resolve_session_with_lease(headers, touch=False)
    original_last_used = next(iter(service._sessions.values())).last_used
    for _ in range(5):
        advance(monkeypatch, 5)
        assert guard() is None
        assert service.session_guard(headers)() is None
    assert next(iter(service._sessions.values())).last_used == original_last_used
    advance(monkeypatch, 6)
    with pytest.raises(PermissionError):
        guard()
    assert not service._lease_index


def test_guard_absolute_expiry_despite_real_activity(configured, provider, monkeypatch):
    config, access = configured
    service = SessionService(replace(config, idle_timeout_s=30, absolute_timeout_s=60), OIDCValidator(access))
    headers = authenticated(service, provider)
    _, guard = service.resolve_session_with_lease(headers)
    for _ in range(2):
        advance(monkeypatch, 20)
        assert service.resolve_session(headers) and guard() is None
    advance(monkeypatch, 21)
    with pytest.raises(PermissionError):
        guard()
    assert not service._lease_index


def test_guard_never_refreshes_or_revives_after_browser_refresh(service, provider, monkeypatch):
    provider.expires_in = 1
    headers = authenticated(service, provider)
    _, old_guard = service.resolve_session_with_lease(headers)
    original_idle = next(iter(service._sessions.values())).last_used
    advance(monkeypatch, 2)
    with pytest.raises(PermissionError):
        old_guard()
    assert len(provider.posts) == 1
    provider.expires_in = 300
    _, new_guard = service.resolve_session_with_lease(headers, touch=False)
    assert len(provider.posts) == 2 and new_guard() is None
    assert next(iter(service._sessions.values())).last_used == original_idle
    with pytest.raises(PermissionError):
        old_guard()


def test_failed_refresh_revokes_guard_and_removes_index(service, provider, monkeypatch):
    provider.expires_in = 1
    headers = authenticated(service, provider)
    _, guard = service.resolve_session_with_lease(headers)
    provider.http_status = 400
    advance(monkeypatch, 2)
    fail(lambda: service.resolve_session(headers, touch=False))
    with pytest.raises(PermissionError):
        guard()
    assert not service._sessions and not service._lease_index


def test_guard_clock_rollback_and_service_loss(configured, provider, monkeypatch):
    config, access = configured
    temporary = SessionService(config, OIDCValidator(access))
    _, orphan = temporary.resolve_session_with_lease(authenticated(temporary, provider))
    reference = weakref.ref(temporary)
    del temporary
    gc.collect()
    assert reference() is None
    with pytest.raises(PermissionError):
        orphan()
    current = SessionService(config, OIDCValidator(access))
    _, guard = current.resolve_session_with_lease(authenticated(current, provider))
    wall = time.time()
    monkeypatch.setattr(sessions.time, "time", lambda: wall - 61)
    with pytest.raises(PermissionError):
        guard()
    assert not current._sessions and not current._lease_index


def test_passive_resolution_and_status_do_not_extend_idle(configured, provider, monkeypatch):
    config, access = configured
    service = SessionService(replace(config, idle_timeout_s=30), OIDCValidator(access))
    headers = authenticated(service, provider)
    initial = next(iter(service._sessions.values())).last_used
    for _ in range(5):
        advance(monkeypatch, 5)
        assert service.resolve_session(headers, touch=False)
        assert service.resolve_session_with_lease(headers, touch=False)[1]() is None
        assert service.session_info(headers)[1]["authenticated"]
    assert next(iter(service._sessions.values())).last_used == initial
    advance(monkeypatch, 6)
    fail(lambda: service.session_info(headers))
    assert not service._sessions and not service._lease_index


def test_auth_status_polling_refresh_still_expires_idle(browser, provider, monkeypatch):
    client, service, _ = browser
    provider.expires_in = 1
    assert browser_login(client, provider).status_code == 303
    initial = next(iter(service._sessions.values())).last_used
    provider.expires_in = 300
    advance(monkeypatch, 2)
    assert client.get("/auth/status").json()["authenticated"]
    assert len(provider.posts) == 2
    assert next(iter(service._sessions.values())).last_used == initial
    for _ in range(14):
        advance(monkeypatch, 60)
        assert client.get("/auth/status").json()["authenticated"]
        assert next(iter(service._sessions.values())).last_used == initial
    advance(monkeypatch, 60)
    assert not client.get("/auth/status").json()["authenticated"]
    assert not service._sessions and not service._lease_index


def test_active_requests_touch_idle_but_false_is_strict(configured, provider, monkeypatch):
    config, access = configured
    service = SessionService(replace(config, idle_timeout_s=30), OIDCValidator(access))
    headers = authenticated(service, provider)
    initial = next(iter(service._sessions.values())).last_used
    advance(monkeypatch, 20)
    assert service.resolve_session(headers)
    assert next(iter(service._sessions.values())).last_used > initial
    advance(monkeypatch, 20)
    assert service.resolve_session_with_lease(headers)[1]() is None
    fail(lambda: service.resolve_session(headers, touch="false"))
    assert service.resolve_session(headers, touch=False)


@pytest.mark.parametrize("mode", ["dev", "oidc", "mesh"])
def test_sessionless_status_never_verifies_typed_actor(mode):
    app = FastAPI()
    ctx = SimpleNamespace(settings=SimpleNamespace(auth_mode=mode))
    assert install_sessions(app, ctx, None) is None
    with TestClient(app, base_url=ORIGIN) as client:
        response = client.get("/auth/status", headers={"X-Actor": "typed-person"})
        assert response.json() == {"mode": mode, "authenticated": False, "login_available": False, "permissions": []}
        assert client.get("/auth/login").status_code == 404
        assert client.post("/auth/logout").status_code == 404
