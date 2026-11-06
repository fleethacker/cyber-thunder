"""Signed adversarial tokens and real, isolated HTTPS JWKS endpoints."""

from base64 import urlsafe_b64encode
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
import ssl
import subprocess
import threading
import time
import traceback

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
import jwt
import pytest

from cyberthunder.security import _oidc_cache, oidc
from cyberthunder.security.oidc import AuthenticationError, OIDCConfig, OIDCValidator

ISSUER = "https://issuer.example.test/tenant"
AUDIENCE = "cyber-thunder"


def b64(data):
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.fixture(scope="session")
def signing_keys():
    return {"rsa": rsa.generate_private_key(public_exponent=65537, key_size=2048),
            "ec": ec.generate_private_key(ec.SECP256R1()),
            "rogue": rsa.generate_private_key(public_exponent=65537, key_size=2048)}


def jwk(key, kid="rsa", alg=None):
    if isinstance(key, rsa.RSAPrivateKey):
        value = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        algorithm = "RS256"
    else:
        value = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
        algorithm = "ES256"
    value.update(kid=kid, alg=alg or algorithm, use="sig", key_ops=["verify"])
    return value


def claims(**changes):
    now = int(time.time())
    value = {"iss": ISSUER, "sub": "operator-123", "aud": AUDIENCE,
             "iat": now - 2, "exp": now + 300}
    value.update(changes)
    return value


def token(keys, payload=None, *, kid="rsa", key_name=None, headers=None, algorithm=None):
    key = keys[key_name or kid]
    alg = algorithm or ("RS256" if isinstance(key, rsa.RSAPrivateKey) else "ES256")
    # JWS encoding permits intentionally invalid claim types in signed fixtures.
    body = json.dumps(claims() if payload is None else payload).encode()
    return jwt.api_jws.encode(body, key, algorithm=alg, headers={"kid": kid, **(headers or {})})


def rejected(validator, encoded):
    with pytest.raises(AuthenticationError) as error:
        validator.validate(encoded)
    assert str(error.value) == "Authentication failed"
    assert error.value.__cause__ is None
    assert error.value.__suppress_context__
    rendered = "".join(traceback.format_exception(error.value))
    # Credentials must not enter public exception text or displayed chains.
    if isinstance(encoded, str) and len(encoded) > 20:
        assert encoded not in rendered
    return error


@pytest.fixture(scope="session")
def certificates(tmp_path_factory):
    directory = tmp_path_factory.mktemp("oidc-certificates")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OIDC loopback test CA")])
    now = datetime.now(timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
          .not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(key, hashes.SHA256()))
    ca_path = directory / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    files = {}
    for label, dns in (("valid", "localhost"), ("wrong-host", "wrong.example.test")):
        server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns)])
        names = [x509.DNSName(dns)]
        if label == "valid":
            names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(name)
                .public_key(server_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName(names), critical=False)
                .sign(key, hashes.SHA256()))
        cert_path, key_path = directory / f"{label}.pem", directory / f"{label}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(server_key.private_bytes(serialization.Encoding.PEM,
                                                     serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()))
        files[label] = (cert_path, key_path)
    return ca_path, files


@pytest.fixture
def https_server(certificates, monkeypatch):
    ca_path, files = certificates
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_path))
    servers = []

    def start(document, certificate="valid"):
        state = {"body": json.dumps(document).encode(), "status": 200, "headers": {},
                 "requests": [], "slow_headers": False, "slow_body": False,
                 "omit_length": False, "extra_headers": []}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                state["requests"].append((self.path, dict(self.headers)))
                try:
                    if state["slow_headers"]:
                        self.connection.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                        while not stopped.wait(0.03):
                            self.connection.sendall(b"x")
                        return
                    self.send_response(state["status"])
                    headers = {"Content-Type": "application/json", **state["headers"]}
                    if not state["omit_length"]:
                        headers.setdefault("Content-Length", str(len(state["body"])))
                    for name, value in [*headers.items(), *state["extra_headers"]]:
                        self.send_header(name, value)
                    self.end_headers()
                    if state["slow_body"]:
                        while not stopped.wait(0.03):
                            self.wfile.write(b" ")
                            self.wfile.flush()
                    else:
                        self.wfile.write(state["body"])
                except (OSError, ssl.SSLError):
                    pass

        class Server(ThreadingHTTPServer):
            daemon_threads = True

        server = Server(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*map(str, files[certificate]))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        stopped = threading.Event()
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        worker.start()
        servers.append((server, worker, stopped))
        state["url"] = f"https://127.0.0.1:{server.server_port}/jwks"
        return state

    yield start
    for server, worker, stopped in servers:
        stopped.set()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
        assert not worker.is_alive()


@pytest.fixture
def environment(tmp_path, signing_keys, https_server):
    server = https_server({"keys": [jwk(signing_keys["rsa"]), jwk(signing_keys["ec"], "ec")]})
    config = OIDCConfig(ISSUER, AUDIENCE, server["url"], tmp_path / "jwks.json")
    return config, server


def offline_config(tmp_path, signing_keys, *, fetched=None, observed=None, jwks=None, **changes):
    config = OIDCConfig(ISSUER, AUDIENCE, "https://issuer.example.test/jwks", tmp_path / "jwks.json", **changes)
    now = int(time.time())
    fetched = now if fetched is None else fetched
    body = {"version": 1, "issuer": config.issuer, "audience": config.audience,
            "authorized_party": config.authorized_party, "jwks_url": config.jwks_url,
            "fetched_at": fetched, "observed_at": max(fetched, now) if observed is None else observed,
            "jwks": jwks or {"keys": [jwk(signing_keys["rsa"]), jwk(signing_keys["ec"], "ec")]}}
    _oidc_cache.write_cache(config.cache_path, json.dumps(body).encode())
    return config


@pytest.fixture
def offline(tmp_path, signing_keys, monkeypatch):
    config = offline_config(tmp_path, signing_keys)

    def no_network(*args, **kwargs):
        pytest.fail("Unexpected network access")

    monkeypatch.setattr(oidc.subprocess, "run", no_network)
    return OIDCValidator(config)


@pytest.mark.parametrize("kid", ["rsa", "ec"])
def test_signed_tokens_https_then_restart_offline(environment, signing_keys, monkeypatch, kid):
    config, server = environment
    encoded = token(signing_keys, kid=kid)
    expected = claims()
    validator = OIDCValidator(config)
    result = validator.validate(encoded)
    assert result["sub"] == expected["sub"]
    assert len(server["requests"]) == 1
    assert config.cache_path.exists()
    cache = json.loads(config.cache_path.read_bytes())
    assert "d" not in cache["jwks"]["keys"][0]
    assert encoded not in config.cache_path.read_text()
    monkeypatch.setattr(oidc.subprocess, "run", lambda *a, **k: pytest.fail("Offline cache performed a fetch"))
    assert OIDCValidator(config).validate(encoded) == result


@pytest.mark.parametrize("field,value", [
    ("iss", "https://issuer.example.test/tenant/"), ("iss", "https://evil.example.test/"),
    ("iss", [ISSUER]), ("iss", None), ("sub", ""), ("sub", "x" * 256),
    ("sub", 12), ("sub", True), ("sub", ["operator"]), ("sub", "line\nbreak"),
    ("sub", "\ud800"), ("sub", "é"), ("aud", "other"), ("aud", []), ("aud", None),
    ("aud", [AUDIENCE, 1]), ("aud", [AUDIENCE, AUDIENCE]), ("aud", {AUDIENCE: True}),
    ("aud", [AUDIENCE, "other"]), ("aud", [AUDIENCE] * 17),
    ("azp", "other"), ("azp", None), ("azp", []), ("azp", True),
    ("iat", True), ("iat", "123"), ("iat", 1.5), ("iat", None), ("iat", -1),
    ("iat", 253402300800), ("exp", True), ("exp", "9999999999"), ("exp", 1.5),
    ("exp", None), ("exp", -1), ("exp", 253402300800),
    ("nbf", True), ("nbf", "123"), ("nbf", None), ("nbf", -1),
    ("auth_time", True), ("auth_time", "123"), ("auth_time", None),
    ("jti", None), ("jti", []), ("jti", ""),
])
def test_signed_invalid_claim_types_and_values(offline, signing_keys, field, value):
    rejected(offline, token(signing_keys, claims(**{field: value})))


@pytest.mark.parametrize("missing", ["iss", "sub", "aud", "iat", "exp"])
def test_required_claims(offline, signing_keys, missing):
    payload = claims()
    payload.pop(missing)
    rejected(offline, token(signing_keys, payload))


@pytest.mark.parametrize("changes", [
    {"iat": 61, "exp": 500}, {"iat": -100, "exp": -60}, {"iat": -100, "exp": -61},
    {"iat": 0, "exp": 3601}, {"iat": 0, "exp": 0}, {"iat": 1, "exp": 0},
    {"iat": -4000, "exp": 100}, {"nbf": 61}, {"nbf": 300}, {"nbf": -500},
    {"auth_time": 61},
])
def test_lifetime_and_time_boundaries(offline, signing_keys, monkeypatch, changes):
    now = int(time.time())
    monkeypatch.setattr(oidc.time, "time", lambda: now)
    payload = claims(iat=now, exp=now + 300)
    payload.update({key: now + value for key, value in changes.items()})
    rejected(offline, token(signing_keys, payload))


def test_skew_and_one_hour_lifetime_accepted(offline, signing_keys, monkeypatch):
    now = int(time.time())
    monkeypatch.setattr(oidc.time, "time", lambda: now)
    for payload in (claims(iat=now + 59, exp=now + 3600), claims(iat=now - 300, exp=now - 59),
                    claims(iat=now, exp=now + 3600, nbf=now + 59),
                    claims(auth_time=now - 86400), claims(aud=[AUDIENCE, "second"], azp=AUDIENCE)):
        assert offline.validate(token(signing_keys, payload))["sub"] == "operator-123"


def test_explicit_authorized_party_required(tmp_path, signing_keys):
    config = offline_config(tmp_path, signing_keys, authorized_party="operator-client")
    validator = OIDCValidator(config)
    rejected(validator, token(signing_keys))
    rejected(validator, token(signing_keys, claims(azp=AUDIENCE)))
    assert validator.validate(token(signing_keys, claims(azp="operator-client")))["azp"] == "operator-client"


@pytest.mark.parametrize("algorithm", ["none", "HS256", "HS384", "HS512", "RS384", "RS512", "PS256", "ES384"])
def test_algorithm_allowlist(offline, signing_keys, algorithm):
    if algorithm == "none":
        key = None
    elif algorithm.startswith("HS"):
        # Classic confusion attempt: the public RSA bytes become an HMAC key.
        key = signing_keys["rsa"].public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    elif algorithm == "ES384":
        key = ec.generate_private_key(ec.SECP384R1())
    else:
        key = signing_keys["rsa"]
    if algorithm.startswith("HS"):
        content = (b64(json.dumps({"alg": algorithm, "kid": "rsa"}).encode())
                   + "." + b64(json.dumps(claims()).encode())).encode()
        encoded = content.decode() + "." + b64(hmac.digest(key, content, getattr(hashlib, "sha" + algorithm[2:])))
    else:
        encoded = jwt.encode(claims(), key, algorithm=algorithm, headers={"kid": "rsa"})
    rejected(offline, encoded)


def test_key_and_algorithm_must_match(offline, signing_keys):
    rejected(offline, token(signing_keys, kid="rsa", key_name="ec"))
    rejected(offline, token(signing_keys, kid="ec", key_name="rsa"))


def test_wrong_signer_and_tampered_payload(offline, signing_keys):
    rejected(offline, token(signing_keys, kid="rsa", key_name="rogue"))
    header, payload, signature = token(signing_keys).split(".")
    changed = b64(json.dumps(claims(sub="administrator")).encode())
    rejected(offline, ".".join((header, changed, signature)))
    raw = bytearray(jwt.utils.base64url_decode(signature))
    raw[0] ^= 1
    rejected(offline, ".".join((header, payload, b64(bytes(raw)))))


def test_signature_verification_is_explicit_even_if_library_defaults_change(offline, signing_keys, monkeypatch):
    encoded = token(signing_keys, kid="rsa", key_name="rogue")
    monkeypatch.setitem(jwt.api_jws.decode_complete.__self__.options, "verify_signature", False)
    rejected(offline, encoded)


@pytest.mark.parametrize("header", [
    {"kid": ""}, {"kid": "x" * 129}, {"kid": None}, {"kid": ["rsa"]}, {"kid": 1},
    {"kid": "rsa\n"}, {"kid": "é"}, {"jku": "https://127.0.0.1/evil"},
    {"x5u": "https://127.0.0.1/evil"}, {"jwk": {}}, {"x5c": []},
    {"crit": []}, {"crit": ["custom"]}, {"zip": "DEF"}, {"b64": True},
    {"typ": "at+jwt"}, {"typ": "other"},
])
def test_invalid_or_remote_headers(offline, signing_keys, header):
    # PyJWT's encoder rejects invalid kid types, so sign exact raw header bytes.
    value = {"alg": "RS256", "typ": "JWT", "kid": "rsa", **header}
    encoded = raw_signed(signing_keys["rsa"], json.dumps(value), json.dumps(claims()))
    rejected(offline, encoded)


def raw_signed(key, header, payload):
    content = f"{b64(header.encode())}.{b64(payload.encode())}".encode("ascii")
    signature = jwt.algorithms.get_default_algorithms()["RS256"].sign(content, key)
    return content.decode() + "." + b64(signature)


@pytest.mark.parametrize("header,payload", [
    ('{"alg":"RS256","alg":"RS256","kid":"rsa"}', None),
    ('{"alg":"RS256","kid":"rsa","kid":"rsa"}', None),
    (None, '"sub":"operator-123"'), (None, '"extra":NaN'), (None, '"extra":Infinity'),
    (None, '"extra":1e999'), (None, '"extra":{"a":1,"a":2}'),
])
def test_signed_duplicate_json_members_and_nonfinite_values(offline, signing_keys, header, payload):
    header = header or '{"alg":"RS256","kid":"rsa"}'
    body = json.dumps(claims())
    if payload:
        body = body[:-1] + "," + payload + "}"
    rejected(offline, raw_signed(signing_keys["rsa"], header, body))


@pytest.mark.parametrize("value", [None, b"token", 12, "", "a.b", "a.b.c.d", "a.b.c", "é.b.c", "x" * 16385])
def test_malformed_and_oversized_tokens(offline, value):
    rejected(offline, value)


def test_deep_payload_and_padded_encoding(offline, signing_keys):
    value = 1
    for _ in range(35):
        value = [value]
    rejected(offline, token(signing_keys, claims(extra=value)))
    header, payload, signature = token(signing_keys).split(".")
    rejected(offline, f"{header}=.{payload}.{signature}")


@pytest.mark.parametrize("changes", [
    {"issuer": "http://issuer.example.test"}, {"issuer": ISSUER + "?q=1"},
    {"issuer": ISSUER + "#"}, {"issuer": "https://user:password@example.test"},
    {"jwks_url": "http://localhost/keys"}, {"jwks_url": "https://user:password@example.test/keys"},
    {"jwks_url": "https://@example.test/keys"}, {"jwks_url": "https://example.test:0/keys"},
    {"jwks_url": "https://example.test:99999/keys"}, {"jwks_url": "https://example.test/\nkeys"},
    {"jwks_url": "https://example.test/keys#fragment"}, {"jwks_url": "file:///keys.json"},
    {"audience": ""}, {"audience": [AUDIENCE]}, {"authorized_party": ""},
    {"max_age_s": 0}, {"max_age_s": 86401}, {"max_age_s": True}, {"max_age_s": 1.5},
    {"clock_skew_s": -1}, {"clock_skew_s": 301}, {"clock_skew_s": True},
    {"cache_path": "relative.json"},
])
def test_invalid_configuration(tmp_path, changes):
    options = {"issuer": ISSUER, "audience": AUDIENCE, "jwks_url": "https://issuer.example.test/jwks",
               "cache_path": tmp_path / "cache.json", **changes}
    with pytest.raises(AuthenticationError, match="^Authentication failed$"):
        OIDCConfig(**options)


@pytest.mark.parametrize("change", [
    {"kid": ""}, {"kid": []}, {"kid": 2}, {"kid": "x" * 129}, {"kid": "bad\n"},
    {"alg": "HS256"}, {"alg": "ES256"}, {"alg": None}, {"kty": "oct"}, {"kty": "EC"},
    {"use": "enc"}, {"key_ops": ["sign"]}, {"key_ops": ["verify", "sign"]},
    {"key_ops": ["verify", "verify"]}, {"key_ops": "verify"}, {"d": "private-value"},
    {"k": "symmetric-value"}, {"x5u": "https://other.example.test"},
    {"n": "AA"}, {"n": "!"}, {"n": "A" * 1367}, {"e": "Aw"}, {"e": "AQAB="},
])
def test_invalid_jwk_metadata_and_parameters(environment, signing_keys, change):
    config, server = environment
    server["body"] = json.dumps({"keys": [{**jwk(signing_keys["rsa"]), **change}]}).encode()
    rejected(OIDCValidator(config), token(signing_keys))
    assert not config.cache_path.exists()


@pytest.mark.parametrize("change", [
    {"crv": "P-384"}, {"crv": "secp256k1"}, {"crv": None}, {"x": "AA"},
    {"y": "AA"}, {"x": b64(bytes(32)), "y": b64(bytes(32))}, {"alg": "RS256"},
])
def test_ec_curve_and_point_validation(environment, signing_keys, change):
    config, server = environment
    server["body"] = json.dumps({"keys": [{**jwk(signing_keys["ec"], "ec"), **change}]}).encode()
    rejected(OIDCValidator(config), token(signing_keys, kid="ec"))


@pytest.mark.parametrize("kind", ["duplicate-kid", "duplicate-json", "empty", "many", "weak-rsa", "missing-kid"])
def test_invalid_jwks_sets(environment, signing_keys, kind):
    config, server = environment
    key = jwk(signing_keys["rsa"])
    sets = {"duplicate-kid": [key, jwk(signing_keys["rogue"], "rsa")], "empty": [],
            "many": [{**key, "kid": f"k{index}"} for index in range(33)],
            "missing-kid": [{k: v for k, v in key.items() if k != "kid"}]}
    if kind == "weak-rsa":
        weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        body = json.dumps({"keys": [jwk(weak)]}).encode()
    elif kind == "duplicate-json":
        body = ('{"keys": [], "keys":' + json.dumps([key]) + '}').encode()
    else:
        body = json.dumps({"keys": sets[kind]}).encode()
    server["body"] = body
    rejected(OIDCValidator(config), token(signing_keys))


def test_optional_jwk_alg_uses_key_type_and_discards_cert_metadata(environment, signing_keys):
    config, server = environment
    key = jwk(signing_keys["rsa"])
    key.pop("alg")
    key["x5c"] = ["unused certificate metadata"]
    server["body"] = json.dumps({"keys": [key]}).encode()
    assert OIDCValidator(config).validate(token(signing_keys))["sub"] == "operator-123"
    assert "x5c" not in config.cache_path.read_text()


def test_unknown_kid_rotation_refresh_is_deduplicated(environment, signing_keys, monkeypatch):
    config, server = environment
    OIDCValidator(config).validate(token(signing_keys))
    # A fresh process loads the already primed cache, then encounters rotation.
    validator = OIDCValidator(config)
    server["body"] = json.dumps({"keys": [jwk(signing_keys["rogue"], "rotated")]}).encode()
    encoded = token(signing_keys, kid="rotated", key_name="rogue")
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(validator.validate, [encoded] * 12))
    assert all(result["sub"] == "operator-123" for result in results)
    assert len(server["requests"]) == 2
    # Successful replacement immediately removes the old key.
    rejected(validator, token(signing_keys))
    assert len(server["requests"]) == 2


def test_unknown_kid_negative_cache_and_global_rate_limit(environment, signing_keys, monkeypatch):
    config, server = environment
    OIDCValidator(config).validate(token(signing_keys))
    validator = OIDCValidator(config)
    unknown = token(signing_keys, kid="unknown", key_name="rogue")
    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(lambda _: rejected(validator, unknown), range(10)))
    assert len(server["requests"]) == 2
    for index in range(300):
        rejected(validator, token(signing_keys, kid=f"missing-{index}", key_name="rogue"))
    assert len(server["requests"]) == 2
    assert len(validator._negative) == oidc.MAX_NEGATIVE_KIDS
    # Last rejected ID stays negatively cached beyond the 30s global interval.
    real_mono = time.monotonic
    real_wall = time.time
    mono, wall = real_mono(), real_wall()
    monkeypatch.setattr(oidc.time, "monotonic", lambda: mono + 31)
    monkeypatch.setattr(oidc.time, "time", lambda: wall + 31)
    rejected(validator, token(signing_keys, kid="missing-299", key_name="rogue"))
    assert len(server["requests"]) == 2
    # A different unknown ID can spend the next global refresh slot.
    rejected(validator, token(signing_keys, kid="new-missing", key_name="rogue"))
    assert len(server["requests"]) == 3
    monkeypatch.setattr(oidc.time, "monotonic", lambda: mono + 62)
    monkeypatch.setattr(oidc.time, "time", lambda: wall + 62)
    rejected(validator, token(signing_keys, kid="missing-299", key_name="rogue"))
    assert len(server["requests"]) == 4


def test_failed_rotation_keeps_valid_cached_keys_but_limits_attempts(environment, signing_keys):
    config, server = environment
    encoded = token(signing_keys)
    OIDCValidator(config).validate(encoded)
    validator = OIDCValidator(config)
    server["status"] = 503
    rejected(validator, token(signing_keys, kid="unknown", key_name="rogue"))
    rejected(validator, token(signing_keys, kid="another", key_name="rogue"))
    assert validator.validate(encoded)["sub"] == "operator-123"
    assert len(server["requests"]) == 2


def test_invalid_signature_never_refreshes_existing_kid(environment, signing_keys):
    config, server = environment
    validator = OIDCValidator(config)
    validator.validate(token(signing_keys))
    for _ in range(3):
        rejected(validator, token(signing_keys, kid="rsa", key_name="rogue"))
    assert len(server["requests"]) == 1


@pytest.mark.parametrize("state", ["expired", "future", "rollback", "bad-binding", "corrupt", "oversized"])
def test_untrusted_or_stale_cache_fails_closed(tmp_path, signing_keys, monkeypatch, state):
    now = int(time.time())
    options = {"fetched": now - 86401} if state == "expired" else {}
    if state == "future":
        options.update(fetched=now + 100, observed=now + 100)
    if state == "rollback":
        options.update(fetched=now - 10, observed=now + 100)
    config = offline_config(tmp_path, signing_keys, **options)
    if state == "bad-binding":
        body = json.loads(config.cache_path.read_bytes())
        body["issuer"] = "https://different.example.test"
        config.cache_path.write_text(json.dumps(body))
    if state == "corrupt":
        config.cache_path.write_bytes(b"not json")
    if state == "oversized":
        config.cache_path.write_bytes(b" " * (_oidc_cache.MAX_CACHE_BYTES + 1))
    attempts = []

    def unavailable(*args, **kwargs):
        attempts.append(True)
        raise OSError("unavailable secret-server-text")

    monkeypatch.setattr(oidc.subprocess, "run", unavailable)
    error = rejected(OIDCValidator(config), token(signing_keys))
    assert "secret-server-text" not in str(error.value)
    assert len(attempts) == (1 if state == "expired" else 0)


def test_expired_cache_can_refresh_over_https(environment, signing_keys):
    config, server = environment
    validator = OIDCValidator(config)
    validator.validate(token(signing_keys))
    cache = json.loads(config.cache_path.read_bytes())
    cache["fetched_at"] -= 86401
    config.cache_path.write_text(json.dumps(cache))
    assert OIDCValidator(config).validate(token(signing_keys))["sub"] == "operator-123"
    assert len(server["requests"]) == 2


def test_monotonic_age_prevents_clock_skew_extending_cache(tmp_path, signing_keys, monkeypatch):
    now, mono = int(time.time()), time.monotonic()
    config = offline_config(tmp_path, signing_keys, fetched=now - 99, max_age_s=100)
    monkeypatch.setattr(oidc.time, "time", lambda: now)
    monkeypatch.setattr(oidc.time, "monotonic", lambda: mono)
    validator = OIDCValidator(config)
    encoded = token(signing_keys)
    validator.validate(encoded)
    monkeypatch.setattr(oidc.time, "monotonic", lambda: mono + 2)
    monkeypatch.setattr(oidc.time, "time", lambda: now - 10)
    monkeypatch.setattr(oidc.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError("offline")))
    rejected(validator, encoded)


def test_clock_rollback_latches_even_after_clock_recovers(offline, signing_keys, monkeypatch):
    encoded = token(signing_keys)
    offline.validate(encoded)
    now = time.time()
    monkeypatch.setattr(oidc.time, "time", lambda: now - 61)
    rejected(offline, encoded)
    monkeypatch.setattr(oidc.time, "time", lambda: now + 5)
    rejected(offline, encoded)


def test_zero_skew_tolerates_clock_sampling_jitter(tmp_path, signing_keys, monkeypatch):
    now, mono = time.time(), time.monotonic()
    config = offline_config(tmp_path, signing_keys, clock_skew_s=0)
    monkeypatch.setattr(oidc.time, "time", lambda: now)
    monkeypatch.setattr(oidc.time, "monotonic", lambda: mono)
    validator = OIDCValidator(config)
    encoded = token(signing_keys)
    monkeypatch.setattr(oidc.time, "monotonic", lambda: mono + 0.0001)
    assert validator.validate(encoded)["sub"] == "operator-123"
    # Sampling tolerance is not token leeway.
    rejected(validator, token(signing_keys, claims(exp=int(now), iat=int(now) - 100)))


def test_token_expiring_during_fetch_is_rejected(environment, signing_keys, monkeypatch):
    config, server = environment
    config = replace(config, clock_skew_s=0)
    wall, mono = time.time(), time.monotonic()
    clock = {"elapsed": 0}
    monkeypatch.setattr(oidc.time, "time", lambda: wall + clock["elapsed"])
    monkeypatch.setattr(oidc.time, "monotonic", lambda: mono + clock["elapsed"])
    validator = OIDCValidator(config)
    original = validator._refresh

    def fetch_then_expire():
        original()
        clock["elapsed"] = 10

    monkeypatch.setattr(validator, "_refresh", fetch_then_expire)
    rejected(validator, token(signing_keys, claims(iat=int(wall), exp=int(wall) + 2)))
    assert len(server["requests"]) == 1


def test_clock_watermark_persists_across_restart(tmp_path, signing_keys, monkeypatch):
    now, mono = int(time.time()), time.monotonic()
    config = offline_config(tmp_path, signing_keys)
    monkeypatch.setattr(oidc.time, "time", lambda: now)
    monkeypatch.setattr(oidc.time, "monotonic", lambda: mono)
    validator = OIDCValidator(config)
    encoded = token(signing_keys, claims(iat=now - 5, exp=now + 300))
    validator.validate(encoded)
    monkeypatch.setattr(oidc.time, "time", lambda: now + 100)
    monkeypatch.setattr(oidc.time, "monotonic", lambda: mono + 100)
    validator.validate(encoded)
    assert json.loads(config.cache_path.read_bytes())["observed_at"] == now + 100
    monkeypatch.setattr(oidc.time, "time", lambda: now)
    rejected(OIDCValidator(config), encoded)


def test_disk_replacement_cannot_roll_back_live_keys(environment, signing_keys):
    config, server = environment
    OIDCValidator(config).validate(token(signing_keys))
    old_cache = config.cache_path.read_bytes()
    server["body"] = json.dumps({"keys": [jwk(signing_keys["rogue"], "rotated")]}).encode()
    validator = OIDCValidator(config)
    validator.validate(token(signing_keys, kid="rotated", key_name="rogue"))
    config.cache_path.write_bytes(old_cache)
    rejected(validator, token(signing_keys))


def test_atomic_write_failure_preserves_old_cache(environment, signing_keys, monkeypatch):
    config, server = environment
    OIDCValidator(config).validate(token(signing_keys))
    before = config.cache_path.read_bytes()
    server["body"] = json.dumps({"keys": [jwk(signing_keys["rogue"], "rotated")]}).encode()

    def interrupted(*args):
        raise OSError("replace failed")

    monkeypatch.setattr(_oidc_cache.os, "replace", interrupted)
    rejected(OIDCValidator(config), token(signing_keys, kid="rotated", key_name="rogue"))
    assert config.cache_path.read_bytes() == before
    assert not list(config.cache_path.parent.glob(".oidc-*"))


def test_missing_cache_directory_fails_before_network(environment, signing_keys):
    config, server = environment
    config = replace(config, cache_path=config.cache_path.parent / "absent" / "cache.json")
    rejected(OIDCValidator(config), token(signing_keys))
    assert not server["requests"]


def test_hardlinked_cache_rejected(tmp_path, signing_keys):
    config = offline_config(tmp_path, signing_keys)
    linked = tmp_path / "linked.json"
    os.link(config.cache_path, linked)
    rejected(OIDCValidator(config), token(signing_keys))
    with pytest.raises(ValueError):
        _oidc_cache.write_cache(config.cache_path, b"{}")


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership/mode enforcement; Windows requires deployment ACLs")
def test_posix_private_permissions(tmp_path, signing_keys):
    config = offline_config(tmp_path, signing_keys)
    assert config.cache_path.stat().st_mode & 0o777 == 0o600
    config.cache_path.chmod(0o644)
    rejected(OIDCValidator(config), token(signing_keys))
    config.cache_path.chmod(0o600)
    tmp_path.chmod(0o777)
    try:
        rejected(OIDCValidator(config), token(signing_keys))
    finally:
        tmp_path.chmod(0o700)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks; Windows reparse handling has a separate fixture")
def test_symlink_cache_and_directory_rejected(tmp_path, signing_keys):
    actual = tmp_path / "actual"
    actual.mkdir(mode=0o700)
    config = offline_config(actual, signing_keys)
    link = tmp_path / "symlink.json"
    link.symlink_to(config.cache_path)
    rejected(OIDCValidator(replace(config, cache_path=link)), token(signing_keys))
    parent_link = tmp_path / "link-directory"
    parent_link.symlink_to(actual, target_is_directory=True)
    rejected(OIDCValidator(replace(config, cache_path=parent_link / "jwks.json")), token(signing_keys))


def test_reparse_point_detection():
    from types import SimpleNamespace
    import stat

    simulated = SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
    if hasattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT"):
        assert _oidc_cache._is_link(simulated)


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction fixture")
def test_windows_junction_cache_path_rejected(tmp_path, signing_keys):
    actual = tmp_path / "actual"
    actual.mkdir()
    config = offline_config(actual, signing_keys)
    link = tmp_path / "junction"
    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(actual)],
                            capture_output=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0
    try:
        assert link.is_junction()
        rejected(OIDCValidator(replace(config, cache_path=link / "jwks.json")), token(signing_keys))
        with pytest.raises(ValueError):
            _oidc_cache.write_cache(link / "jwks.json", b"{}")
    finally:
        # Remove only this junction, never recurse into its target.
        os.rmdir(link)
    assert config.cache_path.is_file()


@pytest.mark.parametrize("scenario", [
    "redirect", "error", "html", "compressed", "large-length", "large-body", "duplicate-length",
    "mixed-framing", "truncated", "invalid-json",
])
def test_http_protocol_rejections(environment, signing_keys, scenario):
    config, server = environment
    if scenario == "redirect":
        server["status"] = 302
        server["headers"]["Location"] = server["url"] + "/redirected?credential=never-forward"
    elif scenario == "error":
        server["status"] = 500
    elif scenario == "html":
        server["headers"]["Content-Type"] = "text/html"
    elif scenario == "compressed":
        server["headers"]["Content-Encoding"] = "gzip"
    elif scenario == "large-length":
        server["headers"]["Content-Length"] = str(oidc.MAX_JWKS_BYTES + 1)
    elif scenario == "large-body":
        server["body"] = b" " * (oidc.MAX_JWKS_BYTES + 1)
        server["omit_length"] = True
    elif scenario == "duplicate-length":
        server["extra_headers"] = [("Content-Length", str(len(server["body"])))]
    elif scenario == "mixed-framing":
        server["headers"]["Transfer-Encoding"] = "chunked"
    elif scenario == "truncated":
        server["headers"]["Content-Length"] = str(len(server["body"]) + 20)
    elif scenario == "invalid-json":
        server["body"] = b"server-private-text"
    error = rejected(OIDCValidator(config), token(signing_keys))
    assert "server-private-text" not in str(error.value)
    assert len(server["requests"]) == 1
    assert not config.cache_path.exists()


@pytest.mark.parametrize("scenario", ["slow_headers", "slow_body"])
def test_total_deadline_stops_trickle_responses(environment, signing_keys, monkeypatch, scenario):
    config, server = environment
    server[scenario] = True
    server["omit_length"] = True
    monkeypatch.setattr(oidc, "FETCH_TIMEOUT_S", 1)
    started = time.monotonic()
    rejected(OIDCValidator(config), token(signing_keys))
    elapsed = time.monotonic() - started
    assert 0.8 <= elapsed < 3
    assert len(server["requests"]) == 1


def test_tls_certificate_hostname_verification(tmp_path, signing_keys, https_server):
    server = https_server({"keys": [jwk(signing_keys["rsa"])]}, certificate="wrong-host")
    config = OIDCConfig(ISSUER, AUDIENCE, server["url"], tmp_path / "cache.json")
    rejected(OIDCValidator(config), token(signing_keys))
    assert not server["requests"]


def test_tls_untrusted_ca(environment, signing_keys, monkeypatch, tmp_path):
    config, server = environment
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "no-trusted-ca.pem"))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path / "empty-ca-directory"))
    rejected(OIDCValidator(config), token(signing_keys))
    assert not server["requests"]


def test_fetch_ignores_proxy_credentials_and_never_sends_token(environment, signing_keys, monkeypatch):
    config, server = environment
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy-user:proxy-password@127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://proxy-user:proxy-password@127.0.0.1:1")
    encoded = token(signing_keys)
    OIDCValidator(config).validate(encoded)
    path, headers = server["requests"][0]
    assert path == "/jwks"
    assert not any(name.lower() in {"authorization", "proxy-authorization", "cookie"} for name in headers)
    assert encoded not in json.dumps(headers)


def test_cold_offline_failure_has_no_fallback(environment, signing_keys, monkeypatch):
    config, server = environment
    attempts = []

    def unavailable(*args, **kwargs):
        attempts.append(True)
        raise OSError("offline")

    monkeypatch.setattr(oidc.subprocess, "run", unavailable)
    validator = OIDCValidator(config)
    rejected(validator, token(signing_keys))
    rejected(validator, token(signing_keys))
    assert len(attempts) == 1
    assert not config.cache_path.exists()
