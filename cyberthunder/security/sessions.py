"""Bounded server-side authorization-code sessions. No token persistence."""

from base64 import b64encode, urlsafe_b64encode
from collections import deque
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import weakref
from urllib.parse import parse_qsl, quote_plus, urlsplit

from oauthlib.oauth2 import WebApplicationClient

from .oidc import AuthenticationError, OIDCConfig, OIDCValidator

SESSION_COOKIE = "__Host-ct_session"
LOGIN_COOKIE = "__Host-ct_login"
CALLBACK_PATH = "/auth/callback"
HTTP_TIMEOUT_S = 5
MAX_RESPONSE_BYTES = 65536
_OPAQUE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Credentials enter this disposable interpreter only over stdin. Its stdout is
# bounded and private to the caller; errors and library diagnostics are discarded.
_POST_HELPER = r'''
import http.client, json, ssl, sys
from urllib.parse import urlsplit
try:
    data = sys.stdin.buffer.read(65537)
    if len(data) > 65536: raise ValueError()
    request = json.loads(data)
    url = urlsplit(request["url"])
    if url.scheme != "https" or not url.hostname or url.username is not None or url.password is not None or url.fragment or url.query: raise ValueError()
    connection = http.client.HTTPSConnection(url.hostname, url.port or 443, timeout=2, context=ssl.create_default_context())
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close"}
    if request["authorization"]: headers["Authorization"] = request["authorization"]
    connection.request("POST", url.path or "/", body=request["body"].encode("ascii"), headers=headers)
    response = connection.getresponse()
    types = response.headers.get_all("Content-Type", [])
    sizes = response.headers.get_all("Content-Length", [])
    transfers = response.headers.get_all("Transfer-Encoding", [])
    if response.status != 200 or len(types) != 1 or types[0].split(";",1)[0].strip().lower() != "application/json": raise ValueError()
    if response.getheader("Content-Encoding", "identity").lower() != "identity": raise ValueError()
    if len(sizes) > 1 or len(transfers) > 1 or (sizes and transfers): raise ValueError()
    if transfers and transfers[0].lower() != "chunked": raise ValueError()
    if sizes and (not sizes[0].isascii() or not sizes[0].isdecimal() or int(sizes[0]) > 65536): raise ValueError()
    result = response.read(65537)
    if len(result) > 65536 or (sizes and len(result) != int(sizes[0])): raise ValueError()
    connection.close()
    sys.stdout.buffer.write(result)
except Exception:
    sys.exit(1)
'''


class CSRFError(AuthenticationError):
    """Sanitized cookie-request rejection."""


def _text(value, limit, *, spaces=False):
    return (isinstance(value, str) and 0 < len(value) <= limit
            and all((31 if spaces else 32) < ord(char) < 127 for char in value))


def _url(value):
    if not _text(value, 2048) or any(char in value for char in ("*", "\\", "#", "?")):
        raise ValueError()
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or "%" in parsed.netloc
            or parsed.port is not None and not 1 <= parsed.port <= 65535):
        raise ValueError()
    return parsed


def _origin(url):
    parsed = _url(url)
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return "https://" + host + (f":{parsed.port}" if parsed.port not in (None, 443) else "")


@dataclass(frozen=True)
class SessionConfig:
    issuer: str
    client_id: str
    authorization_endpoint: str
    token_endpoint: str
    redirect_uri: str
    id_token_config: OIDCConfig
    client_secret_ref: str | None = None
    scope: str = "openid"
    idle_timeout_s: int = 900
    absolute_timeout_s: int = 28800
    login_timeout_s: int = 300
    max_sessions: int = 256
    max_pending: int = 128

    def __post_init__(self):
        try:
            for endpoint in (self.issuer, self.authorization_endpoint, self.token_endpoint, self.redirect_uri):
                _url(endpoint)
            if _url(self.redirect_uri).path != CALLBACK_PATH or not _text(self.client_id, 512):
                raise ValueError()
            if (not isinstance(self.id_token_config, OIDCConfig)
                    or self.id_token_config.issuer != self.issuer
                    or self.id_token_config.audience != self.client_id
                    or self.id_token_config.authorized_party not in (None, self.client_id)):
                raise ValueError()
            if self.client_secret_ref is not None and (
                    not isinstance(self.client_secret_ref, str)
                    or re.fullmatch(r"[A-Za-z0-9_]{1,64}", self.client_secret_ref) is None):
                raise ValueError()
            if not _text(self.scope, 512, spaces=True):
                raise ValueError()
            scopes = self.scope.split(" ")
            if ("openid" not in scopes or len(set(scopes)) != len(scopes)
                    or not all(re.fullmatch(r'[\x21\x23-\x5b\x5d-\x7e]+', item) for item in scopes)):
                raise ValueError()
            for value, low, high in ((self.idle_timeout_s, 30, 3600), (self.absolute_timeout_s, 60, 86400),
                                     (self.login_timeout_s, 30, 600), (self.max_sessions, 1, 1024),
                                     (self.max_pending, 1, 256)):
                if type(value) is not int or not low <= value <= high:
                    raise ValueError()
            if self.idle_timeout_s > self.absolute_timeout_s:
                raise ValueError()
        except Exception:
            raise AuthenticationError() from None


@dataclass(repr=False)
class _Pending:
    state: str
    nonce: str
    verifier: str
    deadline: float


@dataclass(repr=False)
class _Session:
    access_token: str
    refresh_token: str | None
    subject: str
    nonce: str
    csrf: str
    issued: float
    last_used: float
    access_deadline: float
    access_expiry: int
    lease_fingerprint: str
    generation: int = 0


@dataclass(frozen=True, slots=True, repr=False)
class SessionLease:
    """A credential-free, non-renewing guard for copied principal contexts.

    The fingerprint is an audit correlation value, never an authentication
    credential. Weak ownership prevents an abandoned job from retaining sessions.
    """

    fingerprint: str
    _service: weakref.ReferenceType
    _generation: int
    _access_deadline: float
    _access_expiry: int

    def __call__(self) -> None:
        try:
            service = self._service()
            if service is None or not service._lease_active(self):
                raise PermissionError()
        except Exception:
            raise PermissionError("The browser session is no longer authorized") from None


def _header(headers, name):
    # Starlette Headers preserves duplicate fields in .raw. Plain mappings are
    # also supported for middleware tests without silently merging duplicates.
    if hasattr(headers, "raw"):
        values = [value.decode("latin1") for key, value in headers.raw if key.decode("latin1").lower() == name]
    else:
        values = [value for key, value in headers.items() if key.lower() == name]
    if len(values) > 1 or (values and not _text(values[0], 8192, spaces=True)):
        raise AuthenticationError()
    return values[0] if values else None


def _cookies(headers):
    raw = _header(headers, "cookie")
    result = {}
    if raw:
        for field in raw.split(";"):
            name, separator, value = field.strip().partition("=")
            if name in (SESSION_COOKIE, LOGIN_COOKIE):
                if not separator or name in result or not _OPAQUE.fullmatch(value):
                    raise AuthenticationError()
                result[name] = value
    if SESSION_COOKIE in result and _header(headers, "authorization") is not None:
        raise AuthenticationError()
    return result


def _pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError()
        result[name] = value
    return result


def _json(data):
    def invalid(_):
        raise ValueError()

    value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=invalid)
    if not isinstance(value, dict):
        raise ValueError()
    return value


class SessionService:
    def __init__(self, config: SessionConfig, access_validator: OIDCValidator):
        try:
            ac = access_validator.config
            if (ac.issuer != config.issuer or ac.audience == config.client_id
                    or ac.authorized_party != config.client_id or ac.cache_path == config.id_token_config.cache_path):
                raise ValueError()
            self.config = config
            self.access_validator = access_validator
            self.id_validator = OIDCValidator(config.id_token_config)
            self.origin = _origin(config.redirect_uri)
            self._lock = threading.RLock()
            self._pending = {}
            self._sessions = {}
            self._lease_index = {}
            self._login_attempts = deque()
            self._token_attempts = deque()
            self._wall, self._mono = time.time(), time.monotonic()
            self._elapsed = 0.0
            self._clock_failed = False
        except Exception:
            raise AuthenticationError() from None

    def _now(self):
        wall, mono = time.time(), time.monotonic()
        projected = self._wall + mono - self._mono
        tolerance = max(0.01, self.config.id_token_config.clock_skew_s)
        if (self._clock_failed or not math.isfinite(wall) or not math.isfinite(mono)
                or mono < self._mono or wall + tolerance < projected):
            self._clock_failed = True
            self._sessions.clear()
            self._lease_index.clear()
            self._pending.clear()
            raise AuthenticationError()
        # Some operating systems exclude suspend time from their monotonic
        # clock. Use the greater elapsed interval so sleep or forward clock
        # corrections cannot extend idle, absolute or transaction lifetimes.
        self._elapsed += max(0.0, wall - self._wall, mono - self._mono)
        self._wall, self._mono = max(wall, projected), mono
        return self._wall, self._elapsed

    def _prune(self, mono):
        for key, item in list(self._pending.items()):
            if mono >= item.deadline:
                self._pending.pop(key, None)
        for key, item in list(self._sessions.items()):
            if (mono - item.issued >= self.config.absolute_timeout_s
                    or mono - item.last_used >= self.config.idle_timeout_s):
                self._remove_session(key)

    def _remove_session(self, session_id):
        # Call only while holding the service lock. All revocation paths remove
        # the lookup index as well as the token-bearing session record.
        session = self._sessions.pop(session_id, None)
        if session is not None:
            self._lease_index.pop(session.lease_fingerprint, None)

    @staticmethod
    def _rate(queue, mono, maximum):
        while queue and mono - queue[0] >= 60:
            queue.popleft()
        if len(queue) >= maximum:
            raise AuthenticationError()
        queue.append(mono)

    def _origin_check(self, headers, required=False):
        origin = _header(headers, "origin")
        site = _header(headers, "sec-fetch-site")
        if (required and origin is None or origin is not None and origin != self.origin
                or site is not None and site not in {"same-origin", "none"}):
            raise CSRFError()

    def start_login(self, headers) -> tuple[str, str]:
        """Return authorization URL and independent browser-binding cookie."""
        try:
            with self._lock:
                self._origin_check(headers)
                cookies = _cookies(headers)
                _, mono = self._now()
                self._prune(mono)
                self._rate(self._login_attempts, mono, 20)
                self._pending.pop(cookies.get(LOGIN_COOKIE), None)
                if len(self._pending) >= self.config.max_pending:
                    raise ValueError()
                cookie, state, nonce = (secrets.token_urlsafe(32) for _ in range(3))
                verifier = secrets.token_urlsafe(64)
                client = WebApplicationClient(self.config.client_id)
                challenge = client.create_code_challenge(verifier, code_challenge_method="S256")
                url, _, _ = client.prepare_authorization_request(
                    self.config.authorization_endpoint, state=state,
                    redirect_url=self.config.redirect_uri, scope=self.config.scope.split(),
                    nonce=nonce, code_challenge=challenge, code_challenge_method="S256",
                    response_mode="query",
                )
                self._pending[cookie] = _Pending(state, nonce, verifier, mono + self.config.login_timeout_s)
                return url, cookie
        except Exception:
            raise AuthenticationError() from None

    def _exchange(self, body):
        _, mono = self._now()
        self._rate(self._token_attempts, mono, 60)
        authorization = None
        if self.config.client_secret_ref is not None:
            secret = os.environ.get("CT_CRED_" + self.config.client_secret_ref)
            if not _text(secret, 4096, spaces=True):
                raise AuthenticationError()
            credentials = quote_plus(self.config.client_id) + ":" + quote_plus(secret)
            authorization = "Basic " + b64encode(credentials.encode("ascii")).decode("ascii")
        request = json.dumps({"url": self.config.token_endpoint, "body": body,
                              "authorization": authorization}).encode("utf-8")
        if len(request) > MAX_RESPONSE_BYTES:
            raise ValueError()
        result = subprocess.run([sys.executable, "-I", "-c", _POST_HELPER], input=request,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=HTTP_TIMEOUT_S, check=True,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if len(result.stdout) > MAX_RESPONSE_BYTES:
            raise ValueError()
        return _json(result.stdout)

    def _tokens(self, response, nonce, *, previous=None):
        if ("error" in response or not isinstance(response.get("token_type"), str)
                or response["token_type"].lower() != "bearer"
                or not _text(response.get("access_token"), 16384)
                or type(response.get("expires_in")) is not int or not 1 <= response["expires_in"] <= 3600):
            raise ValueError()
        if "scope" in response and (not isinstance(response["scope"], str)
                or not set(response["scope"].split()).issubset(self.config.scope.split())):
            raise ValueError()
        refresh = response.get("refresh_token")
        if "refresh_token" in response and not _text(refresh, 8192):
            raise ValueError()
        # This profile requires rotation whenever a refresh token is redeemed.
        if previous is not None and (refresh is None or hmac.compare_digest(refresh, previous.refresh_token)):
            raise ValueError()
        access = response["access_token"]
        access_claims = self.access_validator.validate(access)
        access_audiences = access_claims["aud"] if isinstance(access_claims["aud"], list) else [access_claims["aud"]]
        if access_claims.get("azp") != self.config.client_id or self.config.client_id in access_audiences:
            raise ValueError()
        identity = response.get("id_token")
        if previous is None or "id_token" in response:
            if not _text(identity, 16384):
                raise ValueError()
            id_claims = self.id_validator.validate(identity)
            id_audiences = id_claims["aud"] if isinstance(id_claims["aud"], list) else [id_claims["aud"]]
            if self.access_validator.config.audience in id_audiences:
                raise ValueError()
            returned_nonce = id_claims.get("nonce")
            if previous is None or "nonce" in id_claims:
                if not isinstance(returned_nonce, str) or not hmac.compare_digest(returned_nonce, nonce):
                    raise ValueError()
            if id_claims["sub"] != access_claims["sub"] or id_claims["iss"] != access_claims["iss"]:
                raise ValueError()
            if "at_hash" in id_claims:
                expected = urlsafe_b64encode(hashlib.sha256(access.encode("ascii")).digest()[:16]).rstrip(b"=").decode()
                if not isinstance(id_claims["at_hash"], str) or not hmac.compare_digest(expected, id_claims["at_hash"]):
                    raise ValueError()
        if previous is not None and access_claims["sub"] != previous.subject:
            raise ValueError()
        wall, mono = self._now()
        if access_claims["exp"] <= wall:
            raise ValueError()
        deadline = mono + min(response["expires_in"], access_claims["exp"] - wall)
        return access, refresh, access_claims, deadline

    def complete_login(self, query_string: str, headers) -> str:
        """Consume the browser-bound transaction once and return a new cookie."""
        try:
            with self._lock:
                cookies = _cookies(headers)
                _, mono = self._now()
                self._prune(mono)
                pending = self._pending.pop(cookies.get(LOGIN_COOKIE), None)
                if pending is None or not isinstance(query_string, str) or len(query_string) > 8192:
                    raise ValueError()
                pairs = parse_qsl(query_string, keep_blank_values=True, strict_parsing=True,
                                  max_num_fields=8, encoding="utf-8", errors="strict")
                params = _pairs(pairs)
                if (not isinstance(params.get("state"), str)
                        or not hmac.compare_digest(params["state"], pending.state)
                        or "error" in params or set(params) - {"state", "code", "iss", "session_state"}
                        or not _text(params.get("code"), 2048)
                        or "iss" in params and params["iss"] != self.config.issuer):
                    raise ValueError()
                if len(self._sessions) >= self.config.max_sessions and cookies.get(SESSION_COOKIE) not in self._sessions:
                    raise ValueError()
                client = WebApplicationClient(self.config.client_id)
                _, _, body = client.prepare_token_request(
                    self.config.token_endpoint,
                    authorization_response=self.config.redirect_uri + "?" + query_string,
                    state=pending.state, redirect_url=self.config.redirect_uri,
                    code_verifier=pending.verifier, include_client_id=self.config.client_secret_ref is None,
                )
                response = self._exchange(body)
                access, refresh, claims, deadline = self._tokens(response, pending.nonce)
                wall, mono = self._now()
                if mono >= pending.deadline or mono >= deadline or wall >= claims["exp"]:
                    raise ValueError()
                session_id = secrets.token_urlsafe(32)
                fingerprint = hashlib.sha256(b"ct-session-lease-v1\0" + session_id.encode("ascii")).hexdigest()
                self._remove_session(cookies.get(SESSION_COOKIE))
                self._sessions[session_id] = _Session(access, refresh, claims["sub"], pending.nonce,
                                                      secrets.token_urlsafe(32), mono, mono, deadline,
                                                      claims["exp"], fingerprint)
                self._lease_index[fingerprint] = session_id
                return session_id
        except Exception:
            raise AuthenticationError() from None

    def _live(self, headers):
        cookies = _cookies(headers)
        _, mono = self._now()
        self._prune(mono)
        session_id = cookies.get(SESSION_COOKIE)
        session = self._sessions.get(session_id)
        if session is None:
            raise AuthenticationError()
        return session_id, session

    def csrf_check(self, method, headers) -> None:
        try:
            if not _text(method, 20):
                raise ValueError()
            if method.upper() in _SAFE_METHODS:
                return
            with self._lock:
                _, session = self._live(headers)
                self._origin_check(headers, required=True)
                supplied = _header(headers, "x-csrf-token")
                if not isinstance(supplied, str) or not hmac.compare_digest(supplied, session.csrf):
                    raise ValueError()
        except Exception:
            raise CSRFError() from None

    def resolve_session(self, headers, *, touch: bool = True) -> dict | None:
        session_id = None
        try:
            with self._lock:
                if type(touch) is not bool:
                    raise AuthenticationError()
                if SESSION_COOKIE not in _cookies(headers):
                    return None
                self._origin_check(headers)
                session_id, session = self._live(headers)
                wall, mono = self._now()
                if mono >= session.access_deadline or wall >= session.access_expiry:
                    if session.refresh_token is None:
                        raise ValueError()
                    client = WebApplicationClient(self.config.client_id)
                    options = {"client_id": self.config.client_id} if self.config.client_secret_ref is None else {}
                    body = client.prepare_refresh_body(refresh_token=session.refresh_token, **options)
                    response = self._exchange(body)
                    access, refresh, claims, deadline = self._tokens(response, session.nonce, previous=session)
                    # Recheck idle/absolute deadlines after the bounded exchange.
                    self._live(headers)
                    session.access_token, session.refresh_token = access, refresh
                    session.access_deadline, session.access_expiry = deadline, claims["exp"]
                    session.generation += 1
                claims = self.access_validator.validate(session.access_token)
                if claims["sub"] != session.subject or claims.get("azp") != self.config.client_id:
                    raise ValueError()
                wall, mono = self._now()
                self._live(headers)
                if mono >= session.access_deadline or wall >= session.access_expiry:
                    raise ValueError()
                if touch:
                    session.last_used = mono
                return claims
        except Exception:
            if session_id is not None:
                with self._lock:
                    self._remove_session(session_id)
            raise AuthenticationError() from None

    def resolve_session_with_lease(self, headers, *, touch: bool = True) -> tuple[dict, SessionLease] | None:
        """Atomically bind validated access claims to a revocable local guard.

        Call the usual CSRF check first for unsafe cookie requests. The caller
        carries the lease in its execution context, not in Principal or audit.
        """
        with self._lock:
            claims = self.resolve_session(headers, touch=touch)
            if claims is None:
                return None
            _, session = self._live(headers)
            return claims, self._new_lease(session)

    def session_guard(self, headers) -> SessionLease:
        """Capture a non-renewing raising guard after cookie authentication.

        Prefer resolve_session_with_lease when binding claims and their guard
        atomically. This compatibility hook never retains the supplied headers.
        """
        with self._lock:
            self._origin_check(headers)
            _, session = self._live(headers)
            return self._new_lease(session)

    def _new_lease(self, session):
        lease = SessionLease(session.lease_fingerprint, weakref.ref(self), session.generation,
                             session.access_deadline, session.access_expiry)
        lease()
        return lease

    def _lease_active(self, lease: SessionLease) -> bool:
        # A lease never refreshes a token, revalidates JWTs or renews idle time.
        # Its original credential deadline remains fixed even if the browser
        # later obtains refreshed credentials and different claims/permissions.
        try:
            with self._lock:
                wall, mono = self._now()
                self._prune(mono)
                session = self._sessions.get(self._lease_index.get(lease.fingerprint))
                return (session is not None and session.generation == lease._generation
                        and mono < lease._access_deadline and wall < lease._access_expiry
                        and mono < session.access_deadline and wall < session.access_expiry)
        except Exception:
            return False

    def session_info(self, headers) -> tuple[dict, dict]:
        """Return validated claims separately from the safe browser metadata."""
        with self._lock:
            claims = self.resolve_session(headers, touch=False)
            if claims is None:
                raise AuthenticationError()
            _, session = self._live(headers)
            return claims, {"authenticated": True, "csrf_token": session.csrf}

    def logout(self, headers) -> None:
        with self._lock:
            self.csrf_check("POST", headers)
            session_id, _ = self._live(headers)
            self._remove_session(session_id)
            self._pending.pop(_cookies(headers).get(LOGIN_COOKIE), None)
