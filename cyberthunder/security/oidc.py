"""Strict signed-token validation with bounded, offline-capable JWKS caching.

This module establishes claims authenticity only. Principal mapping, role
authorization and interactive OIDC flow validation belong to the caller.
"""

from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections import OrderedDict
from dataclasses import dataclass
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

import jwt

from ._oidc_cache import check_cache, digest, read_cache, write_cache

MAX_TOKEN_BYTES = 16384
MAX_TOKEN_LIFETIME_S = 3600
MAX_JWKS_BYTES = 262144
MAX_KEYS = 32
FETCH_TIMEOUT_S = 5
REFRESH_INTERVAL_S = 30
NEGATIVE_CACHE_TTL_S = 60
MAX_NEGATIVE_KIDS = 256
CLOCK_SAMPLE_TOLERANCE_S = 0.01
_B64 = re.compile(r"[A-Za-z0-9_-]+\Z", re.ASCII)
_ALGORITHMS = {"RS256", "ES256"}


class AuthenticationError(Exception):
    """A public failure that never includes credentials, keys or server text."""

    def __init__(self) -> None:
        super().__init__("Authentication failed")


def _text(value: object, limit: int) -> bool:
    return (isinstance(value, str) and 0 < len(value) <= limit
            and all(32 < ord(char) < 127 for char in value))


def _https_url(value: str, *, issuer: bool = False) -> None:
    if not _text(value, 4096):
        raise ValueError("Invalid URL")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment or "#" in value
            or "\\" in value or (issuer and (parsed.query or "?" in value))):
        raise ValueError("Invalid URL")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("Invalid URL")


@dataclass(frozen=True)
class OIDCConfig:
    issuer: str
    audience: str
    jwks_url: str
    cache_path: str | Path
    max_age_s: int = 86400
    clock_skew_s: int = 60
    authorized_party: str | None = None

    def __post_init__(self) -> None:
        try:
            _https_url(self.issuer, issuer=True)
            _https_url(self.jwks_url)
            if not _text(self.audience, 512):
                raise ValueError("Invalid audience")
            if self.authorized_party is not None and not _text(self.authorized_party, 512):
                raise ValueError("Invalid party")
            if type(self.max_age_s) is not int or not 1 <= self.max_age_s <= 86400:
                raise ValueError("Invalid age")
            if type(self.clock_skew_s) is not int or not 0 <= self.clock_skew_s <= 300:
                raise ValueError("Invalid skew")
            path = Path(self.cache_path)
            if not path.is_absolute() or ".." in path.parts or not path.name:
                raise ValueError("Invalid cache path")
            object.__setattr__(self, "cache_path", path)
        except Exception:
            raise AuthenticationError() from None


def _pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError("Invalid JSON number")


def _json(data: bytes) -> dict:
    value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    if not isinstance(value, dict):
        raise ValueError("Invalid JSON object")
    # Cap depth even when the interpreter's JSON parser accepts deeper input.
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > 32 or (isinstance(item, float) and not math.isfinite(item)):
            raise ValueError("Invalid JSON value")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return value


def _unbase64(value: str, limit: int) -> bytes:
    if not isinstance(value, str) or len(value) > limit or not _B64.fullmatch(value):
        raise ValueError("Invalid encoding")
    decoded = urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ValueError("Noncanonical encoding")
    return decoded


def _token_parts(token: str) -> tuple[dict, dict]:
    if not isinstance(token, str) or len(token) > MAX_TOKEN_BYTES or not token.isascii():
        raise ValueError("Invalid token")
    header_part, payload_part, signature = token.split(".")
    header = _json(_unbase64(header_part, 2048))
    claims = _json(_unbase64(payload_part, MAX_TOKEN_BYTES))
    _unbase64(signature, 2048)
    if not isinstance(header.get("alg"), str) or header["alg"] not in _ALGORITHMS:
        raise ValueError("Invalid algorithm")
    if not _text(header.get("kid"), 128):
        raise ValueError("Invalid key identifier")
    if any(name in header for name in ("jku", "jwk", "x5u", "x5c", "crit", "b64", "zip")):
        raise ValueError("Unsupported header")
    if "typ" in header and header["typ"] != "JWT":
        raise ValueError("Invalid token type")
    return header, claims


def _keys(document: dict) -> tuple[dict, dict]:
    values = document.get("keys")
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_KEYS:
        raise ValueError("Invalid key set")
    result, public = {}, []
    for value in values:
        if not isinstance(value, dict) or not _text(value.get("kid"), 128):
            raise ValueError("Invalid key identifier")
        kid = value["kid"]
        if kid in result:
            raise ValueError("Duplicate key identifier")
        if any(name in value for name in ("d", "p", "q", "dp", "dq", "qi", "oth", "k", "jku", "x5u")):
            raise ValueError("Nonpublic or remote key")
        if value.get("use", "sig") != "sig" or value.get("key_ops", ["verify"]) != ["verify"]:
            raise ValueError("Invalid key usage")
        kty = value.get("kty")
        if kty == "RSA":
            algorithm = "RS256"
            modulus = _unbase64(value.get("n"), 1366)
            exponent = _unbase64(value.get("e"), 8)
            if (not modulus or modulus[0] == 0 or not 2048 <= int.from_bytes(modulus).bit_length() <= 8192
                    or exponent != b"\x01\x00\x01"):
                raise ValueError("Invalid RSA parameters")
            fields = ("kty", "kid", "n", "e")
        elif kty == "EC":
            algorithm = "ES256"
            if (value.get("crv") != "P-256" or len(_unbase64(value.get("x"), 43)) != 32
                    or len(_unbase64(value.get("y"), 43)) != 32):
                raise ValueError("Invalid EC parameters")
            fields = ("kty", "kid", "crv", "x", "y")
        else:
            raise ValueError("Invalid key type")
        if value.get("alg", algorithm) != algorithm:
            raise ValueError("Key algorithm mismatch")
        normalized = {name: value[name] for name in fields}
        normalized.update(alg=algorithm, use="sig", key_ops=["verify"])
        parsed = jwt.PyJWK.from_dict(normalized, algorithm=algorithm)
        result[kid] = (algorithm, parsed.key)
        public.append(normalized)
    return result, {"keys": public}


def _date(value: object) -> bool:
    return type(value) is int and 0 <= value <= 253402300799


class OIDCValidator:
    def __init__(self, config: OIDCConfig):
        self.config = config
        self._lock = threading.Lock()
        self._wall_anchor = time.time()
        self._mono_anchor = time.monotonic()
        self._clock_failed = False
        self._cache_failed = False
        self._cache_digest = None
        self._loaded = False
        self._keys = {}
        self._jwks = {}
        self._fetched_at = 0
        self._observed_at = 0
        self._last_attempt = float("-inf")
        self._negative = OrderedDict()

    def _now(self) -> float:
        before = time.monotonic()
        wall = time.time()
        mono = time.monotonic()
        earliest = self._wall_anchor + (before - self._mono_anchor)
        projected = self._wall_anchor + (mono - self._mono_anchor)
        # The wall sample occurred somewhere inside this monotonic interval.
        # Compare rollback against its earliest possible time, not the end of
        # a scheduler pause after the wall read. Still advance effective time
        # through the end of the interval for token expiry and key-cache age.
        rollback_tolerance = max(self.config.clock_skew_s, CLOCK_SAMPLE_TOLERANCE_S)
        if (self._clock_failed or not all(math.isfinite(t) for t in (wall, before, mono, earliest, projected))
                or before < self._mono_anchor or mono < before or wall + rollback_tolerance < earliest):
            self._clock_failed = True
            raise ValueError("Clock rollback")
        effective = max(wall, projected)
        self._wall_anchor, self._mono_anchor = effective, mono
        return effective

    def _load(self, now: float) -> None:
        data = read_cache(self.config.cache_path)
        if data is not None:
            cache = _json(data)
            if (type(cache.get("version")) is not int or cache["version"] != 1
                    or cache.get("issuer") != self.config.issuer
                    or cache.get("jwks_url") != self.config.jwks_url
                    or cache.get("audience") != self.config.audience
                    or cache.get("authorized_party") != self.config.authorized_party):
                raise ValueError("Invalid cache binding")
            fetched, observed = cache.get("fetched_at"), cache.get("observed_at")
            if (not _date(fetched) or not _date(observed) or fetched > observed
                    or observed > now + self.config.clock_skew_s):
                raise ValueError("Invalid cache clock")
            self._keys, self._jwks = _keys(cache["jwks"])
            self._fetched_at, self._observed_at = fetched, observed
            self._wall_anchor = max(self._wall_anchor, observed)
        self._loaded = True
        self._cache_digest = digest(data)

    def _check_cache(self) -> None:
        # Never silently recreate a purged cache or overwrite another writer's
        # key rotation with this instance's older key set/watermark. This check
        # also reapplies the file safety checks after the initial load.
        if self._cache_failed:
            raise ValueError("Cache invalidated")
        try:
            check_cache(self.config.cache_path, self._cache_digest)
        except Exception:
            self._cache_failed = True
            self._keys, self._jwks = {}, {}
            raise

    def _persist(self, jwks: dict, fetched: int, observed: int) -> None:
        body = {"version": 1, "issuer": self.config.issuer, "audience": self.config.audience,
                "authorized_party": self.config.authorized_party, "jwks_url": self.config.jwks_url,
                "fetched_at": fetched, "observed_at": observed, "jwks": jwks}
        data = json.dumps(body, separators=(",", ":"), allow_nan=False).encode("utf-8")
        self._check_cache()
        try:
            write_cache(self.config.cache_path, data, expected_digest=self._cache_digest)
        except Exception:
            # A plain I/O failure may leave the old cache intact. A purge or
            # replacement during persistence must latch invalidation instead.
            self._check_cache()
            raise
        self._cache_digest = digest(data)
        self._check_cache()

    def _refresh(self) -> None:
        self._last_attempt = time.monotonic()
        helper = Path(__file__).with_name("_oidc_fetch.py")
        completed = subprocess.run(
            [sys.executable, "-I", str(helper)], input=self.config.jwks_url.encode("ascii"),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=FETCH_TIMEOUT_S,
            check=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if len(completed.stdout) > MAX_JWKS_BYTES:
            raise ValueError("Oversized key set")
        keys, jwks = _keys(_json(completed.stdout))
        now = int(self._now())
        self._persist(jwks, now, now)
        self._keys, self._jwks = keys, jwks
        self._fetched_at = self._observed_at = now
        self._negative.clear()

    def _reject_kid(self, kid: str, mono: float) -> None:
        self._negative[kid] = mono + NEGATIVE_CACHE_TTL_S
        self._negative.move_to_end(kid)
        while len(self._negative) > MAX_NEGATIVE_KIDS:
            self._negative.popitem(last=False)

    def _key(self, kid: str, now: float) -> tuple:
        mono = time.monotonic()
        fresh = bool(self._keys) and 0 <= now - self._fetched_at < self.config.max_age_s
        if fresh and kid in self._keys:
            return self._keys[kid]
        if fresh and self._negative.get(kid, 0) > mono:
            raise ValueError("Unknown key")
        if mono - self._last_attempt < REFRESH_INTERVAL_S:
            self._reject_kid(kid, mono)
            raise ValueError("Refresh limited")
        try:
            self._refresh()
        except Exception:
            self._reject_kid(kid, time.monotonic())
            raise
        if kid not in self._keys:
            self._reject_kid(kid, time.monotonic())
            raise ValueError("Unknown key")
        return self._keys[kid]

    def _claims(self, claims: dict, now: float) -> None:
        if claims.get("iss") != self.config.issuer or not _text(claims.get("sub"), 255):
            raise ValueError("Invalid identity")
        audience = claims.get("aud")
        if isinstance(audience, str):
            audience = [audience]
        if (not isinstance(audience, list) or not 1 <= len(audience) <= 16
                or not all(_text(item, 512) for item in audience)
                or len(set(audience)) != len(audience) or self.config.audience not in audience):
            raise ValueError("Invalid audience")
        expected_party = self.config.authorized_party or self.config.audience
        if ("azp" in claims or self.config.authorized_party is not None or len(audience) > 1):
            if not _text(claims.get("azp"), 512) or claims["azp"] != expected_party:
                raise ValueError("Invalid authorized party")
        issued, expiry, skew = claims.get("iat"), claims.get("exp"), self.config.clock_skew_s
        if (not _date(issued) or not _date(expiry) or not 0 < expiry - issued <= MAX_TOKEN_LIFETIME_S
                or issued > now + skew or now - issued > MAX_TOKEN_LIFETIME_S + skew
                or now >= expiry + skew):
            raise ValueError("Invalid lifetime")
        if "nbf" in claims:
            before = claims["nbf"]
            if not _date(before) or before > now + skew or before >= expiry or before < issued - skew:
                raise ValueError("Invalid not-before time")
        if "auth_time" in claims:
            if not _date(claims["auth_time"]) or claims["auth_time"] > min(issued, now) + skew:
                raise ValueError("Invalid authentication time")
        if "jti" in claims and not _text(claims["jti"], 512):
            raise ValueError("Invalid token identifier")

    def validate(self, token: str) -> dict:
        """Return verified claims or a fixed AuthenticationError with no cause.

        A single instance serializes refreshes and preserves clock/cache high-water
        marks. Reuse it across requests; do not create a validator per token.
        """
        try:
            header, claims = _token_parts(token)
            with self._lock:
                now = self._now()
                # Reject structurally invalid claims before any network I/O. They
                # remain untrusted until signature verification below succeeds.
                self._claims(claims, now)
                if not self._loaded:
                    self._load(now)
                self._check_cache()
                algorithm, key = self._key(header["kid"], self._now())
                if header["alg"] != algorithm:
                    raise ValueError("Algorithm mismatch")
                # The allowed algorithm comes from the validated trusted JWK,
                # never from the token. PyJWT/cryptography perform all crypto.
                verified = jwt.api_jws.decode_complete(
                    token, key=key, algorithms=[algorithm], options={"verify_signature": True},
                )
                claims = _json(verified["payload"])
                now = self._now()
                self._claims(claims, now)
                if now - self._fetched_at >= self.config.max_age_s:
                    raise ValueError("Expired cache")
                observed = int(now)
                if observed > self._observed_at:
                    self._persist(self._jwks, self._fetched_at, observed)
                    self._observed_at = observed
                self._check_cache()
                # Local reads/fsync can also block. Do not return claims that
                # expired (or used keys that aged out) during cache persistence.
                now = self._now()
                self._claims(claims, now)
                if now - self._fetched_at >= self.config.max_age_s:
                    raise ValueError("Expired cache")
                return claims
        except Exception:
            raise AuthenticationError() from None
