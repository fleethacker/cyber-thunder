"""Human device authorization, verified API identity and rotating client sessions."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import math
import re
import time

from .errors import ClientError, redact, text
from .http import Transport, require_api
from .store import TokenStore


def secret(value, maximum):
    return text(value, maximum) and value.isascii() and all(33 <= ord(c) <= 126 for c in value)


class ClientAuth:
    def __init__(self, profile, *, store=None, transport=None):
        self.profile = profile
        self.store = store if store is not None else TokenStore(profile.digest)
        self.http = transport if transport is not None else Transport(profile)
        self._wall, self._mono = time.time(), time.monotonic()
        self._raw_wall = self._wall

    def now(self, record=None):
        wall, mono = time.time(), time.monotonic()
        if (not all(math.isfinite(v) for v in (wall, mono)) or wall < self._raw_wall or mono < self._mono
                or wall < (record or {}).get("observed_at", 0)):
            raise ClientError("clock_changed_login_required", outcome=3)
        self._wall, self._mono = max(wall, self._wall + mono - self._mono), mono
        self._raw_wall = wall
        return self._wall

    def _identity(self, access, *, timeout=10):
        value = require_api(self.http.request("api", method="GET", route="/whoami", credential=access, timeout=timeout))
        p = value.get("principal")
        if (value.get("mode") not in {"oidc", "mesh"} or value.get("verified") is not True or not isinstance(p, dict)
                or p.get("verified") is not True or p.get("kind") != "human" or p.get("via") not in {"oidc", "mesh"}
                or p.get("iss") != self.profile["issuer"] or not text(p.get("sub"), 255)
                or not text(p.get("name"), 512)):
            raise ClientError("verified_human_required", outcome=3)
        actor = "human:" + hashlib.sha256((p["iss"] + "\0" + p["sub"]).encode()).hexdigest()
        expiry = p.get("expires_at")
        if (p.get("actor") != actor or type(expiry) not in {int, float} or not math.isfinite(expiry) or expiry <= self.now()
                or (p.get("auth_time") is not None and (type(p["auth_time"]) is not int or not 0 <= p["auth_time"] <= self.now()))
                or (p.get("acr") is not None and not text(p["acr"], 128))
                or not isinstance(p.get("amr"), list) or len(p["amr"]) > 64
                or any(not text(x, 128) for x in p["amr"])):
            raise ClientError("identity_response_invalid", outcome=3)
        identity = {k: p.get(k) for k in ("iss", "sub", "name", "actor", "auth_time", "acr", "amr")}
        return identity, expiry

    @staticmethod
    def _same_identity(before, after):
        if any(before.get(k) != after.get(k) for k in ("iss", "sub", "actor", "auth_time", "acr", "amr")):
            raise ClientError("identity_or_assurance_changed_login_required", outcome=3)

    def _tokens(self, response, previous=None, *, deadline=None):
        data = response.body
        if (response.status != 200 or "error" in data or str(data.get("token_type", "")).lower() != "bearer"
                or not secret(data.get("access_token"), 16384) or type(data.get("expires_in")) is not int
                or not 1 <= data["expires_in"] <= 3600):
            raise ClientError("token_response_invalid", outcome=3, source="idp", status=response.status)
        refresh = data.get("refresh_token")
        if (refresh is not None and (not secret(refresh, 8192) or self.profile["revocation_endpoint"] is None)):
            raise ClientError("refresh_policy_invalid", outcome=3)
        if previous is not None and (refresh is None or refresh == previous["refresh_token"]):
            raise ClientError("refresh_rotation_required", outcome=3)
        scope = data.get("scope", previous["scope"] if previous else self.profile["scope"])
        if not text(scope, 1024) or not set(scope.split()).issubset((previous["scope"] if previous else self.profile["scope"]).split()):
            raise ClientError("token_scope_invalid", outcome=3)
        # Account and assurance come exclusively from the configured verified API.
        start = self.now()
        remaining = 10 if deadline is None else deadline - time.monotonic()
        if remaining <= 0:
            raise ClientError("authorization_expired", outcome=4, source="idp")
        identity, expiry = self._identity(data["access_token"], timeout=remaining)
        if previous is not None:
            self._same_identity(previous["identity"], identity)
        deadline = min(start + data["expires_in"], expiry, start + 3600)
        if deadline <= self.now():
            raise ClientError("token_expired", outcome=3)
        return {"access_token": data["access_token"], "refresh_token": refresh,
                "expires_at": deadline, "identity": identity, "scope": scope}

    def _session(self, record):
        session = record.get("session")
        if record["phase"] != "ready" or session is None:
            raise ClientError("login_required", outcome=3)
        if (session.keys() != {"access_token", "refresh_token", "expires_at", "identity", "scope"}
                or not secret(session["access_token"], 16384)
                or (session["refresh_token"] is not None and not secret(session["refresh_token"], 8192))
                or type(session["expires_at"]) not in {int, float} or not math.isfinite(session["expires_at"])
                or not isinstance(session["identity"], dict) or not text(session["scope"], 1024)):
            raise ClientError("client_store_invalid")
        return session

    def login(self, display):
        with self.store.locked():
            record = self.store.load()
            if record["phase"] != "empty":
                raise ClientError("logout_before_login", outcome=3)
            # Establish the generation before polling; logout can invalidate it.
            record["observed_at"] = self.now(record)
            self.store.save(record)
            generation = record["generation"]
        begun = time.monotonic()
        response = self.http.request("device_authorization_endpoint", payload={"client_id": self.profile["client_id"], "scope": self.profile["scope"]})
        data = response.body
        interval, expires = data.get("interval", 5), data.get("expires_in")
        if (response.status != 200 or "error" in data or not secret(data.get("device_code"), 8192)
                or not isinstance(data.get("user_code"), str) or not re.fullmatch(r"[A-Za-z0-9-]{4,32}", data["user_code"])
                or data.get("verification_uri") != self.profile["verification_uri"]
                or type(expires) is not int or not 1 <= expires <= 86400
                or type(interval) is not int or not 1 <= interval <= 86400):
            raise ClientError("device_authorization_invalid", outcome=3, source="idp", status=response.status)
        deadline = begun + min(expires, 900)
        display(self.profile["verification_uri"], data["user_code"])
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ClientError("authorization_expired", outcome=4, source="idp")
            time.sleep(min(interval, remaining))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ClientError("authorization_expired", outcome=4, source="idp")
            try:
                response = self.http.request("token_endpoint", payload={"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": data["device_code"], "client_id": self.profile["client_id"]}, timeout=remaining)
            except ClientError as error:
                if error.code != "request_timeout":
                    raise
                interval *= 2
                continue
            error = response.body.get("error")
            if response.status == 400 and isinstance(error, str) and error in {"authorization_pending", "slow_down"}:
                if error == "slow_down":
                    interval += 5
                continue
            if response.status != 200 or error is not None:
                code = error if isinstance(error, str) and error in {"access_denied", "expired_token"} else "authorization_failed"
                raise ClientError(code, outcome=3, source="idp", status=response.status)
            session = self._tokens(response, deadline=deadline)
            if time.monotonic() >= deadline:
                raise ClientError("authorization_expired", outcome=4, source="idp")
            with self.store.locked():
                current = self.store.load()
                if current["generation"] != generation or current["phase"] != "empty":
                    raise ClientError("login_cancelled", outcome=3)
                current.update(phase="ready", session=session, observed_at=self.now(current))
                self.store.save(current)
            return redact({"status": "authenticated", "identity": session["identity"], "expires_at": session["expires_at"]},
                          session["access_token"], session["refresh_token"])

    def _refresh(self, record):
        session = self._session(record)
        if session["refresh_token"] is None:
            raise ClientError("token_expired_login_required", outcome=3)
        record["phase"] = "refreshing"
        self.store.save(record)
        try:
            response = self.http.request("token_endpoint", payload={"grant_type": "refresh_token",
                "refresh_token": session["refresh_token"], "client_id": self.profile["client_id"]})
            new = self._tokens(response, session)
            record.update(phase="ready", session=new, observed_at=self.now(record))
            self.store.save(record)
        except BaseException:
            self.store.save(self.store.empty(record))
            raise

    @contextmanager
    def access(self):
        # Hold through verification and the request: logout cannot clear the cache
        # and then have an earlier command send a new request using stale credentials.
        with self.store.locked():
            record = self.store.load()
            session = self._session(record)
            if session["expires_at"] - self.now(record) < 30 and session["refresh_token"] is not None:
                self._refresh(record)
                session = self._session(record)
            identity, expiry = self._identity(session["access_token"])
            self._same_identity(session["identity"], identity)
            if min(session["expires_at"], expiry) <= self.now(record):
                raise ClientError("token_expired_login_required", outcome=3)
            record["observed_at"] = self.now(record)
            self.store.save(record)
            yield session["access_token"]

    def status(self):
        with self.store.locked():
            record = self.store.load()
            if record["phase"] == "empty":
                return {"status": "logged_out", "verified": False}, 3
            session = self._session(record)
            now = self.now(record)
            if session["expires_at"] <= now:
                return {"status": "expired", "verified": False}, 3
            identity, expiry = self._identity(session["access_token"])
            self._same_identity(session["identity"], identity)
            record["observed_at"] = self.now(record)
            self.store.save(record)
            return redact({"status": "online_verified", "verified": True, "identity": identity,
                    "expires_at": min(expiry, session["expires_at"])}, session["access_token"], session["refresh_token"]), 0

    def logout(self):
        with self.store.locked():
            record = self.store.load()
            session = record["session"]
            self.store.save(self.store.empty(record))
        acknowledged = session is None
        if session is not None and self.profile["revocation_endpoint"] is not None:
            acknowledged = True
            for key in ("refresh_token", "access_token"):
                token = session.get(key)
                if token is None:
                    continue
                try:
                    if not secret(token, 16384):
                        raise ClientError("client_store_invalid")
                    response = self.http.request("revocation_endpoint", payload={"client_id": self.profile["client_id"],
                        "token": token, "token_type_hint": key})
                    acknowledged = acknowledged and response.status == 200 and "error" not in response.body
                except ClientError:
                    acknowledged = False
        return {"status": "logged_out", "local_cleared": True,
                "provider_revocation": "not_needed" if session is None else "acknowledged" if acknowledged else "unconfirmed",
                "copied_access_tokens": "may_remain_accepted_until_expiry"}, 0 if acknowledged else 4
