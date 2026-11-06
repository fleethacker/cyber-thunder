"""Non-secret, operator-provisioned client profile; no application Settings."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
import re
from types import MappingProxyType
from urllib.parse import urlsplit

from . import files
from .errors import ClientError, decode, text


def endpoint(value):
    try:
        if (not text(value, 2048) or not value.isascii() or any(c in value for c in "\\%?#")
                or " " in value):
            raise ValueError()
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None
                or parsed.port == 0 or any(p in {".", "..", ""} for p in parsed.path.split('/')[1:])):
            raise ValueError()
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                       for label in parsed.hostname.split(".")):
                raise ValueError()
        return parsed
    except (ValueError, TypeError):
        raise ClientError("profile_endpoint_invalid") from None


@dataclass(frozen=True, repr=False)
class ClientProfile:
    document: dict = field(repr=False)
    digest: str
    ca_pem: str | None = field(default=None, repr=False)

    @classmethod
    def load(cls, filename):
        try:
            document = decode(files.read(filename))
            expected = {"version", "api_base_url", "issuer", "audience", "client_id",
                        "device_authorization_endpoint", "token_endpoint", "revocation_endpoint",
                        "verification_uri", "scope", "ca_file"}
            if (document.keys() != expected or type(document["version"]) is not int or document["version"] != 1):
                raise ValueError()
            for name in ("api_base_url", "issuer", "device_authorization_endpoint", "token_endpoint", "verification_uri"):
                endpoint(document[name])
            if document["revocation_endpoint"] is not None:
                endpoint(document["revocation_endpoint"])
            if not document["api_base_url"].endswith("/api/v1"):
                raise ValueError()
            issuer = endpoint(document["issuer"])
            for name in ("device_authorization_endpoint", "token_endpoint", "verification_uri", "revocation_endpoint"):
                if document[name] is not None:
                    selected = endpoint(document[name])
                    if (selected.hostname, selected.port or 443) != (issuer.hostname, issuer.port or 443):
                        raise ValueError()
            if (not text(document["audience"], 256) or not text(document["client_id"], 256)
                    or document["audience"] == document["client_id"] or not text(document["scope"], 1024)):
                raise ValueError()
            scopes = document["scope"].split(" ")
            if ("openid" not in scopes or len(scopes) > 32 or len(set(scopes)) != len(scopes)
                    or any(not s or any(ord(c) < 33 or ord(c) > 126 or c in '\\"' for c in s) for s in scopes)):
                raise ValueError()
            ca = None
            if document["ca_file"] is not None:
                ca = files.read(document["ca_file"], maximum=262144).decode("ascii")
                if "-----BEGIN CERTIFICATE-----" not in ca or "PRIVATE KEY" in ca:
                    raise ValueError()
            material = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
            digest = hashlib.sha256(material + b"\0" + (ca or "system-trust").encode()).hexdigest()
            return cls(MappingProxyType(document), digest, ca)
        except ClientError:
            raise
        except (ValueError, TypeError, UnicodeError, KeyError):
            raise ClientError("profile_invalid") from None

    def __getitem__(self, key):
        return self.document[key]
