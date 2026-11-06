# OIDC signature and claims validation

`cyberthunder.security.oidc` implements the ZT-03 token-verification boundary.
It returns authenticated claims; the application must separately map the
issuer/subject to a principal and enforce permissions. This feature alone does
not establish zero-trust compliance.

## Integration contract and dependencies

```python
from pathlib import Path
from cyberthunder.security.oidc import AuthenticationError, OIDCConfig, OIDCValidator

validator = OIDCValidator(OIDCConfig(
    issuer="https://identity.example.test/tenant",
    audience="cyber-thunder",
    jwks_url="https://identity.example.test/tenant/keys",
    cache_path=Path("/var/lib/cyber-thunder/identity/jwks.json"),
    max_age_s=86400,
    clock_skew_s=60,
    authorized_party=None,
))
# Inside the application's authentication boundary:
# claims = validator.validate(bearer_token)
# AuthenticationError must become a generic authentication rejection.
```

The constructor fields and `validate(token) -> dict` are the complete public
interface. Reuse one validator per configuration for all requests in a process.
Do not construct one per token: refresh deduplication and rate limits are scoped
to that instance. Separate processes should have separate cache files and an
application-level request/refresh limit. The synchronous first fetch can block
for up to five seconds; an asynchronous application should call it in its worker
pool. The parent integration owns settings, startup wiring, authentication
middleware, principal mapping, roles, audit provenance and dependency manifests.

Pinned runtime dependencies tested on Windows CPython 3.12 x64:

| Package | Version | Windows wheel |
| --- | --- | --- |
| PyJWT | 2.15.1 | `pyjwt-2.15.1-py3-none-any.whl` |
| cryptography | 50.0.2 | `cryptography-50.0.2-cp311-abi3-win_amd64.whl` |
| cffi | 2.1.1 | `cffi-2.1.1-cp312-cp312-win_amd64.whl` |
| pycparser | 3.12 | `pycparser-3.12-py3-none-any.whl` |

Pin/vendor all four for offline deployment, choosing matching wheels for each
Python/OS/architecture. The isolated fetch helper uses only the standard library.
No HTTP client dependency is added. Dependency manifests and vendored wheels are
deliberately left to the integrating change.

Settings must provide an explicit HTTPS issuer, exact audience, explicit HTTPS
JWKS URL, absolute cache filename, optional required authorized party, maximum
cache age and allowed clock skew. Issuer URLs cannot have query strings or
fragments. URLs cannot contain credentials, fragments, controls or backslashes.
Issuer discovery and token-supplied key locations are never used.

## Accepted token profile

Only RS256 and ES256 are accepted. PyJWT and cryptography perform signature and
public-key validation. The verifier passes an algorithm selected from the
validated issuer key to PyJWT. It does not derive the allowlist from the token.
This follows [PyJWT's algorithm guidance](https://pyjwt.readthedocs.io/en/stable/api.html)
and the [JWT security best practices](https://www.rfc-editor.org/rfc/rfc8725.html).

The profile is intentionally strict:

- Compact signed JWTs, at most 16 KiB, canonical unpadded base64url, UTF-8 JSON
  objects, no duplicate JSON members, nonfinite numbers or nesting beyond 32.
  `typ` may be absent or `JWT`; other token types, including `at+jwt`, are rejected.
- A printable, nonblank ASCII `kid` of at most 128 characters is required.
  `jku`, `jwk`, `x5u`, `x5c`, `crit`, `b64` and `zip` headers are rejected.
- `iss`, `sub`, `aud`, `iat` and `exp` are mandatory. Issuer is an exact match.
  Subject is nonblank printable ASCII, at most 255 characters. Audience is a
  nonempty string or a list of up to 16 distinct nonempty strings, each at most
  512 printable nonblank ASCII characters, containing the configured audience.
- `azp` is required for multiple audiences or when `authorized_party` is set.
  Whenever present, it must exactly equal `authorized_party`, or the configured
  audience when that setting is absent. It cannot be null or another JSON type.
- Dates must be integer NumericDates from zero through 253402300799; booleans,
  floats and numeric strings are rejected. Expiry must follow issuance by at
  most 3,600 seconds. Issuance cannot be more than the configured skew in the
  future, or more than 3,600 seconds plus skew in the past. Expiry plus skew is
  an exclusive upper bound for acceptance.
- Optional `nbf` must precede expiry, cannot be earlier than issuance minus skew,
  and cannot be later than current time plus skew. Optional `auth_time` must not
  exceed issuance or current time plus skew. Optional `jti` must be a nonblank
  printable ASCII string of at most 512 characters. Other claims are returned as
  signed JSON data; they do not acquire application authorization semantics.

Exact issuer/audience checks and authorized-party handling are based on
[OpenID Connect Core token validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).
The bounds and mandatory multi-audience `azp` check are this application's
stricter profile. This API has no login-transaction state: it does not verify
nonce, state, PKCE, `at_hash`, token replay, revocation or session binding. Use
a dedicated audience for this token profile. Do not allow interchangeable ID and
access tokens with the same issuer/audience; implementing a complete login flow
or RFC 9068 access-token profile requires separate integration work.

## Keys, HTTP and resource limits

A JWKS must contain 1–32 unique keys with valid `kid` values. Duplicate identifiers
reject the entire set, including duplicates across different key types. All keys
must be public signature-verification keys. A mixed set containing unsupported
algorithms, encryption keys or private material rejects the entire set.
Key metadata follows [the JWK format](https://www.rfc-editor.org/rfc/rfc7517.html),
with stricter uniqueness and key-usage requirements for this verifier.

RSA keys require a canonical 2048–8192-bit modulus and exponent 65537, with `alg`
absent or `RS256`. EC keys require P-256, exactly 32-byte coordinates, a valid
curve point, and `alg` absent or `ES256`. Optional `use` must be `sig`; optional
`key_ops` must be exactly `["verify"]`. Absent `alg` is fixed by key type.
Public certificate metadata is discarded; remote key URLs and private fields
are rejected. Cached keys contain only normalized public verification fields.

HTTPS requests use system certificate and hostname verification, including
Python/OpenSSL's configured `SSL_CERT_FILE`/`SSL_CERT_DIR` trust inputs. Provision
the enterprise CA through trusted deployment configuration; there is no option
to disable verification. Requests send no authorization, cookies or token text,
ignore proxy environment variables, and never follow redirects. Only the
configured URL is fetched. Administrators must allowlist that endpoint; no token
can choose its host or path.

The reader accepts HTTP 200 JSON/JWK-set media types, rejects compression and
ambiguous framing, and caps the decoded body at 256 KiB. Its socket timeout is
two seconds. A disposable isolated Python process has a five-second total
deadline, bounding DNS resolution, TLS, headers and trickled/chunked body reads.
Timeout kills and reaps the helper. No background fetch threads are retained.
The installed package must include `_oidc_fetch.py`; its executable is the
running Python interpreter, never a shell command.

## Refresh and offline cache rules

- Valid known keys are used locally until cache age reaches `max_age_s`.
  `max_age_s` must be an integer in 1–86,400; skew must be an integer in 0–300.
  Expiry and all token checks still apply offline.
- A missing or expired cache, or an unknown `kid`, can trigger one refresh.
  A per-instance lock collapses concurrent requests. There is at most one fetch
  attempt per 30 seconds, including failures. Unknown identifiers are negatively
  cached for 60 seconds in a bounded 256-entry LRU. Distinct attacker-supplied
  identifiers cannot bypass the global interval. A new rotation may therefore
  need to wait for the existing cooldown to expire.
- A successful fetch atomically replaces the key set; removed keys are no longer
  accepted. Invalid signatures under an existing key do not trigger refreshes.
  Failed refreshes preserve an existing fresh cache but cannot extend its age.
  Stale keys, an offline first start, or unknown keys while offline fail closed.
- Cache documents are at most 512 KiB and bind issuer, audience, authorized party
  and JWKS URL. Malformed, mismatched, unsafe or future-dated cache files reject
  authentication; they are not silently replaced through network recovery.
  An administrator can remove a corrupt file and re-prime through trusted HTTPS.
- Cache writes use a same-directory exclusive temporary file, file fsync and
  atomic replacement (plus directory fsync on POSIX). Failed writes do not publish
  new keys. Successful validations persist a wall-clock high-water mark when
  its integer second advances. A persistence failure rejects that validation.
- Cache files must be regular, singly linked files. Symlinks and Windows reparse
  points are rejected in the path and its existing ancestors. POSIX additionally
  requires service ownership, private file permissions and a parent directory
  that is not writable by group or others. The directory must already exist.
  Windows deployment must enforce a service-only directory ACL: this module
  detects reparse points but does not inspect or set Windows ACLs.
- Effective time is the maximum of wall time and monotonic elapsed time projected
  from the previous check. Small backward corrections never extend token or key
  lifetime. Clock sampling has a minimum 10 ms measurement tolerance, including
  when token skew is zero; this never adds token-expiry leeway. A rollback
  exceeding the larger of skew and that tolerance latches rejection; repair
  the clock and recreate it. Persisted observation time catches rollback across
  ordinary restarts. A live instance never reloads an older disk key set.

The cache is a trusted local file, not an authenticated backup format. A party
able to edit its contents can substitute keys. Rolling back both the cache and
clock across a restart cannot be detected without an external monotonic anchor
or protected hardware state. Protect the directory and backups and provision a
trusted clock. Offline key revocation may take up to the configured cache age;
immediate revocation requires online checking or an operational cache purge.

## Verification and external acceptance

`tests/security/test_oidc.py` uses freshly generated RSA/EC signatures and a
loopback HTTPS server signed by a temporary test CA. It covers claim/type and
algorithm attacks, duplicate JSON and identifiers, malformed JWKs, rotation,
concurrency, negative caching, offline restart, stale keys, clock rollback,
atomic-write failure, file hazards, TLS verification, redirects, resource bounds
and slow response deadlines. Fixtures never contact a real identity provider.

Run the focused suite from the assigned checkout with its root in `PYTHONPATH`:

```powershell
$env:PYTHONPATH = 'C:/Users/joshu/.codex/worktrees/oidc-validation/cyber-thunder'
& 'C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe' -m pytest tests/security/test_oidc.py -o addopts= -q --tb=short
```

Measured result on Windows CPython 3.12.10: **209 passed, 2 skipped** (77.33 s).
The skips are POSIX permission/ownership and symlink fixtures; the Windows
junction test ran and passed. The staged whitespace check also passed. These
results are isolated verifier acceptance, not a full application or Linux gate.

The separate implementation self-review traced algorithm/key selection, all
refresh paths, the clock/cache state transitions, HTTP resource bounds and file
replacement behavior. It found and fixed a zero-skew clock-sampling false
rejection, and made signature verification explicit rather than depending on the
library's default options. Regression tests cover both. The review also checked
that malformed-token tests actually reach the verifier: fixture signing uses
raw JWS input where the normal encoder refuses intentionally invalid claims.
Wrong-signature tests never substitute mocked cryptographic verification.

External acceptance still requires parent application integration, pinned wheels
for every deployment platform, Linux gates, Windows cache ACL provisioning,
trusted clock/CA deployment, and authorized testing of an actual provider's
token/JWKS profile and rotation behavior. No IdP account, external configuration
or live network was changed by this implementation. Local fixtures do not close
those deployment acceptance items.
