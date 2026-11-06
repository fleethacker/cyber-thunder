# Independent OIDC verifier review

Reviewed base: `a91171937aebc4ae401ed4bc50d452673ae34e10`.
Scope: `security/oidc.py`, `_oidc_cache.py`, `_oidc_fetch.py` and verifier tests.
Browser sessions, principal policy and application middleware are outside this
review. No live identity provider or external host was contacted or changed.

## Fixed findings

### Live cache invalidation was ignored (P1)

After a validator loaded a valid key set, deleting its cache or replacing that
file with a set that removed the signing key did not affect validation under the
old key. Corrupt cache contents were also ignored. When the integer second
advanced, watermark persistence could recreate the deleted cache or overwrite
the replacement with stale in-memory keys. This undermined the documented
cache-purge revocation procedure and allowed conflicting live writers to roll
back persisted state.

Five new signed-token regressions failed on the original verifier: deletion in
the same second and after a two-second advance, corrupt contents, replacement
keys, and a removed key. All accepted the superseded key when rejection was
required. The tests use valid cryptographic signatures, not a substituted
signature-verification result.

The validator now remembers a SHA-256 digest of the exact cache bytes it loaded
or published. It repeats bounded file/safety checks before key use, before
persistence and before returning authenticated claims. An observed mismatch or
unsafe/unreadable file clears in-memory keys and latches rejection. Restoring
previous cache bytes does not release the latch. Persistence checks the expected
cache immediately before creating the temporary file and before replacement,
then verifies the published bytes. A fresh validator is required after repair;
it must obtain fresh trusted keys when the cache was purged.

Additional regressions cover deletion during real signature verification,
deletion at both persistence boundaries, conflicting live writers with different
clock watermarks, an oversized cache introduced after initial validation, and
explicit reinitialization with a new key set.

### Clock sampling could falsely latch rejection (P2)

The verifier sampled wall time and then monotonic time. With zero configured
skew, a thread descheduled for more than ten milliseconds between these reads
appeared to have suffered clock rollback. That set a permanent rejection latch
even though both clocks advanced correctly. A deterministic 250 ms scheduler
pause reproduced this with a valid signed token.

The wall sample is now bracketed by two monotonic reads. Rollback is compared
against the earliest possible sample time, while effective time advances to the
end of the interval. Tests confirm that scheduler pauses do not latch rollback,
tokens expiring during the interval remain rejected without added leeway, and
real backward wall-clock movement still latches rejection.

### Expiry during cache persistence was not rechecked (P2)

The last token and key-cache lifetime checks preceded local cache persistence.
A slow file write/fsync could therefore return authenticated claims after their
expiry or after the signing-key cache reached its maximum age. Two signed-token
regressions advanced the clocks during a successful write and reproduced both
acceptances. The verifier now rechecks effective time, claims and key-cache age
after the final cache I/O, immediately before returning claims.

## Other reviewed boundaries

- Signature verification explicitly enables verification and restricts the
  algorithm to the validated trusted JWK's RS256 or ES256 type. The installed
  PyJWT implementation and RSA/EC key preparation were inspected. Existing real
  signature tests cover wrong signers, key-type confusion, payload/signature
  modification, HMAC/public-key confusion and disallowed algorithms.
- Duplicate JSON members, noncanonical encodings, unsupported JOSE references,
  malformed key parameters and private keys fail closed. The `kid` only indexes
  a bounded trusted key set; it never selects a URL, path or executable.
- Issuer equality, audience membership/type/uniqueness, conditional `azp`,
  bounded integer dates and the mandatory lifetime profile are checked again
  after signature verification. No additional signature/claim acceptance bypass
  was found in this review.
- Unknown-key refreshes are serialized and rate-limited per instance; negative
  entries and key sets are bounded. Successful refresh replaces removed keys.
  HTTP fetches use the fixed HTTPS endpoint, certificate/hostname validation,
  no proxy credentials or redirects, bounded framing/body reads, and a reaped
  subprocess deadline. The original loopback HTTPS regressions exercise these
  paths, including trickled responses and TLS errors.
- Cache reads bound both file size and read length, reject links/non-regular
  files, compare the opened file identity, and enforce POSIX private ownership
  and permissions. Writes use exclusive temporary files and atomic replacement.
  The follow-up checks extend those protections to already-running validators.

## Remaining limits and integration requirements

- Use one live validator per cache file. File digest checks and atomic replace
  are not a cross-process transaction or filesystem compare-and-swap. Stop
  authentication traffic and recreate affected validators when performing an
  immediate revocation purge; arbitrary unlink/replacement racing the final
  filesystem operation and already-running requests need coordinated lifecycle
  control. A privileged cache editor remains inside the trusted local boundary.
- Existing known keys are accepted offline until the configured maximum age.
  Removed keys become unusable after a successful refresh or observed cache
  invalidation. A provider reusing the same `kid` for different key material does
  not trigger an early refresh on signature failure; use new key identifiers for
  rotation or coordinate a verifier reset. This is an existing documented
  availability/revocation tradeoff, not a newly added signature fallback.
- Windows service-only cache ACL provisioning and real POSIX permissions remain
  deployment acceptance. The Windows tests cannot establish the POSIX cases.
  Rolling back both trusted cache and clock across a restart still needs an
  external monotonic anchor to detect.
- Exact provider claims, key rotation and CA deployment need authorized provider
  acceptance. Nonce/state/PKCE, token-kind separation, replay, browser sessions,
  per-user policy and middleware are separate integration boundaries.
- The additional bounded cache reads trade local file I/O for live invalidation
  detection. No public constructor or validation interface changed, and no new
  dependencies were introduced. Runtime used: PyJWT 2.15.1, cryptography 50.0.2.

## Reproduction and verification

The original suite passed before changes: **209 passed, 2 skipped in 32.47s**.
The five invalidation reproductions then failed as expected. After that fix,
the scheduler-pause reproduction failed while eleven other review cases passed.
Two further regressions reproduced token/key expiry during cache persistence.
The skips in the original suite are its POSIX-only file-permission and symlink
tests; the Windows junction test runs.

Final focused result on Windows CPython 3.12: **225 passed, 2 skipped in 27.98s**,
including all sixteen independent review regressions. All five changed files
use LF, all three Python files parse successfully, and the whitespace check
passes. Runtime dependency versions were confirmed directly in the shared
interpreter as PyJWT 2.15.1 and cryptography 50.0.2.

```powershell
$env:PYTHONPATH = 'C:/Users/joshu/.codex/worktrees/kubernetes-fix-safety/cyber-thunder'
& 'C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe' `
  -m pytest tests/security/test_oidc.py tests/security/test_oidc_review.py -o addopts= -q --tb=short
git diff --check
```

Changed paths: `cyberthunder/security/oidc.py`,
`cyberthunder/security/_oidc_cache.py`, `tests/security/test_oidc_review.py`,
`docs/OIDC_VALIDATION.md`, and `docs/OIDC_REVIEW.md`. The fetch helper required no
change. Application-wide gates and live-provider acceptance were not run.
