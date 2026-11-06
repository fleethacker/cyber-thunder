"""Independent verifier regression tests; signed tokens and isolated cache changes."""

import json
import time

import pytest

from cyberthunder.security import _oidc_cache, oidc
from cyberthunder.security.oidc import OIDCValidator
from tests.security.test_oidc import (
    claims, jwk, offline_config, rejected, signing_keys, token,
)


@pytest.mark.parametrize("elapsed", [0, 2])
def test_live_cache_purge_rejects_old_key_without_recreating_cache(tmp_path, signing_keys, monkeypatch, elapsed):
    config = offline_config(tmp_path, signing_keys)
    wall, mono = time.time(), time.monotonic()
    monkeypatch.setattr(oidc.time, "time", lambda: wall)
    monkeypatch.setattr(oidc.time, "monotonic", lambda: mono)
    validator = OIDCValidator(config)
    encoded = token(signing_keys)
    assert validator.validate(encoded)["sub"] == "operator-123"
    config.cache_path.unlink()
    monkeypatch.setattr(oidc.time, "time", lambda: wall + elapsed)
    monkeypatch.setattr(oidc.time, "monotonic", lambda: mono + elapsed)
    rejected(validator, encoded)
    assert not config.cache_path.exists()


@pytest.mark.parametrize("change", ["corrupt", "replace-keys", "remove-key"])
def test_live_external_cache_change_cannot_keep_using_superseded_keys(tmp_path, signing_keys, monkeypatch, change):
    config = offline_config(tmp_path, signing_keys)
    wall, mono = time.time(), time.monotonic()
    monkeypatch.setattr(oidc.time, "time", lambda: wall)
    monkeypatch.setattr(oidc.time, "monotonic", lambda: mono)
    validator = OIDCValidator(config)
    encoded = token(signing_keys)
    validator.validate(encoded)
    original = config.cache_path.read_bytes()
    document = json.loads(original)
    if change == "corrupt":
        updated = b"invalid-cache-private-text"
    else:
        document["jwks"] = {"keys": [jwk(signing_keys["rogue"], "replacement")] if change == "replace-keys"
                            else [jwk(signing_keys["ec"], "ec")]}
        updated = json.dumps(document).encode()
    _oidc_cache.write_cache(config.cache_path, updated)
    rejected(validator, encoded)
    assert config.cache_path.read_bytes() == updated
    # Restoration of the original trusted cache must not silently undo the latch.
    _oidc_cache.write_cache(config.cache_path, original)
    rejected(validator, encoded)


def test_zero_skew_scheduler_pause_between_clock_reads_is_not_rollback(tmp_path, signing_keys, monkeypatch):
    config = offline_config(tmp_path, signing_keys, clock_skew_s=0)
    encoded = token(signing_keys)
    validator = OIDCValidator(config)
    wall, mono = time.time(), time.monotonic()
    validator._wall_anchor, validator._mono_anchor = wall, mono
    clock = {"elapsed": 0.0, "pause": False}

    def read_wall():
        clock["pause"] = True
        return wall + clock["elapsed"]

    def read_mono():
        # A thread can be descheduled between time.time() and time.monotonic().
        if clock["pause"]:
            clock["elapsed"] += 0.25
            clock["pause"] = False
        return mono + clock["elapsed"]

    monkeypatch.setattr(oidc.time, "time", read_wall)
    monkeypatch.setattr(oidc.time, "monotonic", read_mono)
    assert validator.validate(encoded)["sub"] == "operator-123"
    assert not validator._clock_failed
    assert validator._wall_anchor >= wall + clock["elapsed"]


def test_bracketed_sampling_does_not_add_token_leeway(tmp_path, signing_keys, monkeypatch):
    config = offline_config(tmp_path, signing_keys, clock_skew_s=0)
    wall, mono = time.time(), time.monotonic()
    encoded = token(signing_keys, claims(iat=int(wall), exp=int(wall) + 1))
    validator = OIDCValidator(config)
    validator._wall_anchor, validator._mono_anchor = wall, mono
    samples = iter([mono, mono + 2])
    monkeypatch.setattr(oidc.time, "time", lambda: wall)
    monkeypatch.setattr(oidc.time, "monotonic", lambda: next(samples))
    rejected(validator, encoded)
    assert not validator._clock_failed
    assert validator._wall_anchor == wall + 2


def test_actual_rollback_with_scheduler_pause_still_latches(tmp_path, signing_keys, monkeypatch):
    config = offline_config(tmp_path, signing_keys, clock_skew_s=0)
    encoded = token(signing_keys)
    validator = OIDCValidator(config)
    wall, mono = time.time(), time.monotonic()
    validator._wall_anchor, validator._mono_anchor = wall, mono
    samples = iter([mono, mono + 0.25])
    monkeypatch.setattr(oidc.time, "time", lambda: wall - 1)
    monkeypatch.setattr(oidc.time, "monotonic", lambda: next(samples))
    rejected(validator, encoded)
    assert validator._clock_failed


@pytest.mark.parametrize("phase", ["signature", "persist-start", "persist-replace"])
def test_cache_purge_during_validation_cannot_be_undone(tmp_path, signing_keys, monkeypatch, phase):
    config = offline_config(tmp_path, signing_keys)
    validator = OIDCValidator(config)
    encoded = token(signing_keys)
    validator.validate(encoded)
    if phase == "signature":
        original = oidc.jwt.api_jws.decode_complete
        def verify_then_purge(*args, **kwargs):
            result = original(*args, **kwargs)
            config.cache_path.unlink()
            return result
        monkeypatch.setattr(oidc.jwt.api_jws, "decode_complete", verify_then_purge)
    else:
        # Force watermark persistence while retaining real signature verification.
        validator._observed_at -= 1
        if phase == "persist-start":
            original = oidc.write_cache
            def purge_then_write(*args, **kwargs):
                config.cache_path.unlink()
                return original(*args, **kwargs)
            monkeypatch.setattr(oidc, "write_cache", purge_then_write)
        else:
            original = _oidc_cache.os.fsync
            def sync_then_purge(fd):
                original(fd)
                config.cache_path.unlink(missing_ok=True)
            monkeypatch.setattr(_oidc_cache.os, "fsync", sync_then_purge)
    rejected(validator, encoded)
    assert not config.cache_path.exists()
    assert not list(tmp_path.glob(".oidc-*"))


def test_two_live_writers_cannot_regress_the_cache_watermark(tmp_path, signing_keys, monkeypatch):
    config = offline_config(tmp_path, signing_keys)
    wall, mono = time.time(), time.monotonic()
    clock = {"elapsed": 0}
    monkeypatch.setattr(oidc.time, "time", lambda: wall + clock["elapsed"])
    monkeypatch.setattr(oidc.time, "monotonic", lambda: mono + clock["elapsed"])
    first, second = OIDCValidator(config), OIDCValidator(config)
    encoded = token(signing_keys)
    first.validate(encoded)
    second.validate(encoded)
    clock["elapsed"] = 10
    first.validate(encoded)
    updated = config.cache_path.read_bytes()
    # A small wall correction can leave the second instance below the first
    # writer's watermark without triggering its independent rollback detector.
    clock["elapsed"] = 5
    rejected(second, encoded)
    assert config.cache_path.read_bytes() == updated
    clock["elapsed"] = 10
    assert first.validate(encoded)["sub"] == "operator-123"


def test_same_second_cache_file_hazards_are_rechecked(tmp_path, signing_keys, monkeypatch):
    config = offline_config(tmp_path, signing_keys)
    wall, mono = time.time(), time.monotonic()
    monkeypatch.setattr(oidc.time, "time", lambda: wall)
    monkeypatch.setattr(oidc.time, "monotonic", lambda: mono)
    validator = OIDCValidator(config)
    encoded = token(signing_keys)
    validator.validate(encoded)
    config.cache_path.write_bytes(b" " * (_oidc_cache.MAX_CACHE_BYTES + 1))
    rejected(validator, encoded)


def test_fresh_instance_can_prime_after_explicit_cache_purge(tmp_path, signing_keys, monkeypatch):
    from types import SimpleNamespace
    config = offline_config(tmp_path, signing_keys)
    encoded = token(signing_keys)
    validator = OIDCValidator(config)
    validator.validate(encoded)
    config.cache_path.unlink()
    rejected(validator, encoded)
    # Reinitialization and a trusted fetch are required; no stale key resurrection.
    monkeypatch.setattr(oidc.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(stdout=json.dumps({"keys": [jwk(signing_keys["ec"], "ec")]}).encode()))
    restarted = OIDCValidator(config)
    assert restarted.validate(token(signing_keys, kid="ec"))["sub"] == "operator-123"
    rejected(restarted, encoded)
    rejected(validator, token(signing_keys, kid="ec"))


@pytest.mark.parametrize("expires", ["token", "keys"])
def test_expiry_during_cache_persistence_is_checked_before_return(tmp_path, signing_keys, monkeypatch, expires):
    wall, mono = int(time.time()), time.monotonic()
    config = offline_config(tmp_path, signing_keys, fetched=wall - 1, observed=wall - 1,
                            clock_skew_s=0, max_age_s=2 if expires == "keys" else 100)
    encoded = token(signing_keys, claims(iat=wall - 1, exp=wall + (2 if expires == "token" else 300)))
    clock = {"elapsed": 0}
    monkeypatch.setattr(oidc.time, "time", lambda: wall + clock["elapsed"])
    monkeypatch.setattr(oidc.time, "monotonic", lambda: mono + clock["elapsed"])
    validator = OIDCValidator(config)
    original = oidc.write_cache
    def persist_then_advance(*args, **kwargs):
        original(*args, **kwargs)
        clock["elapsed"] = 3
    monkeypatch.setattr(oidc, "write_cache", persist_then_advance)
    rejected(validator, encoded)
