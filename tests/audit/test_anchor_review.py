"""Independent checkpoint review using disposable keys and protected local files."""
import base64
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import errno
import json
import os
import subprocess
import sys
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from cyberthunder.audit import anchors as a
from cyberthunder.audit.chain import file_lock
from tests.audit.test_anchors import export, fixture, process_env, signed


@pytest.mark.parametrize("field", ["node", "log_instance", "key_id", "sequence", "head_hash", "previous"])
def test_signature_binds_every_variable_checkpoint_field(fixture, field):
    f = fixture
    path, _ = export(f)
    a.initialize_store(f["store"], f["trust"])
    a.import_checkpoint(path, f["trust"], f["store"])
    before = f["store"].read_bytes()
    bundle = json.loads(path.read_bytes())
    body = bundle["checkpoint"]
    body[field] = {
        "node": "other-node", "log_instance": "b" * 32, "key_id": "alias",
        "sequence": 2, "head_hash": "b" * 64,
        "previous": {"sequence": 0, "head_hash": a.GENESIS, "checkpoint_id": "c" * 64},
    }[field]
    # Scope/key changes remain trusted and schema-valid; rejection must require
    # the unchanged real signature to match this changed body.
    trust = json.loads(f["trust"].read_bytes())
    trust["streams"][0]["keys"]["alias"] = str(f["public"])
    if field in {"node", "log_instance"}:
        extra = deepcopy(trust["streams"][0])
        extra[field] = body[field]
        trust["streams"].append(extra)
    f["trust"].write_bytes(a.canonical(trust))
    a._checkpoint(body)
    path.write_bytes(a.canonical(bundle))
    with pytest.raises(a.AnchorError):
        a.verify_checkpoint(path, f["trust"])
    with pytest.raises(a.AnchorError):
        a.import_checkpoint(path, f["trust"], f["store"])
    assert f["store"].read_bytes() == before


@pytest.mark.parametrize("kind", ["private_as_public", "ec_public", "second_public", "second_private", "encrypted_private"])
def test_key_files_are_exactly_one_key_of_the_required_type(fixture, kind):
    f = fixture
    path, _ = export(f)
    if kind == "private_as_public":
        f["public"].write_bytes(f["private"].read_bytes())
    elif kind == "ec_public":
        f["public"].write_bytes(ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    elif kind == "second_public":
        f["public"].write_bytes(f["public"].read_bytes() * 2)
    elif kind == "second_private":
        f["private"].write_bytes(f["private"].read_bytes() * 2)
    else:
        f["private"].write_bytes(f["key"].private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"disposable-fixture")))
    if kind in {"private_as_public", "ec_public", "second_public"}:
        with pytest.raises(a.AnchorError):
            a.verify_checkpoint(path, f["trust"])
    with pytest.raises(a.AnchorError):
        export(f, "refused-key.json")
    assert not (f["root"] / "refused-key.json").exists()


@pytest.mark.parametrize("suffix", [b"=", b"\n", b"\x00"])
def test_noncanonical_signature_text_is_refused(fixture, suffix):
    f = fixture
    path, _ = export(f)
    bundle = json.loads(path.read_bytes())
    bundle["signature"] += suffix.decode("ascii")
    path.write_bytes(a.canonical(bundle))
    with pytest.raises(a.AnchorError):
        a.verify_checkpoint(path, f["trust"])


def test_signature_nonzero_padding_bits_are_refused(fixture):
    f = fixture
    path, _ = export(f)
    bundle = json.loads(path.read_bytes())
    original = bundle["signature"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    bundle["signature"] = original[:-1] + alphabet[alphabet.index(original[-1]) + 1]
    assert base64.urlsafe_b64decode(bundle["signature"] + "==") == base64.urlsafe_b64decode(original + "==")
    path.write_bytes(a.canonical(bundle))
    with pytest.raises(a.AnchorError):
        a.verify_checkpoint(path, f["trust"])


def test_streams_cannot_borrow_each_others_predecessor(fixture):
    f = fixture
    first, _ = export(f)
    a.initialize_store(f["store"], f["trust"])
    a.import_checkpoint(first, f["trust"], f["store"])
    first_body = json.loads(first.read_bytes())["checkpoint"]
    trust = json.loads(f["trust"].read_bytes())
    other = deepcopy(trust["streams"][0])
    other["log_instance"] = "b" * 32
    trust["streams"].append(other)
    f["trust"].write_bytes(a.canonical(trust))
    other_body = {**first_body, "log_instance": "b" * 32}
    second = signed(f, other_body, "other.json")
    a.import_checkpoint(second, f["trust"], f["store"])
    before = f["store"].read_bytes()
    borrowed = {**other_body, "sequence": 2, "head_hash": "e" * 64, "previous": a._reference(first_body)}
    path = signed(f, borrowed, "borrowed.json")
    assert a.verify_checkpoint(path, f["trust"])["signature"] == "verified"
    with pytest.raises(a.AnchorError, match="does not extend"):
        a.import_checkpoint(path, f["trust"], f["store"])
    assert f["store"].read_bytes() == before


@pytest.mark.parametrize("operation", ["export", "import"])
@pytest.mark.parametrize("stage", ["flush", "publish", "after_publish"])
def test_publication_failure_is_safe_and_retry_does_not_roll_back(fixture, monkeypatch, operation, stage):
    f = fixture
    first, _ = export(f)
    a.initialize_store(f["store"], f["trust"])
    a.import_checkpoint(first, f["trust"], f["store"])
    before = f["store"].read_bytes()
    f["log"].append("next", "Operator")
    next_path, _ = export(f, "next.json", first)
    out = f["root"] / "failed.json"

    def fail(*args, **kwargs):
        raise OSError("PRIVATE FIXTURE DETAILS")

    with monkeypatch.context() as patch:
        if stage == "flush":
            patch.setattr(a.files.os, "fsync", fail)
        elif stage == "publish":
            patch.setattr(a.files.os, "link" if operation == "export" else "replace", fail)
        else:
            patch.setattr(a.files, "_sync_parent", fail)
        with pytest.raises(a.AnchorError) as exc:
            if operation == "export":
                a.export_checkpoint(f["signer"], f["trust"], out, previous=first)
            else:
                a.import_checkpoint(next_path, f["trust"], f["store"])
        assert "PRIVATE FIXTURE" not in str(exc.value)
    assert not list(f["root"].glob(".audit-anchor-*"))
    if operation == "export":
        assert out.exists() is (stage == "after_publish")
        if out.exists():
            assert a.check_log(f["log"].path, out, f["trust"])["sequence"] == 2
            with pytest.raises(a.AnchorError):
                a.export_checkpoint(f["signer"], f["trust"], out, previous=first)
        else:
            assert a.export_checkpoint(f["signer"], f["trust"], out, previous=first)["sequence"] == 2
        assert f["store"].read_bytes() == before
    else:
        if stage != "after_publish":
            assert f["store"].read_bytes() == before
        result = a.import_checkpoint(next_path, f["trust"], f["store"])
        assert result["local_anchor_state"] == ("unchanged" if stage == "after_publish" else "advanced")
        with pytest.raises(a.AnchorError, match="rollback"):
            a.import_checkpoint(first, f["trust"], f["store"])


def test_process_lock_timeout_is_bounded_and_does_not_release_other_writer(fixture, monkeypatch, capsys):
    f = fixture
    path = f["log"].path.with_name(f["log"].path.name + ".lock")
    ready, release = f["root"] / "ready", f["root"] / "release"
    script = """
import sys,time
from pathlib import Path
from cyberthunder.audit.chain import file_lock
path,ready,release=map(Path,sys.argv[1:])
with file_lock(path):
    ready.touch()
    deadline=time.monotonic()+10
    while not release.exists() and time.monotonic()<deadline:
        time.sleep(.01)
"""
    child = subprocess.Popen([sys.executable, "-c", script, str(path), str(ready), str(release)],
        env=process_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while not ready.exists():
            assert time.monotonic() < deadline and child.poll() is None
            time.sleep(.01)

        def attempt():
            with file_lock(path, timeout=.1):
                return "acquired"

        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(attempt)
            try:
                with pytest.raises(TimeoutError, match="audit log lock busy"):
                    pending.result(timeout=1)
                # A second attempt still cannot acquire the other process's lock.
                with pytest.raises(TimeoutError, match="audit log lock busy"):
                    attempt()
                monkeypatch.setattr(a.files, "file_lock", lambda path: file_lock(path, timeout=.1))
                output = f["root"] / "busy.json"
                assert a.main(["export", "--signer", str(f["signer"]), "--trust", str(f["trust"]),
                               "--out", str(output)]) == 2
                captured = capsys.readouterr()
                assert not output.exists() and not captured.out
                assert str(f["root"]) not in captured.err and "PRIVATE KEY" not in captured.err
                assert child.poll() is None
            finally:
                release.touch()
        stdout, stderr = child.communicate(timeout=10)
        assert child.returncode == 0 and not stdout, stderr.decode()
        with file_lock(path, timeout=.1):
            pass
    finally:
        release.touch()
        if child.poll() is None:
            child.kill()
            child.communicate()


def test_noncontention_lock_error_is_not_retried_or_unlocked(fixture, monkeypatch):
    if os.name == "nt":
        import msvcrt as module
        name = "locking"
    else:
        import fcntl as module
        name = "flock"
    calls = []

    def failed(*args):
        calls.append(args)
        raise OSError(errno.EINVAL, "unsupported fixture lock")

    monkeypatch.setattr(module, name, failed)
    with pytest.raises(OSError) as exc:
        with file_lock(fixture["root"] / "unsupported.lock", timeout=.1):
            pytest.fail("unsupported lock must never enter the critical section")
    assert exc.value.errno == errno.EINVAL and len(calls) == 1


def test_exception_inside_lock_releases_it_for_the_next_caller(fixture):
    path = fixture["root"] / "released.lock"
    with pytest.raises(RuntimeError, match="fixture operation failed"):
        with file_lock(path, timeout=.1):
            raise RuntimeError("fixture operation failed")
    with file_lock(path, timeout=.1):
        pass


@pytest.mark.parametrize("operation", ["export", "verify", "check-log", "init", "import"])
def test_cli_has_no_ambient_trust_or_actor_override(fixture, capsys, operation):
    f = fixture
    first, _ = export(f)
    options = {
        "export": ["--signer", str(f["signer"]), "--out", str(f["root"] / "other.json")],
        "verify": ["--bundle", str(first)],
        "check-log": ["--bundle", str(first), "--log", str(f["log"].path)],
        "init": ["--store", str(f["store"])],
        "import": ["--bundle", str(first), "--store", str(f["store"])],
    }
    args = [operation, "--trust", str(f["trust"]), *options[operation], "--actor", "private-override"]
    with pytest.raises(SystemExit) as exc:
        a.main(args)
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert not captured.out and "private-override" not in captured.err
    assert not f["store"].exists()


@pytest.mark.skipif(os.name != "posix", reason="requires native POSIX mode and inode protection")
@pytest.mark.parametrize("kind", ["fifo", "key_symlink", "lock_symlink", "unsafe_parent"])
def test_native_posix_file_protection(fixture, kind):
    f = fixture
    if kind == "fifo":
        f["private"].unlink()
        os.mkfifo(f["private"], mode=0o600)
    elif kind == "key_symlink":
        alternate = f["root"] / "key-real.pem"
        f["private"].rename(alternate)
        f["private"].symlink_to(alternate)
    elif kind == "lock_symlink":
        lock = f["log"].path.with_name(f["log"].path.name + ".lock")
        lock.unlink()
        lock.symlink_to(f["public"])
    else:
        f["root"].chmod(0o777)
    try:
        with pytest.raises(a.AnchorError):
            export(f, "unsafe.json")
        assert not (f["root"] / "unsafe.json").exists()
    finally:
        f["root"].chmod(0o700)
