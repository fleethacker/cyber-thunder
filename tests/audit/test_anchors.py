"""Ephemeral keys, native file protection, detached signatures and process concurrency."""
import base64
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cyberthunder.audit import anchors as a
from cyberthunder.audit.chain import AuditLog, head_path, record_hash


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    def offline(*args, **kwargs):
        raise AssertionError("audit anchors must not contact external services")
    monkeypatch.setattr(socket, "getaddrinfo", offline)
    monkeypatch.setattr(socket.socket, "connect", offline)
    if os.name == "nt":
        from tests.windows_acl import register_root, set_dacl
        register_root(tmp_path)
        set_dacl(tmp_path)
    key = Ed25519PrivateKey.generate()  # Disposable test material only.
    private, public = tmp_path / "operator.pem", tmp_path / "operator.pub"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    private.chmod(0o600)
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    public.chmod(0o600)
    log = AuditLog(tmp_path / "audit.jsonl", node="fixture-node")
    log.append("fixture.start", "Operator", {"fraction": 0.25, "text": "caf\u00e9"})
    log.path.chmod(0o600)
    head_path(log.path).chmod(0o600)
    signer, trust = tmp_path / "signer.json", tmp_path / "trust.json"
    signer.write_text(json.dumps({"version": 1, "node": "fixture-node", "log_instance": "a" * 32,
        "log_path": str(log.path), "key_id": "operator", "private_key": str(private)}))
    trust.write_text(json.dumps({"version": 1, "streams": [{"node": "fixture-node", "log_instance": "a" * 32,
        "keys": {"operator": str(public)}}]}))
    signer.chmod(0o600)
    trust.chmod(0o600)
    return dict(root=tmp_path, key=key, private=private, public=public, log=log, signer=signer, trust=trust,
                store=tmp_path / "anchors.json")


def export(f, name="first.json", previous=None):
    path = f["root"] / name
    receipt = a.export_checkpoint(f["signer"], f["trust"], path, previous=previous)
    return path, receipt


def signed(f, checkpoint, name="adversarial.json"):
    signature = f["key"].sign(a.DOMAIN + a.canonical(checkpoint))
    path = f["root"] / name
    path.write_bytes(a.canonical({"checkpoint": checkpoint,
        "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode()}))
    path.chmod(0o600)
    return path


def test_real_detached_signature_roundtrip_and_receipts_do_not_claim_delivery(fixture):
    f = fixture
    path, receipt = export(f)
    doc = json.loads(path.read_bytes())
    signature = base64.urlsafe_b64decode(doc["signature"] + "==")
    f["key"].public_key().verify(signature, a.DOMAIN + a.canonical(doc["checkpoint"]))
    assert receipt["sequence"] == 1 and receipt["head_hash"] == f["log"].head
    assert receipt["log_verification"] == "complete_at_export"
    verified = a.verify_checkpoint(path, f["trust"])
    assert verified["checkpoint_id"] == receipt["checkpoint_id"]
    assert verified["log_verification"] == "not_performed"
    assert receipt["off_node_delivery"] == verified["off_node_delivery"] == "not_established"
    assert b"PRIVATE KEY" not in path.read_bytes()
    assert b"fraction" not in path.read_bytes() and b"Operator" not in path.read_bytes()
    assert a.check_log(f["log"].path, path, f["trust"])["log_sequence"] == 1


def test_monotonic_import_idempotence_restart_and_deleted_state(fixture):
    f = fixture
    first, one = export(f)
    a.initialize_store(f["store"], f["trust"])
    assert a.import_checkpoint(first, f["trust"], f["store"])["local_anchor_state"] == "advanced"
    before = f["store"].read_bytes()
    assert a.import_checkpoint(first, f["trust"], f["store"])["local_anchor_state"] == "unchanged"
    assert f["store"].read_bytes() == before
    f["log"].append("fixture.next", "Operator")
    second, two = export(f, "second.json", first)
    assert two["sequence"] == 2
    assert json.loads(second.read_bytes())["checkpoint"]["previous"]["checkpoint_id"] == one["checkpoint_id"]
    assert a.import_checkpoint(second, f["trust"], f["store"])["local_anchor_state"] == "advanced"
    before = f["store"].read_bytes()
    with pytest.raises(a.AnchorError, match="rollback"):
        a.import_checkpoint(first, f["trust"], f["store"])
    assert f["store"].read_bytes() == before
    with pytest.raises(a.AnchorError):
        a.initialize_store(f["store"], f["trust"])
    f["store"].unlink()
    with pytest.raises(a.AnchorError):
        a.import_checkpoint(second, f["trust"], f["store"])
    assert not f["store"].exists()


@pytest.mark.parametrize("fault", ["same_seq_fork", "missing_previous", "wrong_previous", "different_instance", "different_node"])
def test_valid_signature_cannot_bypass_receiver_continuity_or_scope(fixture, fault):
    f = fixture
    first, _ = export(f)
    a.initialize_store(f["store"], f["trust"])
    a.import_checkpoint(first, f["trust"], f["store"])
    before = f["store"].read_bytes()
    body = json.loads(first.read_bytes())["checkpoint"]
    if fault == "same_seq_fork":
        body["head_hash"] = "b" * 64
    elif fault in {"missing_previous", "wrong_previous"}:
        body["sequence"] += 1
        if fault == "wrong_previous":
            body["previous"] = {"sequence": 1, "head_hash": "c" * 64, "checkpoint_id": "d" * 64}
    elif fault == "different_instance":
        body["log_instance"] = "b" * 32
    else:
        body["node"] = "other-node"
    path = signed(f, body)
    with pytest.raises(a.AnchorError):
        a.import_checkpoint(path, f["trust"], f["store"])
    assert f["store"].read_bytes() == before


@pytest.mark.parametrize("fault", ["algorithm", "unknown", "boolean", "float", "signature", "kid", "duplicate", "depth", "oversize", "nonfinite"])
def test_malformed_or_confusing_bundle_fails_closed(fixture, fault):
    f = fixture
    path, _ = export(f)
    doc = json.loads(path.read_bytes())
    if fault == "algorithm":
        doc["checkpoint"]["algorithm"] = "none"
    elif fault == "unknown":
        doc["checkpoint"]["trusted"] = True
    elif fault in {"boolean", "float"}:
        doc["checkpoint"]["sequence"] = True if fault == "boolean" else 1.0
    elif fault == "signature":
        doc["signature"] = "A" * 86
    elif fault == "kid":
        doc["checkpoint"]["key_id"] = "unknown"
    raw = a.canonical(doc)
    if fault == "duplicate":
        raw = raw.replace(b'"sequence":1', b'"sequence":1,"sequence":1')
    elif fault == "depth":
        raw = b'{"a":' * 40 + b'0' + b'}' * 40
    elif fault == "oversize":
        raw += b" " * a.MAX_BUNDLE
    elif fault == "nonfinite":
        raw = raw.replace(b'"sequence":1', b'"sequence":NaN')
    path.write_bytes(raw)
    with pytest.raises(a.AnchorError):
        a.verify_checkpoint(path, f["trust"])


@pytest.mark.parametrize("fault", ["earlier_record", "head_missing", "head_behind", "duplicate", "node", "truncated_line", "unknown_record_version"])
def test_signing_checks_the_complete_chain_not_only_cached_tail(fixture, fault):
    f = fixture
    f["log"].append("fixture.second", "Operator")
    records = list(f["log"].records())
    if fault == "head_missing":
        head_path(f["log"].path).unlink()
    elif fault == "head_behind":
        head_path(f["log"].path).write_text(json.dumps({"seq": 1, "hash": records[0]["hash"], "ts": records[0]["ts"]}))
    elif fault == "duplicate":
        raw = f["log"].path.read_bytes().replace(b'"seq": 1', b'"seq": 1, "seq": 1')
        f["log"].path.write_bytes(raw)
    elif fault == "truncated_line":
        f["log"].path.write_bytes(f["log"].path.read_bytes().rstrip(b"\r\n"))
    else:
        if fault == "earlier_record":
            records[0]["actor"] = "changed"
        elif fault == "node":
            records[0]["node"] = "other"
        else:
            records[0]["v"] = 99
        if fault in {"node", "unknown_record_version"}:
            previous = "0" * 64
            for record in records:
                record["prev_hash"] = previous
                record["hash"] = previous = record_hash(record)
            head_path(f["log"].path).write_text(json.dumps({"seq": 2, "hash": previous, "ts": records[-1]["ts"]}))
        f["log"].path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    with pytest.raises(a.AnchorError):
        export(f, "refused.json")
    assert not (f["root"] / "refused.json").exists()


def test_previous_anchor_detects_a_rewritten_but_rehashed_prefix(fixture):
    f = fixture
    first, _ = export(f)
    f["log"].append("fixture.next", "Operator")
    records = list(f["log"].records())
    records[0]["details"] = {"changed": True}
    previous = "0" * 64
    for record in records:
        record["prev_hash"] = previous
        record["hash"] = previous = record_hash(record)
    f["log"].path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    head_path(f["log"].path).write_text(json.dumps({"seq": 2, "hash": previous, "ts": records[-1]["ts"]}))
    assert f["log"].verify().ok  # Local unsigned head alone cannot detect this rewrite.
    with pytest.raises(a.AnchorError):
        a.check_log(f["log"].path, first, f["trust"])
    with pytest.raises(a.AnchorError):
        export(f, "fork.json", first)


def test_revoked_key_and_changed_trust_have_no_last_good_fallback(fixture):
    f = fixture
    path, _ = export(f)
    assert a.verify_checkpoint(path, f["trust"])
    other = Ed25519PrivateKey.generate()
    f["public"].write_bytes(other.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    with pytest.raises(a.AnchorError):
        a.verify_checkpoint(path, f["trust"])
    with pytest.raises(a.AnchorError):
        export(f, "wrong-key.json")
    f["trust"].write_text("{}")
    with pytest.raises(a.AnchorError):
        a.verify_checkpoint(path, f["trust"])


def test_cli_errors_are_safe_and_existing_outputs_are_never_overwritten(fixture, capsys):
    f = fixture
    path, _ = export(f)
    original = path.read_bytes()
    assert a.main(["export", "--signer", str(f["signer"]), "--trust", str(f["trust"]), "--out", str(path)]) == 2
    captured = capsys.readouterr()
    assert not captured.out and str(f["root"]) not in captured.err and "PRIVATE KEY" not in captured.err
    assert path.read_bytes() == original
    assert a.main(["verify", "--trust", str(f["trust"]), "--bundle", str(path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["off_node_delivery"] == "not_established"


def test_private_and_public_file_protection_is_enforced(fixture):
    f = fixture
    first, _ = export(f)
    if os.name == "nt":
        from tests.windows_acl import set_dacl, protected_aces
        set_dacl(f["private"], protected_aces() + "(A;;GR;;;S-1-1-0)")
    else:
        f["private"].chmod(0o644)
    with pytest.raises(a.AnchorError):
        export(f, "unsafe-private.json")
    if os.name == "nt":
        set_dacl(f["private"])
        set_dacl(f["public"], protected_aces() + "(A;;GW;;;S-1-1-0)")
    else:
        f["private"].chmod(0o600)
        f["public"].chmod(0o666)
    with pytest.raises(a.AnchorError):
        a.verify_checkpoint(first, f["trust"])


def test_key_hardlinks_fail_closed(fixture):
    f = fixture
    link = f["root"] / "key-link"
    os.link(f["private"], link)
    with pytest.raises(a.AnchorError):
        export(f, "hardlink.json")


def process_env():
    env = {k: v for k, v in os.environ.items() if not k.startswith("CT_")}
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2])
    return env


def test_append_process_and_export_share_the_same_writer_lock(fixture):
    f = fixture
    script = ("import sys,time; from cyberthunder.audit.chain import AuditLog; "
              "log=AuditLog(sys.argv[1],node='fixture-node'); "
              "[(log.append('parallel','Operator',{'i':i}),time.sleep(.01)) for i in range(24)]")
    child = subprocess.Popen([sys.executable, "-c", script, str(f["log"].path)], env=process_env(),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        paths = [export(f, f"concurrent-{i}.json")[0] for i in range(4)]
        stdout, stderr = child.communicate(timeout=30)
        assert child.returncode == 0, stderr.decode()
        assert not stdout and f["log"].verify().ok
        assert f["log"].verify().count == 25
        for path in paths:
            assert a.check_log(f["log"].path, path, f["trust"])["log_sequence"] == 25
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate()


def test_concurrent_process_imports_cannot_both_accept_distinct_forks(fixture):
    f = fixture
    first, _ = export(f)
    a.initialize_store(f["store"], f["trust"])
    a.import_checkpoint(first, f["trust"], f["store"])
    f["log"].append("fixture.next", "Operator")
    second, _ = export(f, "second.json", first)
    other = deepcopy(json.loads(second.read_bytes())["checkpoint"])
    other["head_hash"] = "e" * 64
    fork = signed(f, other)
    def run(path):
        return subprocess.run([sys.executable, "-m", "cyberthunder.audit.anchors", "import", "--bundle", str(path),
            "--trust", str(f["trust"]), "--store", str(f["store"])], env=process_env(), capture_output=True, timeout=30)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, [second, fork]))
    assert sorted(result.returncode for result in results) == [0, 2]
    saved = json.loads(f["store"].read_bytes())["anchors"]
    assert len(saved) == 1 and saved[0]["checkpoint"]["sequence"] == 2
    assert all("PRIVATE KEY" not in result.stderr.decode() for result in results)


@pytest.mark.parametrize("fault", ["duplicate", "duplicate_stream", "malformed", "signature", "unknown"])
def test_invalid_receiver_state_never_silently_resets(fixture, fault):
    f = fixture
    first, _ = export(f)
    a.initialize_store(f["store"], f["trust"])
    a.import_checkpoint(first, f["trust"], f["store"])
    state = json.loads(f["store"].read_bytes())
    if fault == "duplicate_stream":
        state["anchors"].append(deepcopy(state["anchors"][0]))
    elif fault == "signature":
        state["anchors"][0]["signature"] = "A" * 86
    elif fault == "unknown":
        state["reset"] = True
    raw = a.canonical(state)
    if fault == "duplicate":
        raw = raw[:-1] + b',"anchors":[]}'
    elif fault == "malformed":
        raw = b"{"
    f["store"].write_bytes(raw)
    with pytest.raises(a.AnchorError):
        a.import_checkpoint(first, f["trust"], f["store"])
    assert f["store"].read_bytes() == raw


@pytest.mark.parametrize("fault", ["unknown", "boolean", "float", "algorithm", "genesis", "previous"])
def test_a_valid_signature_does_not_authorize_invalid_schema(fixture, fault):
    f = fixture
    first, _ = export(f)
    body = json.loads(first.read_bytes())["checkpoint"]
    if fault == "unknown":
        body["other"] = "allowed?"
    elif fault == "boolean":
        body["sequence"] = True
    elif fault == "float":
        body["sequence"] = 1.0
    elif fault == "algorithm":
        body["algorithm"] = "ed25519"
    elif fault == "genesis":
        body["head_hash"] = "0" * 64
    else:
        body["previous"] = {"sequence": 1, "head_hash": body["head_hash"], "checkpoint_id": "f" * 64}
    with pytest.raises(a.AnchorError):
        a.verify_checkpoint(signed(f, body), f["trust"])


def test_other_signature_domain_is_refused(fixture):
    f = fixture
    first, _ = export(f)
    doc = json.loads(first.read_bytes())
    signature = f["key"].sign(a.canonical(doc["checkpoint"]))
    doc["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    first.write_bytes(a.canonical(doc))
    with pytest.raises(a.AnchorError):
        a.verify_checkpoint(first, f["trust"])


def test_key_rotation_preserves_exact_predecessor_and_new_key_survives_restart(fixture):
    f = fixture
    first, _ = export(f)
    a.initialize_store(f["store"], f["trust"])
    a.import_checkpoint(first, f["trust"], f["store"])
    next_key = Ed25519PrivateKey.generate()
    next_private, next_public = f["root"] / "next.pem", f["root"] / "next.pub"
    next_private.write_bytes(next_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    next_public.write_bytes(next_key.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    next_private.chmod(0o600)
    next_public.chmod(0o600)
    trust = json.loads(f["trust"].read_bytes())
    trust["streams"][0]["keys"]["next"] = str(next_public)
    f["trust"].write_text(json.dumps(trust))
    config = json.loads(f["signer"].read_bytes())
    config.update(key_id="next", private_key=str(next_private))
    f["signer"].write_text(json.dumps(config))
    f["log"].append("rotation", "Operator")
    second, _ = export(f, "rotated.json", first)
    assert a.import_checkpoint(second, f["trust"], f["store"])["local_anchor_state"] == "advanced"
    del trust["streams"][0]["keys"]["operator"]
    f["trust"].write_text(json.dumps(trust))
    assert a.import_checkpoint(second, f["trust"], f["store"])["local_anchor_state"] == "unchanged"
    with pytest.raises(a.AnchorError):
        a.verify_checkpoint(first, f["trust"])


@pytest.mark.parametrize("operation", ["export", "import"])
def test_trust_revocation_during_validation_prevents_publication(fixture, monkeypatch, operation):
    f = fixture
    first, _ = export(f)
    a.initialize_store(f["store"], f["trust"])
    before = f["store"].read_bytes()
    original = a._verify
    def revoke(*args):
        result = original(*args)
        f["trust"].write_text("{}")
        return result
    monkeypatch.setattr(a, "_verify", revoke)
    with pytest.raises(a.AnchorError):
        if operation == "export":
            export(f, "refused.json")
        else:
            a.import_checkpoint(first, f["trust"], f["store"])
    assert not (f["root"] / "refused.json").exists()
    assert f["store"].read_bytes() == before


def test_failed_atomic_state_replace_preserves_previous_anchor(fixture, monkeypatch):
    f = fixture
    first, _ = export(f)
    a.initialize_store(f["store"], f["trust"])
    a.import_checkpoint(first, f["trust"], f["store"])
    f["log"].append("next", "Operator")
    second, _ = export(f, "second.json", first)
    before = f["store"].read_bytes()
    def failed(*args):
        raise OSError("PRIVATE FIXTURE PATH MUST NOT APPEAR")
    monkeypatch.setattr(a.files.os, "replace", failed)
    with pytest.raises(a.AnchorError) as exc:
        a.import_checkpoint(second, f["trust"], f["store"])
    assert "PRIVATE FIXTURE" not in str(exc.value)
    assert f["store"].read_bytes() == before
    assert not list(f["root"].glob(".audit-anchor-*"))


def test_symlink_or_windows_reparse_parent_is_refused(fixture):
    f = fixture
    alias = f["root"] / "alias"
    if os.name == "nt":
        import _winapi
        _winapi.CreateJunction(str(f["root"]), str(alias))
    else:
        alias.symlink_to(f["root"], target_is_directory=True)
    config = json.loads(f["signer"].read_bytes())
    config["private_key"] = str(alias / f["private"].name)
    f["signer"].write_text(json.dumps(config))
    try:
        with pytest.raises(a.AnchorError):
            export(f, "reparse.json")
    finally:
        if os.name == "nt":
            alias.rmdir()
        else:
            alias.unlink()


@pytest.mark.parametrize("bound", ["MAX_LOG", "MAX_RECORD", "MAX_RECORDS"])
def test_signing_bounds_fail_without_output(fixture, monkeypatch, bound):
    f = fixture
    monkeypatch.setattr(a, bound, 0 if bound == "MAX_RECORDS" else 1)
    with pytest.raises(a.AnchorError):
        export(f, "bounded.json")
    assert not (f["root"] / "bounded.json").exists()


def test_export_waits_until_another_process_finishes_the_locked_head(fixture, monkeypatch):
    f = fixture
    script = """
import json, sys, time
from pathlib import Path
from cyberthunder.audit.chain import file_lock, head_path
path, ready, release = map(Path, sys.argv[1:])
with file_lock(path.with_name(path.name + '.lock')):
    head = head_path(path)
    saved = head.read_bytes()
    head.write_bytes(b'{}')
    ready.touch()
    deadline = time.monotonic() + 10
    while not release.exists():
        if time.monotonic() > deadline:
            raise RuntimeError('test release deadline')
        time.sleep(.01)
    head.write_bytes(saved)
"""
    ready, release = f["root"] / "ready", f["root"] / "release"
    child = subprocess.Popen([sys.executable, "-c", script, str(f["log"].path), str(ready), str(release)],
        env=process_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while not ready.exists():
            assert time.monotonic() < deadline and child.poll() is None
            time.sleep(.01)
        # Observe the actual lock attempt before releasing the other process.
        from threading import Event
        attempting = Event()
        original = a.files.file_lock
        def observed(path):
            attempting.set()
            return original(path)
        monkeypatch.setattr(a.files, "file_lock", observed)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(export, f, "locked.json")
            try:
                assert attempting.wait(5)
                time.sleep(.05)
                assert not pending.done()
                assert not (f["root"] / "locked.json").exists()
            finally:
                release.touch()
            path, receipt = pending.result(timeout=15)
        stdout, stderr = child.communicate(timeout=15)
        assert child.returncode == 0, stderr.decode()
        assert not stdout and receipt["sequence"] == 1
        assert a.check_log(f["log"].path, path, f["trust"])
    finally:
        release.touch()
        if child.poll() is None:
            child.kill()
            child.communicate()


def test_argument_errors_never_echo_values(capsys):
    with pytest.raises(SystemExit) as exc:
        a.main(["unexpected-private-value"])
    assert exc.value.code == 2
    assert "unexpected-private-value" not in capsys.readouterr().err


def test_verified_principal_events_remain_hash_covered_without_exporting_details(fixture):
    from cyberthunder.control.principal import Principal, principal_scope
    f = fixture
    principal = Principal("https://identity.example.test", "fixture-subject", "Operator",
        roles=("auditor",), session_id="private-session-fixture", expires_at=time.time() + 600)
    with principal_scope(principal):
        f["log"].append("verified.event", principal.actor, {"secret_fixture": "not for checkpoint"})
    record = list(f["log"].records())[-1]
    assert record["v"] == 2 and record["principal"]["sub"] == "fixture-subject"
    path, receipt = export(f)
    assert receipt["sequence"] == 2 and a.check_log(f["log"].path, path, f["trust"])
    raw = path.read_bytes()
    assert b"private-session-fixture" not in raw and b"fixture-subject" not in raw and b"secret_fixture" not in raw


def test_explicit_empty_log_can_anchor_genesis_and_advance(fixture):
    f = fixture
    f["log"].path.write_bytes(b"")
    head_path(f["log"].path).unlink()
    first, receipt = export(f)
    assert receipt["sequence"] == 0 and receipt["head_hash"] == "0" * 64
    a.initialize_store(f["store"], f["trust"])
    a.import_checkpoint(first, f["trust"], f["store"])
    f["log"].append("first", "Operator")
    second, _ = export(f, "after-genesis.json", first)
    assert a.import_checkpoint(second, f["trust"], f["store"])["sequence"] == 1
