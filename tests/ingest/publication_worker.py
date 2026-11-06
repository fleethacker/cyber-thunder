"""Subprocess fixture for local publication races and abrupt termination."""
import json
import os
from pathlib import Path
import socket
import sys
import tempfile

from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.control.access import AccessPolicy
from cyberthunder.control.principal import Principal, principal_scope
from cyberthunder.ingest.content import publication as pub, signatures as sig, uploads
from tests.ingest.test_content_publication import candidate
import hashlib


def main():
    control = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    state = Path(control["state"])
    def forbidden(*args, **kwargs):
        raise AssertionError("Subprocess fixture cannot use the network")
    socket.socket.connect = forbidden
    socket.socket.connect_ex = forbidden
    ctx = AppContext(Settings(state_dir=state, state_backend=control["backend"], auth_mode="dev",
                               llm_backend="template", explain_precompute=False, bootstrap_cluster_target=False))
    ctx.settings.auth_mode = "oidc"
    ctx.settings.step_up_acr_values = ("urn:ct:test:strong",)
    ctx.access = AccessPolicy(state / "auth/access.json")
    ctx.content_signature_config = sig.ContentSignatureConfig(**control["signature"])
    human = Principal(**control["principal"])
    phase = sys.argv[3]
    def checkpoint(at):
        if at == phase:
            os._exit(73)
    pub.checkpoint = checkpoint
    try:
        with tempfile.TemporaryDirectory(dir=state, prefix="worker-") as temporary:
            path, entry = candidate(Path(temporary), int(sys.argv[2]))
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
            row = {"filename": path.name, "disk_name": path.name, "url": "https://dl.dod.cyber.mil/fixture",
                   "kind": entry.kind, "product_key": entry.product_key, "version": list(entry.version),
                   "version_label": entry.version_label, "sha256": sha, "bytes": path.stat().st_size}
            envelope = sig.sign_document({"files": [row]}, "lock", ctx.content_signature_config)
            _, evidence = sig.verify_document(sig.canonical(envelope), "lock", ctx.content_signature_config)
            mode = sys.argv[4]
            with principal_scope(human), sig.receipt(ctx, human.actor, [(sha, row["bytes"])], evidence):
                if mode == "direct":
                    result = ctx.ingest.ingest_stig(path, actor=human.actor)
                elif mode == "upload":
                    result = uploads.import_content(ctx.ingest.content, path.read_bytes(), path.name, human.actor)["record"]
                else:
                    sig.atomic_document(path.parent / "manifest.lock.json", envelope)
                    result = ctx.ingest.content.import_dir(path.parent, human.actor)["imported"][0]
            print(json.dumps({"generation": result["generation"], "status": result["commit_status"]}))
    except pub.PublicationReviewRequired:
        print(json.dumps({"status": "review_required"}))
    finally:
        ctx.store.close()


if __name__ == "__main__":
    main()
