"""Import unchanged engine XCCDF in disposable development JSON/SQLite states.

The product directory must be a separately recorded Git archive. No live server,
shared profile, transport, model, scheduler or verified identity is used.
"""
import argparse
import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

TARGET = "ubi9-nginx-image-20261106"
X = "{http://checklists.nist.gov/xccdf/1.2}"


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def clean_environment(source, state, backend):
    env = {key: value for key, value in os.environ.items() if key.upper() in {
        "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP",
        "HOME", "USERPROFILE", "LOCALAPPDATA", "LANG", "LC_ALL"}}
    env.update({"PYTHONPATH": str(source), "PYTHONDONTWRITEBYTECODE": "1",
        "CT_STATE_DIR": str(state), "CT_STATE_BACKEND": backend, "CT_AUTH_MODE": "dev",
        "CT_SECURITY_MODE": "range", "CT_LLM_BACKEND": "template", "CT_AUTO_PROPOSE": "0",
        "CT_EXPLAIN_PRECOMPUTE": "0", "CT_SCAN_INTERVAL_SECONDS": "0",
        "CT_CONTENT_CHECK_INTERVAL_SECONDS": "0", "CT_CONTENT_CHECK_ON_RECONNECT": "0",
        "CT_CONTENT_AUTO_PULL": "0", "CT_BOOTSTRAP_CLUSTER_TARGET": "0", "CT_LINK_OFFLINE": "1",
        "CT_NODE": "container-scap-disposable-acceptance"})
    return env


def context(source, state, backend):
    env = clean_environment(source, state, backend)
    os.environ.clear()
    os.environ.update(env)
    sys.path.insert(0, str(source))
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext
    from cyberthunder.ingest import scap_results
    assert Path(scap_results.__file__).resolve().is_relative_to(source)
    ctx = AppContext(Settings.from_env())
    def blocked(*args, **kwargs):
        raise AssertionError("passive acceptance cannot invoke an external operation")
    for obj, names in [(ctx, ("transport_for", "adapter_for")), (ctx.scanner, ("start", "run")),
                       (ctx.engine, ("propose", "execute", "rollback")), (ctx.explain, ("precompute",))]:
        for name in names:
            setattr(obj, name, blocked)
    return ctx


def prepare(evidence):
    raw = (evidence / "image-xccdf.xml").read_bytes()
    scope = json.loads((evidence / "declared-scope.json").read_text())
    result = list(ET.fromstring(raw).iter(X + "TestResult"))
    assert len(result) == 1
    assert result[0].find(X + "profile").get("idref") == scope["profile_id"]
    engine = json.loads((evidence / "engine-state.json").read_text())
    version = (evidence / "scanner-version.txt").read_text().splitlines()[0].rsplit(" ", 1)[-1]
    image = (evidence / "target-image.txt").read_text()
    image_digest = json.loads(image[image.index("["):image.index("]") + 1])[0].split("@", 1)[1]
    manifest = {"source_id": "ubi9-nginx-sys-chroot-20261106", "target_id": TARGET,
        "test_result_id": result[0].get("id"), "benchmark_id": scope["benchmark_id"],
        "profile_id": scope["profile_id"], "expected_rule_ids": scope["expected_rule_ids"],
        "provenance": {"engine": "openscap", "engine_version": version, "mode": "rootfs",
            "image_ref": "registry.access.redhat.com/ubi9/nginx-124:1-1756913337",
            "image_digest": image_digest, "subject_ref": "/target", "exit_code": engine["ExitCode"],
            "platform": "UBI 9 copy; ownership and permissions not original; RHEL host applicability unverified"}}
    save(evidence / "manifest.json", manifest)
    return manifest


def initialize(source, evidence, backend):
    state = evidence / ("state-" + backend)
    state.mkdir()
    ctx = context(source, state, backend)
    from cyberthunder.inventory.targets import Target
    ctx.inventory.add(Target(TARGET, "Exported UBI nginx image (passive evidence)", "containers",
        transport="fixture", in_scope=False, environment="isolated-image-acceptance",
        notes="Development actor unverified; no live target connection; image metadata normalized"))
    ctx.inventory.save()
    save(evidence / (backend + "-inventory.json"), ctx.inventory.get(TARGET).to_dict())
    ctx.store.close()


def inspect(source, evidence, backend, phase):
    ctx = context(source, evidence / ("state-" + backend), backend)
    from fastapi.testclient import TestClient
    from cyberthunder.api.app import create_app
    # No lifespan context: no runtime tasks start, no TCP listener is opened.
    client = TestClient(create_app(ctx))
    result = {"backend": backend, "phase": phase, "pid": os.getpid(),
              "identity_verified": False, "auth_mode": "dev"}
    try:
        envelope = {"xml_base64": base64.b64encode((evidence / "image-xccdf.xml").read_bytes()).decode(),
                    "manifest": json.loads((evidence / "manifest.json").read_text())}
        # Exact-repeat API publication also exposes real-format errors if the CLI failed.
        response = client.post("/api/v1/ingest/scap-results", json=envelope, headers={"X-Actor": "Joshua Ott"})
        result["import_http_status"] = response.status_code
        result["import_response"] = response.json()
        urls = {"findings": "/findings?limit=5000", "commander": "/reports/commander?format=json",
                "poam": "/reports/poam.csv", "checklist": "/reports/checklist.cklb?host=" + TARGET}
        if response.status_code == 200:
            urls["scan"] = "/scans/" + response.json()["scan_id"]
        reads = {name: client.get("/api/v1" + url) for name, url in urls.items()}
        result["read_http_status"] = {name: response.status_code for name, response in reads.items()}
        findings = reads["findings"].json().get("findings", [])
        result["finding_count"] = len(findings)
        result["finding_status_counts"] = dict(Counter(f["status"] for f in findings))
        result["finding_raw_counts"] = dict(Counter(f["collection_provenance"]["raw_result"] for f in findings
            if "raw_result" in f.get("collection_provenance", {})))
        result["coverage_findings"] = [{"rule_id": f["rule_id"], "status": f["status"],
            "collection_provenance": f["collection_provenance"]} for f in findings
            if f.get("collection_provenance", {}).get("observation_kind") == "coverage"]
        observations = sorted([f.to_dict() for f in ctx.store.current_findings()], key=lambda f: f["id"])
        result["persisted_observations_sha256"] = digest(json.dumps(observations, sort_keys=True).encode())
        result["published_runs"] = len(ctx.store.list_scan_runs())
        for name in ("commander", "poam", "checklist"):
            (evidence / (backend + "-" + phase + "-" + name + ".txt")).write_bytes(reads[name].content)
        result["report_bytes_and_sha256"] = {name: {"bytes": len(reads[name].content),
            "sha256": digest(reads[name].content)} for name in ("commander", "poam", "checklist")}
        result["commander_mentions_unverified"] = "unverified" in reads["commander"].text.lower()
        result["checks"] = {"reads_succeeded": all(r.status_code == 200 for r in reads.values())}
        if response.status_code == 200:
            receipt = response.json()
            result["coverage_incomplete"] = reads["scan"].json()["coverage_incomplete"]
            result["checks"].update({"raw_counts_preserved": result["finding_raw_counts"] == receipt["result_counts"],
                "expected_finding_count": len(findings) == receipt["findings_count"],
                "xml_hash_matches": receipt["source_sha256"] == digest((evidence / "image-xccdf.xml").read_bytes()),
                "no_compliance_claim": receipt["compliance_claim"] is False,
                "unverified_platform": receipt["platform_applicability"] == "unverified",
                "one_published_run": result["published_runs"] == 1,
                "repeat_idempotent": receipt["repeated"] is True,
                "coverage_incomplete": result["coverage_incomplete"] is True})
        if phase == "restart":
            first = json.loads((evidence / (backend + "-first.json")).read_text())
            result["checks"]["restart_observations_equal"] = (
                result["persisted_observations_sha256"] == first["persisted_observations_sha256"])
            result["checks"]["restart_receipt_equal"] = result["import_response"] == first["import_response"]
        save(evidence / (backend + "-" + phase + ".json"), result)
        print(json.dumps({k: result[k] for k in ("backend", "phase", "import_http_status", "finding_count", "checks")}))
    finally:
        client.close()
        ctx.store.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--backend", choices=("json", "sqlite"))
    parser.add_argument("--phase", choices=("init", "first", "restart"))
    args = parser.parse_args()
    source, evidence = args.source.resolve(strict=True), args.evidence.resolve(strict=True)
    if args.phase:
        if args.phase == "init":
            initialize(source, evidence, args.backend)
        else:
            inspect(source, evidence, args.backend, args.phase)
        return
    prepare(evidence)
    overall = {"product_source": json.loads((evidence / "source-identity.json").read_text()), "backends": {}}
    for backend in ("json", "sqlite"):
        state = evidence / ("state-" + backend)
        env = clean_environment(source, state, backend)
        command = [sys.executable, str(Path(__file__).resolve()), str(source), str(evidence), "--backend", backend]
        subprocess.run([*command, "--phase", "init"], env=env, cwd=source, check=True, timeout=60)
        cli = [sys.executable, "-m", "cyberthunder.ingest.scap_cli", "--state-dir", str(state),
               "--actor", "Joshua Ott", str(evidence / "image-xccdf.xml"), "--manifest", str(evidence / "manifest.json")]
        completed = subprocess.run(cli, env=env, cwd=source, capture_output=True, timeout=120)
        (evidence / (backend + "-cli-stdout.txt")).write_bytes(completed.stdout)
        (evidence / (backend + "-cli-stderr.txt")).write_bytes(completed.stderr)
        save(evidence / (backend + "-cli.json"), {"arguments": cli, "exit_code": completed.returncode})
        for phase in ("first", "restart"):
            subprocess.run([*command, "--phase", phase], env=env, cwd=source, check=True, timeout=120)
        restart = json.loads((evidence / (backend + "-restart.json")).read_text())
        overall["backends"][backend] = {"cli_exit_code": completed.returncode,
            "api_import_status": restart["import_http_status"], "findings": restart["finding_count"],
            "accepted": completed.returncode == 0 and restart["import_http_status"] == 200 and all(restart["checks"].values())}
    save(evidence / "acceptance-summary.json", overall)
    print(json.dumps(overall, indent=2))


if __name__ == "__main__":
    main()
