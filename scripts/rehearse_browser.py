"""Exercise the built UI against new simulated state; never reuse an operator inventory."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LIMITS = ("Simulated Linux transport, template explanations, unverified loopback development identity; "
          "not verified-realm acceptance, official risk authorization, or target privilege proof. "
          "Backend security fixtures remain separate.")


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


def block_external_network(event: str, arguments: tuple) -> None:
    # Process-local guard: even an accidental provider/transport call cannot leave loopback.
    if event == "socket.connect":
        address = arguments[1]
        if not isinstance(address, tuple) or address[0] not in ("127.0.0.1", "::1"):
            raise PermissionError("browser fixture blocks non-loopback connections")
    elif event == "socket.getaddrinfo" and arguments[0] not in ("127.0.0.1", "::1", "localhost"):
        raise PermissionError("browser fixture blocks external name resolution")
    elif event == "socket.sendto":
        raise PermissionError("browser fixture blocks outbound datagrams")


def serve_fixture(output: Path, backend: str, scenario: str) -> None:
    output = output.resolve()
    if not output.is_relative_to((ROOT / ".build/browser-rehearsals").resolve()):
        raise ValueError("fixture state must remain inside this checkout's browser-rehearsals directory")
    if not output.is_dir() or any(path.name != "server.log" for path in output.iterdir()):
        raise ValueError("fixture output must be a new directory; existing state is never reused")
    # Ambient deployment settings must not select a model, inventory, scheduler or credential.
    for name in list(os.environ):
        if name.startswith("CT_"):
            del os.environ[name]
    sys.addaudithook(block_external_network)
    sys.path.insert(0, str(ROOT))
    import uvicorn
    from cyberthunder import demo
    from cyberthunder.api.app import create_app
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext

    settings = Settings(state_dir=output / "state", state_backend=backend, auth_mode="dev",
        security_mode="range", host="127.0.0.1", llm_backend="template", explain_precompute=False,
        auto_propose=True, scan_interval_s=0, content_check_interval_s=0,
        bootstrap_cluster_target=False, content_check_on_reconnect=False, content_auto_pull=False,
        link_offline=True, vulnerability_poll_s=0)
    ctx = AppContext(settings)
    targets = demo.load(ctx, "Browser rehearsal")
    if not targets or not all(target.simulated for target in targets):
        raise RuntimeError("rehearsal inventory must contain only simulated targets")
    original = ctx.transport_for

    def simulated_only(target):
        if target.simulated is not True or target.transport != "simulated":
            raise PermissionError("browser rehearsal permits simulated transports only")
        return original(target)

    ctx.transport_for = simulated_only
    linux = next(target for target in targets if target.asset_type == "linux")
    run = ctx.scanner.start([linux.id], requested_by="Browser rehearsal", trigger="demo", background=False)
    finding = next(item for item in ctx.store.load_findings() if item.rule_id == "RHEL-09-232270")
    proposal = next(item for item in ctx.gate.list() if item.finding_id == finding.id)
    if scenario == "verification_failure":
        demo.set_simulate_verify_fail_next(ctx, True, actor="Browser rehearsal")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    manifest = {"port": port, "backend": backend, "scenario": scenario, "scan": run.id,
                "target": linux.id, "proposal": proposal.id, "finding": finding.id,
                "simulated_only": True, "model_backend": "template"}
    write_json(output / "fixture.json", manifest)
    # Log to the parent's file. An unread process pipe must never stall request handling.
    config = uvicorn.Config(create_app(ctx), host="127.0.0.1", port=port, log_level="warning",
                            access_log=False, proxy_headers=False)
    try:
        uvicorn.Server(config).run(sockets=[listener])
    finally:
        listener.close()


def wait_ready(process, output: Path) -> None:
    deadline = time.monotonic() + 45
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("fixture exited; inspect server.log")
        try:
            fixture = json.loads((output / "fixture.json").read_text(encoding="utf-8"))
            with opener.open(f"http://127.0.0.1:{fixture['port']}/auth/status", timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    raise TimeoutError("fixture did not become ready within 45 seconds")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("json", "sqlite", "both"), default="both")
    parser.add_argument("--node", default="node", help="Node.js executable")
    parser.add_argument("--playwright-module", default=os.getenv("CT_PLAYWRIGHT_MODULE", "playwright"),
                        help="Installed Playwright module name or local module URL/path")
    parser.add_argument("--browser", default=os.getenv("CT_PERMISSION_BROWSER"), help="Chromium executable")
    parser.add_argument("--serve", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--scenario", choices=("normal", "verification_failure"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.serve:
        if args.backend == "both" or not args.scenario:
            parser.error("a fixture requires one backend and scenario")
        serve_fixture(args.serve, args.backend, args.scenario)
        return 0
    if not (ROOT / "cyberthunder/ui/dist/index.html").is_file():
        parser.error("the prepared UI build is missing; supply it before running this rehearsal")
    def git(*arguments: str) -> str:
        return subprocess.check_output(["git", *arguments], cwd=ROOT, text=True).strip()

    tested_head = git("rev-parse", "HEAD")
    if git("status", "--porcelain", "--untracked-files=no"):
        parser.error("commit tracked source and UI changes before recording a rehearsal")
    source_files = ["scripts/browser_rehearsal.mjs", "scripts/rehearse_browser.py"]
    build_files = git("ls-files", "cyberthunder/ui/dist").splitlines()
    def source_hashes() -> dict:
        return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                for name in source_files + build_files}

    hashes = source_hashes()
    output_root = ROOT / ".build" / "browser-rehearsals"
    output_root.mkdir(parents=True, exist_ok=True)
    run_root = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=output_root))
    receipts = run_root / "receipts"
    receipts.mkdir()
    private = run_root / "private"
    private.mkdir()
    backends = ("json", "sqlite") if args.backend == "both" else (args.backend,)
    results = []
    for backend in backends:
        for scenario in ("normal", "verification_failure"):
            name = f"{backend}-{scenario}"
            output = private / name
            output.mkdir()
            evidence = receipts / name
            evidence.mkdir()
            item = {"backend": backend, "scenario": scenario, "exit_code": 1,
                    "evidence": f"{name}/result.json", "fixture_stopped": False}
            results.append(item)
            with (output / "server.log").open("w", encoding="utf-8") as log:
                process = None
                try:
                    process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--serve", str(output),
                        "--backend", backend, "--scenario", scenario], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
                    wait_ready(process, output)
                    command = [args.node, str(ROOT / "scripts/browser_rehearsal.mjs"), str(output),
                               args.playwright_module, args.browser or "", str(evidence)]
                    result = subprocess.run(command, cwd=ROOT, timeout=300, check=False)
                    item["exit_code"] = result.returncode
                    browser_result = json.loads((evidence / "result.json").read_text(encoding="utf-8"))
                    if not browser_result.get("passed"):
                        item["exit_code"] = result.returncode or 1
                except Exception as exc:
                    # Keep detailed startup logs private; publish enough to locate a failed stage.
                    item["exit_code"] = 1
                    item["runner_failure"] = type(exc).__name__
                    if not (evidence / "result.json").exists():
                        write_json(evidence / "result.json", {"backend": backend, "scenario": scenario,
                            "passed": False, "phase": "fixture_or_browser_runner", "failure": type(exc).__name__,
                            "diagnosis": "Inspect the corresponding private server.log; browser did not produce a receipt."})
                finally:
                    if process is not None:
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
                        item["fixture_stopped"] = process.poll() is not None
    end_head = git("rev-parse", "HEAD")
    source_unchanged = end_head == tested_head and not git("status", "--porcelain", "--untracked-files=no")
    artifacts_unchanged = hashes == source_hashes()
    record = {"head": tested_head, "end_head": end_head, "source_unchanged": source_unchanged,
              "artifacts_unchanged": artifacts_unchanged, "source_sha256": hashes,
              "runtime": {"python": sys.version.split()[0], "node": args.node,
                          "playwright_module": args.playwright_module, "browser": args.browser},
              "finished_at": datetime.now(timezone.utc).isoformat(), "results": results,
              "passed": source_unchanged and artifacts_unchanged and len(results) == len(backends) * 2
                        and all(item["exit_code"] == 0 and item["fixture_stopped"] for item in results),
              "limits": LIMITS}
    write_json(receipts / "summary.json", record)
    write_json(receipts / "SHA256SUMS.json", {path.relative_to(receipts).as_posix():
        hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(receipts.rglob("*")) if path.is_file()})
    print(json.dumps({"passed": record["passed"], "summary": str(receipts / "summary.json")}))
    return 0 if record["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
