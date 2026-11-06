"""Exercise the built UI against new simulated state; never reuse an operator inventory."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
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
    (output / "fixture.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
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
        parser.error("build the UI before running this rehearsal")
    output_root = ROOT / ".build" / "browser-rehearsals"
    output_root.mkdir(parents=True, exist_ok=True)
    run_root = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=output_root))
    backends = ("json", "sqlite") if args.backend == "both" else (args.backend,)
    results = []
    for backend in backends:
        for scenario in ("normal", "verification_failure"):
            output = run_root / f"{backend}-{scenario}"
            output.mkdir()
            with (output / "server.log").open("w", encoding="utf-8") as log:
                process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--serve", str(output),
                    "--backend", backend, "--scenario", scenario], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
                try:
                    wait_ready(process, output)
                    command = [args.node, str(ROOT / "scripts/browser_rehearsal.mjs"), str(output), args.playwright_module]
                    if args.browser:
                        command.append(args.browser)
                    result = subprocess.run(command, cwd=ROOT, timeout=180, check=False)
                    results.append({"backend": backend, "scenario": scenario, "exit_code": result.returncode,
                                    "evidence": str(output / "result.json")})
                    if result.returncode:
                        break
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
        if results and results[-1]["exit_code"]:
            break
    record = {"head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "finished_at": datetime.now(timezone.utc).isoformat(), "results": results,
              "passed": len(results) == len(backends) * 2 and all(item["exit_code"] == 0 for item in results),
              "limits": "Simulated Linux transport, template explanations, unverified loopback development identity; not real-host or live-identity acceptance."}
    (run_root / "summary.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": record["passed"], "summary": str(run_root / "summary.json")}))
    return 0 if record["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
