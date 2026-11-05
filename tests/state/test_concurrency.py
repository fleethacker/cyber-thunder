"""Two API workers (uvicorn on two ports) and the CLI against one state directory at the same time.

For a few seconds they add targets, start scans, propose (through the scans' auto-propose) and decide
concurrently. Afterwards nothing may be lost: every target added is in the inventory as every process sees it,
every decision stands, every scan run is present and done, no finding has two live proposals, and the audit
chain verifies with a record for every change. The state_dir fixture runs it once per backend; the numbers it
prints are the ones quoted in docs/STATE.md and the pull request.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path

import httpx

from cyberthunder.audit.chain import AuditLog, verify_file
from cyberthunder.inventory.targets import Inventory
from cyberthunder.store import StateStore

API = "/api/v1"
ACTOR = "ITC Rivera"
PY = [sys.executable, "-m", "cyberthunder"]
LIVE = {"proposed", "approved"}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _cli(env: dict, state_dir: Path, *args: str, timeout: float = 180) -> str:
    r = subprocess.run([*PY, "--state-dir", str(state_dir), "--actor", ACTOR, *args], env=env,
                       capture_output=True, text=True, timeout=timeout)
    assert r.returncode == 0, f"cli {args}: rc={r.returncode}\n{r.stdout}\n{r.stderr}"
    return r.stdout


class Worker:
    """One `cyberthunder serve` process."""

    def __init__(self, env: dict, state_dir: Path, log_dir: Path, name: str):
        self.name = name
        self.port = _free_port()
        self.log_path = log_dir / f"{name}.log"
        self._log = open(self.log_path, "w", encoding="utf-8")
        self.proc = subprocess.Popen([*PY, "--state-dir", str(state_dir), "serve", "--host", "127.0.0.1",
                                      "--port", str(self.port)], env=env, stdout=self._log, stderr=subprocess.STDOUT)
        self.http = httpx.Client(base_url=f"http://127.0.0.1:{self.port}{API}", timeout=60)
        self.errors: list[tuple] = []

    def wait_ready(self, timeout: float = 120) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise AssertionError(f"{self.name} exited with {self.proc.returncode}:\n{self.log_text()}")
            try:
                if self.http.get("/status").status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
        raise AssertionError(f"{self.name} did not answer within {timeout}s:\n{self.log_text()}")

    def call(self, method: str, path: str, **kw) -> httpx.Response:
        r = self.http.request(method, path, headers={"X-Actor": ACTOR}, **kw)
        if r.status_code >= 500:
            self.errors.append((method, path, r.status_code, r.text[:300]))
        return r

    def wait_scan(self, scan_id: str, timeout: float = 180) -> dict:
        """The finished run. A run is saved as done before its after-scan step (auto-propose) runs and saves
        it again with `proposals_created`, so wait for that too."""
        deadline = time.monotonic() + timeout
        run = None
        while time.monotonic() < deadline:
            r = self.call("GET", f"/scans/{scan_id}")
            if r.status_code == 200:
                run = r.json()
                if run.get("status") not in ("pending", "running"):
                    summary = run.get("summary") or {}
                    if run.get("status") != "done" or any(k in summary for k in ("proposals_created", "auto_propose_error", "after_scan")):
                        return run
            time.sleep(0.3)
        raise AssertionError(f"scan {scan_id} did not finish within {timeout}s: {run}")

    def log_text(self) -> str:
        self._log.flush()
        return self.log_path.read_text(encoding="utf-8", errors="replace")[-4000:]

    def stop(self) -> None:
        self.http.close()
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(15)
        self._log.close()


def test_two_workers_and_the_cli_share_one_state(state_dir, tmp_path):
    backend = os.environ["CT_STATE_BACKEND"]
    env = {**os.environ, "CT_STATE_DIR": str(state_dir), "CT_STATE_BACKEND": backend,
           "CT_EXPLAIN_PRECOMPUTE": "0", "CT_LLM_BACKEND": "template", "PYTHONUNBUFFERED": "1"}
    env.pop("CT_KILL", None)
    loaded = _cli(env, state_dir, "demo", "load")
    linux = next(line.split()[0] for line in loaded.splitlines() if "(linux, simulated)" in line)

    a = Worker(env, state_dir, tmp_path, "worker-a")
    b = Worker(env, state_dir, tmp_path, "worker-b")
    try:
        a.wait_ready()
        b.wait_ready()
        # a first scan of every demo target gives findings and, through auto-propose, proposals to decide on
        first = a.call("POST", "/scans", json={})
        assert first.status_code == 202, first.text
        sid0 = first.json()["id"]
        assert a.wait_scan(sid0)["status"] == "done"
        proposals = b.call("GET", "/proposals").json()["proposals"]      # the other worker sees them
        pids = [p["id"] for p in proposals if p["state"] == "proposed"]
        assert len(pids) >= 9, proposals

        added: list[str] = []
        decided: dict[str, str] = {}
        scans: list[str] = []
        failures: list[str] = []
        guard = threading.Lock()

        def record(fn):
            def run():
                try:
                    fn()
                except Exception as e:  # noqa: BLE001  reported after the join
                    with guard:
                        failures.append(f"{fn.__name__}: {e!r}")
            return run

        def add_targets(w: Worker, tag: str, n: int):
            for i in range(n):
                tid = f"ct-{tag}-{i:02d}"
                r = w.call("POST", "/targets", json={"id": tid, "name": tid, "asset_type": "linux", "transport": "ssh",
                                                      "address": f"10.0.{len(tag)}.{i + 1}", "in_scope": False})
                assert r.status_code == 201, (tid, r.status_code, r.text)
                with guard:
                    added.append(tid)

        def decide(w: Worker, mine: list[str], action: str):
            for pid in mine:
                r = w.call("POST", f"/proposals/{pid}/{action}", json={"note": f"by {w.name}"})
                assert r.status_code == 200, (pid, action, r.status_code, r.text)
                with guard:
                    decided[pid] = r.json()["state"]

        def scan(w: Worker):
            r = w.call("POST", "/scans", json={"target_ids": [linux]})
            assert r.status_code == 202, r.text
            with guard:
                scans.append(r.json()["id"])

        def cli_adds(n: int):
            for i in range(n):
                tid = f"ct-cli-{i:02d}"
                _cli(env, state_dir, "targets", "add", "--id", tid, "--type", "linux", "--address", f"10.0.9.{i + 1}")
                with guard:
                    added.append(tid)

        def cli_decides(mine: list[str]):
            for pid in mine:
                _cli(env, state_dir, "proposals", "approve", pid)
                with guard:
                    decided[pid] = "approved"

        jobs = [
            lambda: add_targets(a, "a", 12), lambda: add_targets(b, "b", 12), lambda: cli_adds(3),
            lambda: decide(a, pids[0::3], "approve"), lambda: decide(b, pids[1::3], "deny"),
            lambda: cli_decides(pids[2::3][:3]),
            lambda: scan(a), lambda: scan(b),
        ]
        for j, name in zip(jobs, ["add_a", "add_b", "add_cli", "decide_a", "decide_b", "decide_cli", "scan_a", "scan_b"]):
            j.__name__ = name
        threads = [threading.Thread(target=record(j), name=j.__name__) for j in jobs]
        t0 = time.monotonic()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for sid in scans:
            assert a.wait_scan(sid)["status"] == "done"
        elapsed = time.monotonic() - t0

        assert not failures, failures
        assert not a.errors and not b.errors, (a.errors, b.errors)

        # inventory: every target added through either worker or the CLI is in the file and in both workers' views
        on_disk = {t.id for t in Inventory.load(state_dir / "targets.yaml").all()}
        assert set(added) <= on_disk, sorted(set(added) - on_disk)
        for w in (a, b):
            seen = {t["id"] for t in w.call("GET", "/targets").json()["targets"]}
            assert set(added) <= seen, (w.name, sorted(set(added) - seen))
        # decisions stand, and no finding ended up with two live proposals
        after = {p["id"]: p for p in a.call("GET", "/proposals").json()["proposals"]}
        for pid, state in decided.items():
            assert after[pid]["state"] == state, (pid, state, after[pid]["state"])
        live = Counter(p["finding_id"] for p in after.values() if p["state"] in LIVE)
        assert not [f for f, n in live.items() if n > 1]
        # the scans both workers ran are present and done, in the store and in both workers' views
        store = StateStore(state_dir)
        runs = {r["id"]: r for r in store.list_scan_runs()}
        for sid in [sid0, *scans]:
            assert runs[sid]["status"] == "done" and runs[sid]["findings_count"] > 0, runs.get(sid)
        for w in (a, b):
            assert {r["id"] for r in w.call("GET", "/scans").json()["scans"]} >= set(runs)
        # the audit chain is intact and carries every change
        v = verify_file(state_dir / "audit.jsonl")
        assert v.ok, str(v)
        actions = Counter(r["action"] for r in AuditLog(state_dir / "audit.jsonl").records())
        assert actions["inventory.add"] == len(added)
        assert actions["proposal.approved"] + actions["proposal.denied"] >= len(decided)
        assert actions["scan.finish"] == 1 + len(scans)
        documents = store.docs.count() if backend == "sqlite" else len(store.docs.documents())
        store.close()
        print(f"\nconcurrency[{backend}]: {elapsed:.1f}s concurrent phase, {len(added)} targets added "
              f"({len(added) - 3} over HTTP, 3 by CLI), {len(decided)} decisions, {1 + len(scans)} scans, "
              f"{len(after)} proposals, {documents} documents, {v.count} audit records, chain {v}")
    finally:
        a.stop()
        b.stop()
