"""A stateful fake Linux host for engine and scanner tests.

FakeTransport holds the host's files and services in memory and understands a handful of fixed commands,
so an applied fix really changes state, verify really re-checks it and rollback really restores it.
Nothing here touches the network or the machine running the tests.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

from cyberthunder.adapters.base import Adapter, AssetFacts, Collected, make_finding
from cyberthunder.remediation import snapshot
from cyberthunder.remediation.library import FixEntry
from cyberthunder.remediation.models import (ApplyResult, BeforeState, HealthCheck, HealthResult, RollbackResult,
                                             VerifyResult)
from cyberthunder.transport.base import CommandResult, Transport, TransportError

SEED = Path(__file__).resolve().parent.parent / "fixtures" / "engine" / "seed_host.json"

SSHD = "/etc/ssh/sshd_config"
LOGIN_DEFS = "/etc/login.defs"
CRON_BACKDOOR = "/etc/cron.d/0hourly-sync"

RULE_ROOT_LOGIN = "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
STIG_ROOT_LOGIN = "RHEL-09-255045"
RULE_PASS_MAX = "xccdf_org.ssgproject.content_rule_accounts_maximum_age_login_defs"
CMD_ROOT_LOGIN = "fake-sshd-set PermitRootLogin no"
CMD_PASS_MAX = "fake-login-defs-set PASS_MAX_DAYS 60"

# id -> host state; reset by the test fixture so every test starts from the seed
HOSTS: dict[str, dict] = {}


def seed_state() -> dict:
    return json.loads(SEED.read_text(encoding="utf-8"))


def reset_hosts(*ids: str) -> None:
    HOSTS.clear()
    for i in ids:
        HOSTS[i] = seed_state()


def _set_line(text: str, key: str, value: str) -> str:
    out, done = [], False
    for line in text.splitlines():
        if line.split(" ", 1)[0] == key:
            out.append(f"{key} {value}")
            done = True
        else:
            out.append(line)
    if not done:
        out.append(f"{key} {value}")
    return "\n".join(out) + "\n"


class FakeTransport(Transport):
    kind = "simulated"

    def __init__(self, state: dict):
        self.state = state
        self.calls: list[str] = []
        self.closed = False

    def run(self, command: str, *, timeout: int = 120, sudo: bool = False) -> CommandResult:
        self.calls.append(command)
        lines = [ln for ln in command.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
        if len(lines) == 1:
            command = lines[0]                   # a script whose other lines are comments runs its one command
        files = self.state["files"]
        if command == "fake-dump":
            return CommandResult(command, 0, json.dumps(self.state))
        if command == CMD_ROOT_LOGIN:
            files[SSHD] = _set_line(files[SSHD], "PermitRootLogin", "no")
            return CommandResult(command, 0, "PermitRootLogin set to no")
        if command == CMD_PASS_MAX:
            files[LOGIN_DEFS] = _set_line(files[LOGIN_DEFS], "PASS_MAX_DAYS", "60")
            return CommandResult(command, 0, "PASS_MAX_DAYS set to 60")
        if command == "fake-break-sshd":
            files[SSHD] = files[SSHD] + "Garbage\n"
            self.state["services"]["sshd"] = "failed"
            return CommandResult(command, 1, "", "sshd failed to restart")
        return CommandResult(command, 127, "", f"unknown command {command!r}")

    def read_file(self, path: str) -> bytes:
        try:
            return self.state["files"][path].encode("utf-8")
        except KeyError:
            raise TransportError(f"no such file {path}") from None

    def write_file(self, path: str, data: bytes, *, mode: int | None = None, sudo: bool = False) -> None:
        self.state["files"][path] = data.decode("utf-8")

    def close(self) -> None:
        self.closed = True


class FakeLinuxAdapter(Adapter):
    asset_type = "linux"
    display_name = "Fake Linux (tests)"
    transports = ()
    own_transports = ("simulated",)

    def __init__(self):
        self.raise_on_apply: str | None = None
        self.fail_transport: bool = False
        self.transports_made: list[FakeTransport] = []

    # -- discovery / collection ---------------------------------------------------------
    def make_transport(self, target, settings=None):
        if self.fail_transport:
            raise TransportError("host unreachable")
        if target.id not in HOSTS:
            raise TransportError(f"no fake host {target.id}")
        t = FakeTransport(HOSTS[target.id])
        self.transports_made.append(t)
        return t

    def discover(self, target, transport) -> AssetFacts:
        return AssetFacts(hostname=target.id, os_name="Rocky Linux", os_version="9.4")

    def collect(self, target, transport, workdir: Path, *, modules=("check", "hunt", "cve"), rule_filter=None) -> Collected:
        state = json.loads(transport.check_output("fake-dump"))
        dump = Path(workdir) / "state.json"
        dump.write_text(json.dumps(state, indent=2), encoding="utf-8")
        return Collected(target_id=target.id, asset_type=self.asset_type, workdir=str(workdir),
                         artifacts={"state": str(dump)}, raw={"files": state["files"]},
                         modules=list(modules), rule_filter=rule_filter)

    # -- detection ----------------------------------------------------------------------
    @staticmethod
    def _value(text: str, key: str) -> str | None:
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == key:
                return parts[1]
        return None

    def _findings(self, target, files: dict) -> list:
        out = []
        root = self._value(files.get(SSHD, ""), "PermitRootLogin")
        out.append(make_finding(
            target=target, source="openscap", rule_id=RULE_ROOT_LOGIN, rule_version=STIG_ROOT_LOGIN,
            title="Disable SSH root login", severity="medium", status="open" if root != "no" else "not_a_finding",
            evidence=f"PermitRootLogin {root}", references=[STIG_ROOT_LOGIN]))
        max_days = self._value(files.get(LOGIN_DEFS, ""), "PASS_MAX_DAYS")
        ok = max_days is not None and int(max_days) <= 60
        f = make_finding(
            target=target, source="openscap", rule_id=RULE_PASS_MAX, title="Set password maximum age",
            severity="medium", status="not_a_finding" if ok else "open", evidence=f"PASS_MAX_DAYS {max_days}",
            description="Cited by CCI only in this test fixture.", references=["CCI-000199"])
        f.fix_script = f"# set PASS_MAX_DAYS in {LOGIN_DEFS}\n{CMD_PASS_MAX}"
        out.append(f)
        return out

    def check(self, target, collected):
        return self._findings(target, collected.raw["files"])

    def hunt(self, target, collected):
        if CRON_BACKDOOR in collected.raw["files"]:
            return [make_finding(target=target, source="hunt", rule_id="hunt:linux:cron_persistence",
                                 title="Unexpected cron job", severity="high", references=["T1053.003"],
                                 evidence=CRON_BACKDOOR)]
        return []

    # -- remediation --------------------------------------------------------------------
    def fixes(self):
        return [FixEntry(fix_ref="fake:sshd_disable_root_login", title="Disable SSH root login", asset_type="linux",
                         applies_to=[RULE_ROOT_LOGIN, STIG_ROOT_LOGIN], payload=CMD_ROOT_LOGIN,
                         before_state={"files": [SSHD]}, verify={"rule_ids": [RULE_ROOT_LOGIN]},
                         citations=[STIG_ROOT_LOGIN], source="manual")]

    def capture_before_state(self, target, transport, fix, finding, dest: Path) -> BeforeState:
        files = transport.state["files"]
        wanted = fix.before_state.get("files", [])
        captured = [p for p in files if any(p == w or p.startswith(w.rstrip("/") + "/") for w in wanted)]
        for p in captured:
            c = snapshot.file_copy(dest, p)
            c.parent.mkdir(parents=True, exist_ok=True)
            c.write_bytes(transport.read_file(p))
        return BeforeState(target_id=target.id, fix_ref=fix.fix_ref, dir=str(dest), files=captured,
                           extra={"services": copy.deepcopy(transport.state["services"])})

    def apply(self, target, transport, fix, finding, before) -> ApplyResult:
        if self.raise_on_apply:
            raise RuntimeError(self.raise_on_apply)
        r = transport.run(fix.payload, sudo=True)
        return ApplyResult(ok=r.ok, output=r.stdout or r.stderr)

    def health_check(self, target, transport) -> HealthResult:
        checks = [HealthCheck(name, st == "active", st) for name, st in transport.state["services"].items()]
        return HealthResult(ok=all(c.ok for c in checks), checks=checks)

    def verify(self, target, transport, fix, finding) -> VerifyResult:
        now = {f.rule_id: f for f in self._findings(target, transport.state["files"])}
        f = now.get(finding.rule_id)
        passed = f is not None and not f.is_open
        health = self.health_check(target, transport)
        return VerifyResult(ok=passed and health.ok, rule_passed=passed, health=health,
                            evidence=f.evidence if f else "rule not evaluated")

    def rollback(self, target, transport, fix, before) -> RollbackResult:
        for p in before.files:
            transport.write_file(p, snapshot.file_copy(before.dir, p).read_bytes())
        transport.state["services"] = copy.deepcopy(before.extra.get("services", {}))
        return RollbackResult(ok=True, output=f"restored {len(before.files)} file(s)")
