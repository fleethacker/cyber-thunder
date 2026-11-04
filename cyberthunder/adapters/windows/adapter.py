"""Windows host adapter: STIG checks, intrusion hunt, CKLB ingestion and reversible PowerShell fixes.

With target.options.scap_datastream naming a DISA SCAP datastream on the operator machine (and optionally
options.scap_profile), the adapter also runs that benchmark: one collection script gathers what the selected
rules' OVAL definitions need, cyberthunder.scap evaluates them, and the results are merged with the native
checks by STIG id with the benchmark winning (scap_merge.py). See docs/SCAP.md.

All host interaction goes through the adapter's own scripts under ps/ and the payloads in fixes.py, sent as
'powershell -NoProfile -NonInteractive -EncodedCommand <base64>' over whatever transport the target uses
(winrm, local, fixture, simulated). Detection is pure Python over the collected JSON.
"""
from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path, PureWindowsPath
from typing import Iterable

from cyberthunder.adapters.base import MODULES, Adapter, AssetFacts, Collected, register
from cyberthunder.findings.schema import Finding, Status, utcnow
from cyberthunder.inventory.targets import Target
from cyberthunder.remediation.library import FixEntry
from cyberthunder.remediation.models import (ApplyResult, BeforeState, HealthCheck, HealthResult, RollbackResult,
                                             VerifyResult)
from cyberthunder.transport.base import CommandResult, Transport, TransportError

from . import checks as checks_mod
from . import cklb_merge, fixes as fixes_mod, hunt as hunt_mod, scap_merge
from .scripts import MAX_INLINE, command_for, encode, load, parse_json_output, safe_values, with_data
from .simhost import SimulatedWindowsHost, state_path

log = logging.getLogger(__name__)

LIVE_KINDS = ("winrm", "local")
REMOTE_STAGE = r"C:\Windows\Temp\cyberthunder"


def run_script(transport: Transport, script: str, *, timeout: int = 300, stage_dir: str = REMOTE_STAGE) -> CommandResult:
    """Run one marked script. Scripts too long for a command line are staged as a file on the host first."""
    if len(encode(script)) <= MAX_INLINE:
        return transport.run(command_for(script), timeout=timeout)
    import hashlib
    name = hashlib.sha256(script.encode("utf-8")).hexdigest()[:12]
    path = str(PureWindowsPath(stage_dir) / f"ct_{name}.ps1")
    transport.write_file(path, script.encode("utf-8-sig"))
    try:
        return transport.run(f'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{path}"', timeout=timeout)
    finally:
        try:
            transport.run(command_for(f"# cyberthunder-script: cleanup\nRemove-Item -LiteralPath '{path}' -Force -ErrorAction SilentlyContinue\n"))
        except TransportError:
            pass


def run_json(transport: Transport, script: str, *, timeout: int = 300):
    r = run_script(transport, script, timeout=timeout)
    if not r.ok:
        raise TransportError(f"script failed ({r.exit_code}): {(r.stderr or r.stdout).strip()[:300]}")
    return parse_json_output(r.stdout)


@register
class WindowsAdapter(Adapter):
    asset_type = "windows"
    display_name = "Windows workstation / server"
    transports = ("winrm", "local", "fixture")
    own_transports = ("simulated",)

    # -- discovery / collection -------------------------------------------------------------------------
    def discover(self, target: Target, transport: Transport) -> AssetFacts:
        d = run_json(transport, load("facts"))
        return AssetFacts(hostname=d.get("hostname"), os_name=d.get("os_name"), os_version=d.get("os_version"),
                          kernel=d.get("kernel"), addresses=list(d.get("addresses") or []), model=d.get("model"),
                          extra={k: d.get(k) for k in ("build", "domain", "part_of_domain", "last_boot", "powershell", "simulated")
                                 if k in d})

    def collect(self, target: Target, transport: Transport, workdir: Path, *,
                modules: Iterable[str] = MODULES, rule_filter: list[str] | None = None) -> Collected:
        workdir = Path(workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        mods = list(modules)
        col = Collected(target_id=target.id, asset_type=self.asset_type, workdir=str(workdir), modules=mods,
                        rule_filter=rule_filter)
        try:
            col.facts = self.discover(target, transport)
        except (TransportError, ValueError) as e:
            col.errors.append(f"facts: {e}")
        for name in ("check", "hunt"):
            if name not in mods:
                continue
            script = "checks" if name == "check" else "hunt"
            try:
                data = run_json(transport, load(script), timeout=600)
                col.raw[script] = data
                p = workdir / f"{script}.json"
                p.write_text(json.dumps(data, indent=1), encoding="utf-8")
                col.artifacts[script] = str(p)
            except (TransportError, ValueError) as e:
                col.errors.append(f"{script}: {e}")
        if "check" in mods:
            self._collect_scap(target, transport, workdir, col)
            self._collect_cklb(target, transport, workdir, col)
        return col

    # -- SCAP benchmark -----------------------------------------------------------------------------------
    @staticmethod
    def _scap_options(target: Target) -> tuple[str | None, str | None]:
        o = target.options or {}
        return (str(o["scap_datastream"]) if o.get("scap_datastream") else None,
                str(o["scap_profile"]) if o.get("scap_profile") else None)

    @staticmethod
    def _scap_rules(path: str, profile: str | None, rule_filter: list[str] | None):
        from cyberthunder.scap.datastream import load_cached, rules_for
        ds = load_cached(path)
        return ds, rules_for(ds, profile, rule_filter)

    @staticmethod
    def _scap_gather(transport: Transport, ds, rules) -> tuple[dict, list[dict]]:
        from cyberthunder.scap.windows_plan import collect_benchmark, script_for, supported_rules
        return collect_benchmark(ds, supported_rules(ds, rules),
                                 lambda params: run_json(transport, script_for(params), timeout=900))

    def _collect_scap(self, target: Target, transport: Transport, workdir: Path, col: Collected) -> None:
        path, profile = self._scap_options(target)
        if not path:
            return
        try:
            ds, rules = self._scap_rules(path, profile, col.rule_filter)
        except (OSError, ValueError, KeyError, SyntaxError) as e:   # ParseError is a SyntaxError
            col.errors.append(f"scap datastream {path}: {e}")
            return
        if not rules:
            return
        try:
            data, rounds = self._scap_gather(transport, ds, rules)
        except (TransportError, ValueError) as e:
            col.errors.append(f"scap collect: {e}")
            return
        p = workdir / "scap_collect.json"
        p.write_text(json.dumps(data, indent=1), encoding="utf-8")
        col.artifacts["scap_collect"] = str(p)
        col.raw["scap"] = data
        col.raw["scap_source"] = {"datastream": path, "profile": profile, "rounds": rounds}
        for e in data.get("errors") or []:
            col.errors.append(f"scap collect: {e}")

    def _scap_findings(self, target: Target, collected: Collected) -> list[Finding]:
        from cyberthunder.scap.benchmark import evaluate, to_findings
        src = collected.raw.get("scap_source") or {}
        ds, rules = self._scap_rules(src.get("datastream") or self._scap_options(target)[0],
                                     src.get("profile"), collected.rule_filter)
        results = evaluate(ds, rules, collected.raw["scap"])
        return to_findings(target, ds, results, collected_at=collected.collected_at,
                           raw_ref=collected.artifacts.get("scap_collect"))

    def _scap_recheck(self, target: Target, transport: Transport, finding: Finding) -> tuple[bool, str] | None:
        """Re-evaluate one rule from the benchmark. None when the benchmark lacks the rule or cannot decide it."""
        path, profile = self._scap_options(target)
        if not path:
            return None
        from cyberthunder.scap.benchmark import evaluate, evidence_text
        try:
            ds, rules = self._scap_rules(path, profile, [finding.rule_version or "", finding.rule_id])
        except (OSError, KeyError, SyntaxError) as e:
            log.warning("scap datastream %s unusable for verify: %s", path, e)
            return None
        if not rules:
            return None
        data, _ = self._scap_gather(transport, ds, rules[:1])
        rr = evaluate(ds, rules[:1], data)[0]
        if rr.result not in ("pass", "fail"):
            return None
        return rr.result == "pass", "SCAP benchmark (OVAL): " + evidence_text(rr.evidence)

    def _collect_cklb(self, target: Target, transport: Transport, workdir: Path, col: Collected) -> None:
        o = target.options or {}
        dest = workdir / "evaluate-stig.cklb"
        try:
            if o.get("evaluate_stig_path") and transport.kind in LIVE_KINDS:
                params = safe_values({"path": str(o["evaluate_stig_path"]),
                                      "out": str(o.get("evaluate_stig_output", REMOTE_STAGE + r"\evaluate-stig"))})
                res = run_json(transport, with_data(load("evaluate_stig"), "CtParams", params), timeout=3600)
                if res.get("cklb"):
                    transport.fetch(res["cklb"], str(dest))
                    col.artifacts["cklb"] = str(dest)
                    return
                col.errors.append("evaluate-stig: no CKLB produced")
            cp = o.get("cklb_path")
            if cp:
                if Path(cp).exists():
                    shutil.copyfile(cp, dest)
                else:
                    transport.fetch(cp, str(dest))
                col.artifacts["cklb"] = str(dest)
        except (TransportError, OSError, ValueError) as e:
            col.errors.append(f"cklb: {e}")

    # -- detection --------------------------------------------------------------------------------------
    def check(self, target: Target, collected: Collected) -> list[Finding]:
        out: list[Finding] = []
        state = collected.raw.get("checks")
        if state is not None:
            out = checks_mod.evaluate(target, state, collected_at=collected.collected_at,
                                      raw_ref=collected.artifacts.get("checks"), rule_filter=collected.rule_filter)
        if collected.raw.get("scap") is not None:
            out = scap_merge.merge(target, out, self._scap_findings(target, collected))
        cp = collected.path("cklb")
        if cp and cp.exists():
            from cyberthunder.parsers.cklb import parse_cklb
            ck = parse_cklb(cp, host=target.id)
            if collected.rule_filter:
                ck = [f for f in ck if {f.rule_id, f.rule_version} & set(collected.rule_filter)]
            out = cklb_merge.merge(target, out, ck)
        return out

    def hunt(self, target: Target, collected: Collected) -> list[Finding]:
        state = collected.raw.get("hunt")
        if state is None:
            return []
        return hunt_mod.evaluate(target, state, collected_at=collected.collected_at, raw_ref=collected.artifacts.get("hunt"))

    # -- remediation ------------------------------------------------------------------------------------
    def fixes(self) -> list[FixEntry]:
        return fixes_mod.all_fixes()

    @staticmethod
    def _is_hunt_fix(fix: FixEntry) -> bool:
        return fix.fix_ref.startswith("windows:hunt:")

    def _hunt_params(self, target: Target, transport: Transport, fix: FixEntry, finding: Finding) -> dict:
        """The structured item a hunt fix acts on, re-read from the host's own state (never from finding text)."""
        state = run_json(transport, load("hunt"), timeout=600)
        hit = hunt_mod.find_hit(state, target.options or {}, finding.rule_id)
        if hit is None:
            raise TransportError(f"{finding.rule_id} is no longer present on {target.id}")
        if hit.fix_ref != fix.fix_ref and fix.fix_ref not in ("windows:hunt:disable_account",):
            raise TransportError(f"{fix.fix_ref} does not apply to {finding.rule_id}")
        if fix.fix_ref == "windows:hunt:disable_account" and "name" not in hit.params:
            name = hit.params.get("member", "").split("\\")[-1]
            return safe_values({"name": name})
        return safe_values(dict(hit.params))

    def capture_before_state(self, target: Target, transport: Transport, fix: FixEntry, finding: Finding,
                             dest: Path) -> BeforeState:
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        params = None
        if self._is_hunt_fix(fix):
            params = self._hunt_params(target, transport, fix, finding)
            script = fixes_mod.snapshot_command(fixes_mod.hunt_spec(fix.fix_ref, params))
        else:
            script = fix.before_state["commands"]["snapshot"]
        snap = run_json(transport, script)
        out = dest / "snapshot.json"
        out.write_text(json.dumps(snap, indent=1), encoding="utf-8")
        (dest / "snapshot.ps1").write_text(script, encoding="utf-8")
        return BeforeState(target_id=target.id, fix_ref=fix.fix_ref, dir=str(dest), commands={"snapshot": str(out)},
                           notes="exported with snapshot.ps1; rollback re-imports it with restore.ps1",
                           extra={"snapshot": snap, "params": params, "finding_rule_id": finding.rule_id})

    def apply(self, target: Target, transport: Transport, fix: FixEntry, finding: Finding,
              before: BeforeState) -> ApplyResult:
        if fix.asset_type != self.asset_type or fix.kind != "powershell" or not fix.payload:
            return ApplyResult(ok=False, changed=False, output=f"{fix.fix_ref} is not an automatic Windows fix "
                                                              f"({fix.kind}); follow its steps by hand",
                               finished_at=utcnow())
        script = fix.payload
        if self._is_hunt_fix(fix):
            params = (before.extra or {}).get("params")
            if not params:
                return ApplyResult(ok=False, changed=False, output="before-state holds no item for this hunt fix",
                                   finished_at=utcnow())
            script = with_data(script, "CtParams", safe_values(params))
        try:
            r = run_script(transport, script, timeout=600)
        except TransportError as e:
            return ApplyResult(ok=False, changed=False, output=str(e), finished_at=utcnow())
        return ApplyResult(ok=r.ok, changed=r.ok, output=(r.stdout + r.stderr).strip()[-4000:], finished_at=utcnow(),
                           details={"exit_code": r.exit_code, "reboot_required": fix.reboot})

    def verify(self, target: Target, transport: Transport, fix: FixEntry, finding: Finding) -> VerifyResult:
        health = self.health_check(target, transport)
        module = "hunt" if self._is_hunt_fix(fix) or finding.source == hunt_mod.SOURCE else "check"
        rule_passed: bool | None
        try:
            scap = self._scap_recheck(target, transport, finding) if module == "check" else None
            if scap is not None:
                rule_passed, evidence = scap
            elif module == "check":
                state = run_json(transport, load("checks"), timeout=600)
                found = [f for f in checks_mod.evaluate(target, state, rule_filter=[finding.rule_id, finding.rule_version or ""])
                         if f.rule_id == finding.rule_id or (finding.rule_version and f.rule_version == finding.rule_version)]
                if not found:
                    rule_passed, evidence = None, f"{finding.rule_id} is not checked natively; re-run the checklist"
                else:
                    f = found[0]
                    rule_passed = None if f.status == Status.NOT_REVIEWED else f.status != Status.OPEN
                    evidence = f.evidence or ""
            else:
                state = run_json(transport, load("hunt"), timeout=600)
                still = hunt_mod.find_hit(state, target.options or {}, finding.rule_id)
                rule_passed = still is None
                evidence = "indicator no longer present" if still is None else f"still present: {still.evidence}"
        except (TransportError, ValueError) as e:
            rule_passed, evidence = None, f"re-check failed: {e}"
        return VerifyResult(ok=bool(rule_passed) and health.ok, rule_passed=rule_passed, health=health,
                            evidence=evidence, details={"module": module})

    def health_check(self, target: Target, transport: Transport) -> HealthResult:
        try:
            d = run_json(transport, load("health"), timeout=120)
        except (TransportError, ValueError) as e:
            return HealthResult(ok=False, checks=[HealthCheck("reachable", False, str(e))])
        checks = [HealthCheck("reachable", True, str(d.get("hostname") or ""))]
        checks += [HealthCheck(str(c.get("name")), bool(c.get("ok")), str(c.get("detail") or ""))
                   for c in (d.get("checks") or [])]
        return HealthResult(ok=all(c.ok for c in checks), checks=checks)

    def rollback(self, target: Target, transport: Transport, fix: FixEntry, before: BeforeState) -> RollbackResult:
        snap = (before.extra or {}).get("snapshot")
        if snap is None and before.commands.get("snapshot") and Path(before.commands["snapshot"]).exists():
            snap = json.loads(Path(before.commands["snapshot"]).read_text(encoding="utf-8"))
        if not snap:
            return RollbackResult(ok=False, output="no exported before-state to restore")
        try:
            r = run_script(transport, fixes_mod.restore_command(snap), timeout=600)
        except TransportError as e:
            return RollbackResult(ok=False, output=str(e))
        return RollbackResult(ok=r.ok, output=(r.stdout + r.stderr).strip()[-4000:],
                              details={"exit_code": r.exit_code, "restored_from": before.commands.get("snapshot")})

    # -- simulation -------------------------------------------------------------------------------------
    def make_transport(self, target: Target, settings=None) -> Transport | None:
        if target.transport != "simulated":
            return None
        return SimulatedWindowsHost(state_path(target.id, settings), target.id)

    def demo_targets(self) -> list[Target]:
        return [Target(id="sim-win-01", name="ws-01 (simulated)", asset_type="windows", transport="simulated",
                       simulated=True, sudo=False, tags=["demo", "workstation"],
                       options={"known_admins": ["Administrator", "itadmin"], "expected_ports": [3389, 5985]},
                       notes="Simulated Windows 11 workstation seeded per range/answer_key/windows.json")]

    def reset_simulated(self, target: Target, settings=None) -> bool:
        if target.transport != "simulated":
            return False
        SimulatedWindowsHost(state_path(target.id, settings), target.id).reset()
        return True
