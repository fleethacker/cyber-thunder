"""Container host adapter (docker, with podman as fallback).

Transports: ssh, local, fixture, and 'simulated' (a stateful docker host under the state directory).
Detection is a pure function of `docker inspect` output plus optional Trivy image reports.
"""
from __future__ import annotations

import json
import logging
import shlex
import tempfile
from pathlib import Path
from typing import Iterable

from cyberthunder.adapters.base import MODULES, Adapter, AssetFacts, Collected, register
from cyberthunder.findings.schema import Finding
from cyberthunder.remediation.library import FixEntry
from cyberthunder.remediation.models import (ApplyResult, BeforeState, HealthCheck, HealthResult, RollbackResult,
                                             VerifyResult)

from . import checks, fixes, hunt
from .images import safe_image
from .simulated import SimulatedDockerTransport
from .trivy_min import parse_trivy as _local_parse_trivy

log = logging.getLogger(__name__)

DEMO_TARGET_ID = "sim-docker-01"
ENGINES = ("docker", "podman")


def _json(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def _json_lines(text: str) -> list[dict]:
    text = (text or "").strip()
    if text.startswith("["):
        v = _json(text)
        return v if isinstance(v, list) else []
    out = []
    for line in text.splitlines():
        v = _json(line.strip())
        if isinstance(v, dict):
            out.append(v)
    return out


def parse_trivy_report(path: Path, target, image: str) -> list[Finding]:
    """Use the shared Trivy parser when it is installed, otherwise the minimal local one."""
    try:
        from cyberthunder.parsers.trivy import parse_trivy as shared  # built separately; optional here
    except Exception:  # noqa: BLE001
        shared = None
    if shared is not None:
        for call in (lambda: shared(path, target=target), lambda: shared(path)):
            try:
                res = call()
            except TypeError:
                continue
            except Exception as e:  # noqa: BLE001
                log.warning("shared trivy parser failed on %s: %s", path, e)
                break
            if isinstance(res, list) and all(isinstance(f, Finding) for f in res):
                for f in res:
                    if f.host != target.id or f.asset_type != target.asset_type:
                        f.host, f.asset_type = target.id, target.asset_type
                        f.id = f.make_id(f.host, f.source, f.rule_id)
                return res
            break
    return _local_parse_trivy(path, target, image=image)


@register
class ContainersAdapter(Adapter):
    asset_type = "containers"
    display_name = "Container host (docker/podman)"
    transports = ("ssh", "local", "fixture")
    own_transports = ("simulated",)

    # -- transports / simulation ----------------------------------------------------------------
    @staticmethod
    def simulated_state_path(target, settings=None) -> Path:
        if settings is None:
            from cyberthunder.config import Settings
            settings = Settings.from_env()
        return Path(settings.state_dir) / "simulated" / f"{target.id}.json"

    def make_transport(self, target, settings=None):
        if target.transport == "simulated":
            return SimulatedDockerTransport(self.simulated_state_path(target, settings))
        return None

    def demo_targets(self):
        from cyberthunder.inventory.targets import Target
        return [Target(id=DEMO_TARGET_ID, name="rocky-01 containers (simulated)", asset_type="containers",
                       transport="simulated", simulated=True, sudo=False, tags=["demo", "containers"],
                       options={"engine": "docker", "allowed_registries": ["registry.local", "docker.io/library"],
                                "expected_containers": ["web", "ops-agent", "ops-dashboard", "metrics-relay"],
                                "expected_ports": [443]},
                       notes="Simulated docker host seeded to match range/answer_key/containers.json")]

    def reset_simulated(self, target, settings=None) -> bool:
        if not target.simulated and target.transport != "simulated":
            return False
        SimulatedDockerTransport(self.simulated_state_path(target, settings)).reset()
        return True

    # -- helpers ---------------------------------------------------------------------------------------
    @staticmethod
    def _sudo(target) -> bool:
        return bool(target.sudo) and target.transport in ("ssh", "local")

    def _run(self, target, transport, cmd: str, timeout: int = 120):
        return transport.run(cmd, timeout=timeout, sudo=self._sudo(target))

    def _engine(self, target, transport) -> str | None:
        pref = (target.options or {}).get("engine")
        order = [pref] + [e for e in ENGINES if e != pref] if pref in ENGINES else list(ENGINES)
        for e in order:
            fmt = "'{{json .}}'" if e == "docker" else "json"
            r = self._run(target, transport, f"{e} version --format {fmt}")
            if r.ok and _json(r.stdout) is not None:
                return e
        return None

    @staticmethod
    def _with_engine(cmd: str, engine: str) -> str:
        return engine + cmd[len("docker"):] if cmd.startswith("docker ") and engine != "docker" else cmd

    # -- discovery / collection ------------------------------------------------------------------------
    def discover(self, target, transport) -> AssetFacts:
        engine = self._engine(target, transport)
        info = _json(self._run(target, transport, f"{engine} info --format '{{{{json .}}}}'").stdout) if engine else None
        return self._facts(target, engine, info or {})

    @staticmethod
    def _facts(target, engine, info: dict) -> AssetFacts:
        return AssetFacts(hostname=info.get("Name") or target.name, os_name=info.get("OperatingSystem"),
                          model=f"{engine or 'no engine'} {info.get('ServerVersion', '')}".strip(),
                          extra={"engine": engine, "containers": info.get("Containers"),
                                 "running": info.get("ContainersRunning"), "security_options": info.get("SecurityOptions")})

    def collect(self, target, transport, workdir: Path, *, modules: Iterable[str] = MODULES,
                rule_filter: list[str] | None = None) -> Collected:
        workdir = Path(workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        col = Collected(target_id=target.id, asset_type=self.asset_type, workdir=str(workdir),
                        modules=list(modules), rule_filter=rule_filter)
        engine = self._engine(target, transport)
        col.raw["engine"] = engine
        if engine is None:
            col.errors.append("neither docker nor podman answered 'version'")
            col.facts = self._facts(target, None, {})
            return col
        info = _json(self._run(target, transport, f"{engine} info --format '{{{{json .}}}}'").stdout) or {}
        ps = self._run(target, transport, f"{engine} ps -a --no-trunc --format '{{{{json .}}}}'")
        rows = _json_lines(ps.stdout) if ps.ok else []
        if not ps.ok:
            col.errors.append(f"{engine} ps: exit {ps.exit_code}: {ps.stderr.strip()[:200]}")
        (workdir / "ps.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
        col.artifacts["ps"] = str(workdir / "ps.json")
        ids = [str(r.get("ID") or r.get("Id") or "") for r in rows]
        ids = [i for i in ids if checks.RE_ID.match(i)]
        inspect: list = []
        if ids:
            r = self._run(target, transport, f"{engine} inspect " + " ".join(ids))
            inspect = _json(r.stdout) or []
            if not r.ok:
                col.errors.append(f"{engine} inspect: exit {r.exit_code}: {r.stderr.strip()[:200]}")
        (workdir / "inspect.json").write_text(json.dumps(inspect, indent=2), encoding="utf-8")
        col.artifacts["inspect"] = str(workdir / "inspect.json")
        imgs = self._run(target, transport, f"{engine} images --format '{{{{json .}}}}'")
        (workdir / "images.json").write_text(json.dumps(_json_lines(imgs.stdout), indent=2), encoding="utf-8")
        col.artifacts["images"] = str(workdir / "images.json")
        (workdir / "info.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
        col.artifacts["info"] = str(workdir / "info.json")
        if "cve" in col.modules:
            self._collect_trivy(target, transport, col, workdir, inspect)
        col.facts = self._facts(target, engine, info)
        return col

    def _collect_trivy(self, target, transport, col: Collected, workdir: Path, inspect: list) -> None:
        if not self._run(target, transport, "command -v trivy").ok:
            col.raw["trivy"] = "not installed"
            return
        images = sorted({(d.get("Config") or {}).get("Image", "") for d in inspect
                         if (d.get("State") or {}).get("Running")})
        col.raw["trivy_images"] = {}
        for n, image in enumerate(i for i in images if safe_image(i)):
            r = self._run(target, transport, f"trivy image --skip-db-update --quiet --format json {shlex.quote(image)}",
                          timeout=170)
            if not r.ok or _json(r.stdout) is None:
                col.errors.append(f"trivy {image}: exit {r.exit_code}: {r.stderr.strip()[:200]}")
                continue
            name = f"trivy_{n:02d}"
            (workdir / f"{name}.json").write_text(r.stdout, encoding="utf-8")
            col.artifacts[name] = str(workdir / f"{name}.json")
            col.raw["trivy_images"][name] = image

    # -- detection ---------------------------------------------------------------------------------------
    def check(self, target, collected: Collected) -> list[Finding]:
        return _filter(checks.run_checks(target, collected), collected.rule_filter)

    def hunt(self, target, collected: Collected) -> list[Finding]:
        return _filter(hunt.run_hunt(target, collected), collected.rule_filter)

    def cve(self, target, collected: Collected) -> list[Finding]:
        out: list[Finding] = []
        names = collected.raw.get("trivy_images") or {}
        for name, path in collected.artifacts.items():
            if name.startswith("trivy_"):
                out.extend(parse_trivy_report(Path(path), target, names.get(name, "")))
        return _filter(out, collected.rule_filter)

    # -- remediation ---------------------------------------------------------------------------------------
    def fixes(self) -> list[FixEntry]:
        return fixes.container_fixes()

    @staticmethod
    def _locator(finding: Finding) -> tuple[str, str]:
        cid = name = None
        for t in finding.tags:
            if t.startswith(checks.ID_TAG):
                cid = t[len(checks.ID_TAG):]
            elif t.startswith(checks.NAME_TAG):
                name = t[len(checks.NAME_TAG):]
        if not cid or not checks.RE_ID.match(cid) or not name or not checks.RE_NAME.match(name):
            raise ValueError(f"finding {finding.id} carries no valid container reference")
        return cid, name

    def _render(self, template: str, finding: Finding, target) -> list[str]:
        cid, name = self._locator(finding)
        engine = (target.options or {}).get("engine", "docker")
        engine = engine if engine in ENGINES else "docker"
        lines = [ln.strip() for ln in template.replace("<id>", cid).replace("<name>", name).splitlines() if ln.strip()]
        return [self._with_engine(ln, engine) for ln in lines]

    def capture_before_state(self, target, transport, fix: FixEntry, finding: Finding, dest: Path) -> BeforeState:
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        before = BeforeState(target_id=target.id, fix_ref=fix.fix_ref, dir=str(dest))
        cid, name = self._locator(finding)
        before.extra.update({"container_id": cid, "container_name": name})
        cmds = fix.before_state.get("commands") or {"inspect": "docker inspect <id>"}
        for key, template in cmds.items():
            cmd = self._render(template, finding, target)[0]
            r = self._run(target, transport, cmd)
            (dest / f"{key}.json").write_text(r.stdout, encoding="utf-8")
            before.commands[key] = f"{key}.json"
            if key == "inspect":
                data = _json(r.stdout) if r.ok else None
                if not data:
                    raise RuntimeError(f"could not inspect container {name} before the change: {r.stderr.strip()[:200]}")
                d = data[0]
                rp = (d.get("HostConfig") or {}).get("RestartPolicy") or {}
                before.extra.update({"running": bool((d.get("State") or {}).get("Running")),
                                     "restart_policy": rp.get("Name") or "no",
                                     "restart_retries": int(rp.get("MaximumRetryCount") or 0)})
        before.notes = (f"{name}: running={before.extra.get('running')}, restart={before.extra.get('restart_policy')}")
        return before

    def apply(self, target, transport, fix: FixEntry, finding: Finding, before: BeforeState) -> ApplyResult:
        if fix.kind == "runbook":
            return self._runbook_output(target, transport, fix, finding)
        if fix.kind != "script" or not fix.payload:
            return ApplyResult(ok=False, changed=False, output=f"unsupported fix {fix.fix_ref} for containers")
        try:
            commands = self._render(fix.payload, finding, target)
        except ValueError as e:
            return ApplyResult(ok=False, changed=False, output=str(e))
        outputs, ran = [], []
        for cmd in commands:
            if cmd.split(" ", 1)[0] not in ENGINES:
                return ApplyResult(ok=False, changed=bool(ran), output=f"refused payload line: {cmd[:80]!r}")
            r = self._run(target, transport, cmd)
            ran.append(cmd)
            outputs.append(f"$ {cmd}\n{r.stdout}{r.stderr}")
            if not r.ok:
                return ApplyResult(ok=False, changed=len(ran) > 1, output="\n".join(outputs),
                                   details={"ran": ran, "exit_code": r.exit_code})
        return ApplyResult(ok=True, output="\n".join(outputs), details={"ran": ran})

    def _runbook_output(self, target, transport, fix: FixEntry, finding: Finding) -> ApplyResult:
        details: dict = {"runbook": True, "steps": list(fix.steps)}
        text = ["Runbook fix: the tool does not re-create containers. Steps for the operator:", fix.preview_text()]
        if not fixes.RECREATE:
            fixes.container_fixes()
        key_compose = fixes.RECREATE.get(fix.fix_ref)
        try:
            cid, name = self._locator(finding)
            text[1] = text[1].replace("<name>", name).replace("<id>", cid)
            if key_compose:
                key, compose = key_compose
                engine = (target.options or {}).get("engine", "docker")
                r = self._run(target, transport, f"{engine if engine in ENGINES else 'docker'} inspect {cid}")
                data = _json(r.stdout) if r.ok else None
                if data:
                    run = fixes.corrected_run(data[0], key, engine if engine in ENGINES else "docker")
                    details.update({"corrected_run": run, "compose": compose})
                    text += ["", "Corrected command (review before running):", run, "", f"Compose: {compose}"]
        except ValueError as e:
            text.append(f"(no container reference: {e})")
        return ApplyResult(ok=False, changed=False, output="\n".join(text), details=details)

    def _redetect(self, target, transport) -> tuple[list[Finding], list[str]]:
        with tempfile.TemporaryDirectory(prefix="ct-containers-verify-") as tmp:
            col = self.collect(target, transport, Path(tmp), modules=("check", "hunt"))
            return self.run_detection(target, col), list(col.errors)

    def verify(self, target, transport, fix: FixEntry, finding: Finding) -> VerifyResult:
        health = self.health_check(target, transport)
        found, errors = self._redetect(target, transport)
        still = [f for f in found if f.rule_id == finding.rule_id and f.is_open]
        if errors and not found and not health.ok:
            rule_passed, evidence = None, "could not re-collect: " + "; ".join(errors[:3])
        else:
            rule_passed = not still
            evidence = f"{finding.rule_id} no longer detected" if rule_passed else f"still detected: {still[0].evidence}"
        return VerifyResult(ok=bool(rule_passed) and health.ok, rule_passed=rule_passed, health=health,
                            evidence=evidence, details={"rescan_findings": len(found), "errors": errors[:5]})

    def health_check(self, target, transport) -> HealthResult:
        res: list[HealthCheck] = []
        engine = self._engine(target, transport)
        res.append(HealthCheck("engine", engine is not None, f"{engine} answering" if engine else "no container engine answered"))
        critical = list((target.options or {}).get("critical_containers") or [])
        if engine and critical:
            ps = self._run(target, transport, f"{engine} ps --format '{{{{json .}}}}'")
            running = set()
            for r in _json_lines(ps.stdout):
                n = r.get("Names")
                running.update(n if isinstance(n, list) else [n])
            missing = [c for c in critical if c not in running]
            res.append(HealthCheck("critical_containers", not missing,
                                   "all running" if not missing else f"not running: {', '.join(missing)}"))
        return HealthResult(ok=all(c.ok for c in res), checks=res)

    def rollback(self, target, transport, fix: FixEntry, before: BeforeState) -> RollbackResult:
        if fix.kind == "runbook":
            return RollbackResult(ok=True, output="Runbook fix: nothing was changed by the tool. Manual rollback:\n"
                                  + fix.rollback_plan_text(), details={"runbook": True})
        cid = before.extra.get("container_id", "")
        policy = before.extra.get("restart_policy", "no")
        retries = int(before.extra.get("restart_retries") or 0)
        if not checks.RE_ID.match(cid) or policy not in fixes.RESTART_POLICIES:
            return RollbackResult(ok=False, output="before-state is incomplete; cannot roll back")
        engine = (target.options or {}).get("engine", "docker")
        engine = engine if engine in ENGINES else "docker"
        pol = f"{policy}:{retries}" if policy == "on-failure" and retries else policy
        cmds = [f"{engine} update --restart={pol} {cid}"]
        if before.extra.get("running"):
            cmds.append(f"{engine} start {cid}")
        outputs = []
        for cmd in cmds:
            r = self._run(target, transport, cmd)
            outputs.append(f"$ {cmd}\n{r.stdout}{r.stderr}")
            if not r.ok:
                return RollbackResult(ok=False, output="\n".join(outputs))
        return RollbackResult(ok=True, output="\n".join(outputs), details={"container": cid, "restart_policy": pol})


def _filter(findings: list[Finding], rule_filter: list[str] | None) -> list[Finding]:
    if not rule_filter:
        return findings
    keys = set(rule_filter)
    return [f for f in findings if f.rule_id in keys or f.rule_version in keys or any(r.id in keys for r in f.references)]
