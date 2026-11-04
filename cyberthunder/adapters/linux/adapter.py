"""The Linux host adapter: the primary detection surface.

Collection runs only over the Transport. Detection (check, hunt, cve) is a pure function of the Collected
material, so the same code runs against a live SSH host, a recorded fixture and the simulated host.
Remediation applies exactly one FixEntry payload, captures a before-state first and can roll it back.
"""
from __future__ import annotations

import logging
import re
import shlex
from pathlib import Path
from typing import Iterable

from cyberthunder.adapters.base import Adapter, AssetFacts, Collected, register
from cyberthunder.findings.schema import Finding
from cyberthunder.remediation.library import FixEntry
from cyberthunder.remediation.models import (ApplyResult, BeforeState, HealthCheck, HealthResult,
                                             RollbackResult, VerifyResult)

from . import checks, cve, fixes, hunt, parse
from . import commands as C
from .simhost import SimulatedLinuxHost
from .simstate import HOSTNAME, KNOWN_USERS, ADMIN_KEY_BLOB

log = logging.getLogger(__name__)

REMOTE_TMP = "/tmp"                    # staging dir for fix payloads on the target (a tmpfs on RHEL)
HASH_TARGETS = tuple(sorted(set(hunt.REFERENCE_SHELLS)))


@register
class LinuxAdapter(Adapter):
    asset_type = "linux"
    display_name = "Linux host (RHEL/Ubuntu)"
    transports = ("ssh", "local", "fixture")
    own_transports = ("simulated",)

    # -- discovery / collection ----------------------------------------------------------------
    def discover(self, target, transport) -> AssetFacts:
        facts = AssetFacts()
        r = transport.run(C.CMDS["os_release"].cmd)
        if r.ok:
            d = parse.os_release(r.stdout)
            facts.os_name = d.get("NAME")
            facts.os_version = d.get("VERSION_ID")
            facts.model = d.get("ID")
        h = transport.run(C.CMDS["hostname"].cmd)
        facts.hostname = h.stdout.strip() or None
        k = transport.run(C.CMDS["kernel"].cmd)
        facts.kernel = k.stdout.strip() or None
        a = transport.run(C.CMDS["addrs"].cmd)
        if a.ok:
            facts.addresses = re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", a.stdout)
        return facts

    def collect(self, target, transport, workdir: Path, *, modules: Iterable[str] = ("check", "hunt", "cve"),
                rule_filter: list[str] | None = None) -> Collected:
        workdir = Path(workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        modules = list(modules)
        collected = Collected(target_id=target.id, asset_type=self.asset_type, workdir=str(workdir),
                              modules=modules, rule_filter=rule_filter)
        wanted = self._wanted_commands(modules, rule_filter)
        cmd_out: dict[str, dict] = {}
        for name in wanted:
            cmd = C.CMDS[name]
            r = transport.run(cmd.cmd, timeout=cmd.timeout, sudo=cmd.sudo)
            cmd_out[name] = {"exit": r.exit_code, "out": r.stdout, "err": r.stderr}
            if r.exit_code not in cmd.ok_exits:
                collected.errors.append(f"{name} (exit {r.exit_code}): {(r.stderr or '').strip()[:200]}")
        collected.raw["cmd"] = cmd_out

        # facts and the package inventory in the exact shape the bulletin matcher consumes
        collected.facts = self._facts_from(cmd_out)
        collected.raw["packages"] = self._packages(cmd_out)
        if "hunt" in modules or (rule_filter and any(r.startswith(hunt.PREFIX) for r in rule_filter)):
            collected.raw["hashes"] = self._hashes(transport, cmd_out)

        self._maybe_oscap(target, transport, workdir, collected, rule_filter)
        self._maybe_trivy(transport, workdir, collected)
        return collected

    def _wanted_commands(self, modules: list[str], rule_filter: list[str] | None) -> list[str]:
        names = set(C.FACT_CMDS) | {"rpm_packages", "dpkg_packages"}
        if rule_filter:
            for r in rule_filter:
                names.update(checks.needs(r))
                names.update(hunt.needs(r))
            # file stats / passwd are shared by several native checks
            return [c.name for c in C.CMDS.values() if c.name in names]
        if "check" in modules:
            names |= checks.all_needs()
        if "hunt" in modules:
            names |= hunt.all_needs()
        return [c.name for c in C.CMDS.values() if c.name in names]

    def _facts_from(self, cmd_out: dict) -> AssetFacts:
        facts = AssetFacts()
        osr = cmd_out.get("os_release", {}).get("out", "")
        if osr:
            d = parse.os_release(osr)
            facts.os_name, facts.os_version, facts.model = d.get("NAME"), d.get("VERSION_ID"), d.get("ID")
        facts.hostname = cmd_out.get("hostname", {}).get("out", "").strip() or None
        facts.kernel = cmd_out.get("kernel", {}).get("out", "").strip() or None
        facts.addresses = re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", cmd_out.get("addrs", {}).get("out", ""))
        return facts

    def _packages(self, cmd_out: dict) -> list[dict]:
        rpm = cmd_out.get("rpm_packages", {})
        if rpm.get("exit") == 0 and rpm.get("out", "").strip():
            return parse.rpm_packages(rpm["out"])
        dpkg = cmd_out.get("dpkg_packages", {})
        if dpkg.get("exit") == 0 and dpkg.get("out", "").strip():
            return parse.dpkg_packages(dpkg["out"])
        return []

    def _hashes(self, transport, cmd_out: dict) -> dict[str, str]:
        suid_paths = [r["path"] for r in parse.find_printf(
            cmd_out.get("suid", {}).get("out", ""), ["mode", "owner", "size", "path"])]
        paths = list(dict.fromkeys([*HASH_TARGETS, *suid_paths]))
        if not paths:
            return {}
        quoted = " ".join(shlex.quote(p) for p in paths)
        r = transport.run(f"sha256sum -- {quoted} 2>/dev/null", sudo=True)
        return parse.sha256sums(r.stdout) if r.stdout else {}

    def _maybe_oscap(self, target, transport, workdir, collected, rule_filter) -> None:
        if not transport.run("command -v oscap").ok:
            return
        ds = self._oscap_datastream(transport)
        if not ds:
            collected.errors.append("oscap present but no SSG datastream under /usr/share/xml/scap/ssg/content/")
            return
        profile = self._oscap_profile(transport, ds)
        remote = f"{REMOTE_TMP}/ct-oscap-results.xml"
        rules = [f"--rule {shlex.quote(r)}" for r in (rule_filter or []) if r.startswith("xccdf_")]
        cmd = (f"oscap xccdf eval --profile {shlex.quote(profile)} {' '.join(rules)} "
               f"--results {remote} {shlex.quote(ds)}")
        transport.run(cmd, sudo=True, timeout=600)
        local = workdir / "oscap_results.xml"
        try:
            transport.fetch(remote, str(local))
            collected.artifacts["oscap_results"] = str(local)
        except Exception as e:  # noqa: BLE001
            collected.errors.append(f"oscap results fetch: {e}")

    def _oscap_datastream(self, transport) -> str | None:
        r = transport.run("ls /usr/share/xml/scap/ssg/content/ssg-*-ds.xml 2>/dev/null")
        files = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
        for f in files:
            if re.search(r"ssg-(rhel|ubuntu|centos|ol)\d", f):
                return f
        return files[0] if files else None

    def _oscap_profile(self, transport, datastream: str) -> str:
        r = transport.run(f"oscap info {shlex.quote(datastream)}")
        profiles = re.findall(r"(xccdf_org\.ssgproject\.content_profile_\S+)", r.stdout)
        for p in profiles:
            if "stig" in p.lower() and "gui" not in p.lower():
                return p
        return profiles[0] if profiles else "xccdf_org.ssgproject.content_profile_stig"

    def _maybe_trivy(self, transport, workdir, collected) -> None:
        if not transport.run("command -v trivy").ok:
            return
        remote = f"{REMOTE_TMP}/ct-trivy.json"
        transport.run(f"trivy rootfs --skip-db-update --format json --output {remote} /", sudo=True, timeout=600)
        local = workdir / "trivy.json"
        try:
            transport.fetch(remote, str(local))
            collected.artifacts["trivy"] = str(local)
        except Exception as e:  # noqa: BLE001
            collected.errors.append(f"trivy results fetch: {e}")

    # -- detection -----------------------------------------------------------------------------
    def check(self, target, collected: Collected) -> list[Finding]:
        return checks.run_checks(target, collected)

    def hunt(self, target, collected: Collected) -> list[Finding]:
        return hunt.run_hunt(target, collected)

    def cve(self, target, collected: Collected) -> list[Finding]:
        return cve.run_cve(target, collected)

    # -- remediation ---------------------------------------------------------------------------
    def fixes(self) -> list[FixEntry]:
        return fixes.all_fixes()

    def _subject(self, finding: Finding | None) -> str | None:
        if finding is None:
            return None
        for t in finding.tags:
            if t.startswith("subject:"):
                return t[len("subject:"):]
        return None

    def capture_before_state(self, target, transport, fix: FixEntry, finding, dest: Path) -> BeforeState:
        dest = Path(dest)
        (dest / "files").mkdir(parents=True, exist_ok=True)
        before = BeforeState(target_id=target.id, fix_ref=fix.fix_ref, dir=str(dest))
        spec = dict(fix.before_state)
        subject = self._subject(finding)
        file_list = list(spec.get("files", []))
        # a hunt fix also captures the file or unit it acts on
        if spec.get("subject") == "key" and subject and "|" in subject:
            file_list.append(subject.split("|", 1)[0])
        if spec.get("subject") == "path" and subject:
            file_list.append(subject)
        if spec.get("subject") == "unit" and subject and subject.endswith(".service"):
            file_list.append(f"/etc/systemd/system/{subject}")
        for pat in spec.get("dirs", []):
            file_list.extend(self._glob(transport, pat["dir"], pat["pattern"]))
        before.files = list(dict.fromkeys(file_list))
        meta: dict[str, dict] = {}
        for path in before.files:
            meta[path] = self._capture_file(transport, path, dest / "files")
        before.extra["files"] = meta
        before.extra["subject"] = subject
        for name, cmd in spec.get("commands", {}).items():
            r = transport.run(cmd, sudo=True)
            (dest / f"cmd_{name}.txt").write_text(r.stdout, encoding="utf-8")
            before.commands[name] = f"cmd_{name}.txt"
        if "services" in spec:
            before.extra["services"] = {u: self._svc_pair(transport, u) for u in spec["services"]}
        if "sysctl" in spec:
            before.extra["sysctl"] = {k: transport.run(f"sysctl -n {shlex.quote(k)}").stdout.strip()
                                      for k in spec["sysctl"]}
        if spec.get("selinux"):
            before.extra["selinux"] = transport.run("getenforce").stdout.strip()
        if "path_modes" in spec:
            before.extra["path_modes"] = transport.run(spec["path_modes"], sudo=True).stdout
        if "packages" in spec:
            before.extra["packages"] = {p: transport.run(f"rpm -q {shlex.quote(p)}").stdout.strip()
                                        for p in spec["packages"]}
        (dest / "before_state.json").write_text(
            __import__("json").dumps(before.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        return before

    def _capture_file(self, transport, path: str, into: Path) -> dict:
        st = parse.stat_lines(transport.run(f"stat -c '%a %U %G %n' {shlex.quote(path)}").stdout)
        if path not in st:
            return {"exists": False}
        mode, owner, grp = st[path]
        try:
            data = transport.read_file(path)
        except Exception:  # noqa: BLE001
            data = b""
        local = into / path.lstrip("/").replace("/", "__")
        local.write_bytes(data)
        return {"exists": True, "mode": mode, "owner": owner, "group": grp, "local": local.name}

    def _glob(self, transport, directory: str, pattern: str) -> list[str]:
        r = transport.run(f"find {shlex.quote(directory)} -maxdepth 1 -type f -name {shlex.quote(pattern)} 2>/dev/null")
        return [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]

    def _svc_pair(self, transport, unit: str) -> dict:
        return {"enabled": transport.run(f"systemctl is-enabled {shlex.quote(unit)}").stdout.strip(),
                "active": transport.run(f"systemctl is-active {shlex.quote(unit)}").stdout.strip()}

    def apply(self, target, transport, fix: FixEntry, finding, before: BeforeState) -> ApplyResult:
        if fix.kind == "runbook":
            return ApplyResult(ok=True, changed=False, output="runbook: operator performs the listed steps",
                               details={"kind": "runbook"})
        if fixes.fix_header_ref(fix.payload) != fix.fix_ref:
            return ApplyResult(ok=False, changed=False, output="payload header does not match fix_ref")
        token = re.sub(r"[^A-Za-z0-9]", "_", fix.fix_ref)[:40]
        script = f"{REMOTE_TMP}/ct-fix-{token}.sh"
        argv = [script]
        subject = self._subject(finding)
        # refuse a bad subject before anything is written to the target
        if fix.before_state.get("subject") and (subject is None or not fixes.valid_subject(
                fix.before_state["subject"], subject, tuple(fix.before_state.get("allow", ())))):
            return ApplyResult(ok=False, changed=False, output=f"refusing invalid subject {subject!r}")
        transport.write_file(script, fix.payload.encode("utf-8"), mode=0o700, sudo=True)
        if fix.before_state.get("subject"):
            argfile = f"{REMOTE_TMP}/ct-fix-{token}.arg"
            transport.write_file(argfile, (subject + "\n").encode("utf-8"), mode=0o600, sudo=True)
            argv.append(argfile)
        cmd = "bash " + " ".join(shlex.quote(a) for a in argv)
        r = transport.run(cmd, sudo=True, timeout=300)
        return ApplyResult(ok=r.ok, changed=r.ok, output=(r.stdout + r.stderr).strip(),
                           details={"exit": r.exit_code, "command": cmd})

    def verify(self, target, transport, fix: FixEntry, finding) -> VerifyResult:
        """Re-run the one check behind this finding and confirm it no longer fires, plus a health check.

        For a native fix the finding carries a STIG ID (rule_version); for a hunt fix the finding's own
        rule_id (hunt:linux:<check>:<subject>) names the check. A patch runbook has no automated re-check.
        """
        health = self.health_check(target, transport)
        rule_ids = self._verify_rule_ids(fix, finding)
        if not rule_ids:
            return VerifyResult(ok=health.ok, rule_passed=None, health=health,
                                evidence="no automated rule re-check for this fix; confirm the package version manually")
        findings = self._recheck(target, transport, rule_ids)
        matched = [f for f in findings if self._matches(f, rule_ids)]
        still_open = [f for f in matched if f.is_open]
        rule_passed = len(still_open) == 0
        ev = "; ".join(f.evidence or f.rule_id for f in matched) or "rule no longer reported (resolved)"
        return VerifyResult(ok=rule_passed and health.ok, rule_passed=rule_passed, health=health, evidence=ev,
                            details={"still_open": [f.rule_id for f in still_open]})

    def _verify_rule_ids(self, fix: FixEntry, finding) -> list[str]:
        if finding is not None and finding.source == "hunt":
            return [finding.rule_id]
        ids = list(fix.verify.get("rule_ids", []))
        if finding is not None and finding.rule_version and finding.rule_version not in ids:
            ids.append(finding.rule_version)
        return [i for i in ids if not i.startswith(hunt.PREFIX)]

    def _matches(self, f: Finding, rule_ids: list[str]) -> bool:
        if {f.rule_id, f.rule_version} & set(rule_ids):
            return True
        return any(r.startswith(hunt.PREFIX) and hunt.check_name(r) == hunt.check_name(f.rule_id)
                   and r.split(":", 3)[3:] == f.rule_id.split(":", 3)[3:] for r in rule_ids)

    def _recheck(self, target, transport, rule_ids: list[str]) -> list[Finding]:
        workdir = Path(self._scratch(target)) / "verify"
        hunt_ids = [r for r in rule_ids if r.startswith(hunt.PREFIX)]
        native_ids = [r for r in rule_ids if not r.startswith(hunt.PREFIX)]
        out: list[Finding] = []
        collected = self.collect(target, transport, workdir, modules=("check", "hunt"), rule_filter=rule_ids)
        if native_ids:
            out += checks.run_checks(target, collected)
        if hunt_ids:
            out += hunt.run_hunt(target, collected)
        return out

    def _scratch(self, target) -> str:
        import tempfile
        d = Path(tempfile.gettempdir()) / "cyberthunder-verify" / target.id
        d.mkdir(parents=True, exist_ok=True)
        return str(d)

    def health_check(self, target, transport) -> HealthResult:
        checks_out = []
        r = transport.run("true")
        checks_out.append(HealthCheck("transport", r.ok, "ran 'true'"))
        sshd = transport.run("systemctl is-active sshd")
        checks_out.append(HealthCheck("sshd_active", sshd.stdout.strip() == "active" or sshd.ok,
                                      f"is-active sshd: {sshd.stdout.strip() or sshd.stderr.strip()}"))
        sysr = transport.run("systemctl is-system-running")
        state = sysr.stdout.strip()
        checks_out.append(HealthCheck("system_running", state in ("running", "starting", "degraded"),
                                      f"is-system-running: {state or 'unknown'}"))
        return HealthResult(ok=all(c.ok for c in checks_out), checks=checks_out)

    def rollback(self, target, transport, fix: FixEntry, before: BeforeState) -> RollbackResult:
        if fix.kind == "runbook":
            return RollbackResult(ok=True, output="runbook: operator performs the rollback steps")
        notes = []
        meta = (before.extra or {}).get("files", {})
        files_dir = Path(before.dir) / "files"
        subject = (before.extra or {}).get("subject")
        for path, info in meta.items():
            if not info.get("exists"):
                # file did not exist before: a quarantine/disable fix moved it away, so it stays gone
                notes.append(f"{path}: was absent before, left as is")
                continue
            local = files_dir / info["local"]
            if fix.before_state.get("quarantine") and path == subject:
                # the fix moved the original into quarantine: move it back so content, mode, owner and
                # timestamps are exactly what they were, and no quarantine copy is left behind
                q = fixes.quarantine_path(path)
                mv = transport.run(f"mv -f -- {shlex.quote(q)} {shlex.quote(path)}", sudo=True)
                if mv.ok:
                    transport.run(f"chmod {info['mode']:o} {shlex.quote(path)}", sudo=True)
                    notes.append(f"moved {path} back from quarantine")
                    continue
                notes.append(f"{path}: quarantine copy not found ({mv.stderr.strip() or mv.stdout.strip()}), "
                             "restoring the captured copy")
            if local.exists():
                transport.write_file(path, local.read_bytes(), mode=info.get("mode"), sudo=True)
                transport.run(f"chmod {info['mode']:o} {shlex.quote(path)}", sudo=True)
                transport.run(f"chown {shlex.quote(info['owner'])}:{shlex.quote(info['group'])} {shlex.quote(path)}", sudo=True)
                notes.append(f"restored {path}")
        for unit, pair in (before.extra or {}).get("services", {}).items():
            self._restore_service(transport, unit, pair)
            notes.append(f"restored service {unit}")
        for key, val in (before.extra or {}).get("sysctl", {}).items():
            transport.run(f"sysctl -q -w {shlex.quote(key)}={shlex.quote(val)}", sudo=True)
            notes.append(f"restored sysctl {key}")
        if (before.extra or {}).get("selinux"):
            prev = before.extra["selinux"].lower()
            transport.run(f"setenforce {'1' if prev == 'enforcing' else '0'}", sudo=True)
            notes.append(f"restored SELinux to {before.extra['selinux']}")
        for svc in fix.restarts_services:
            transport.run(f"systemctl reload-or-restart {shlex.quote(svc)}", sudo=True)
            notes.append(f"reloaded {svc}")
        return RollbackResult(ok=True, output="; ".join(notes) or "nothing to restore",
                              details={"restored": len(meta)})

    def _restore_service(self, transport, unit: str, pair: dict) -> None:
        enabled, active = pair.get("enabled", ""), pair.get("active", "")
        if enabled == "masked":
            transport.run(f"systemctl mask {shlex.quote(unit)}", sudo=True)
            return
        transport.run(f"systemctl unmask {shlex.quote(unit)}", sudo=True)
        transport.run(f"systemctl {'enable' if enabled == 'enabled' else 'disable'} {shlex.quote(unit)}", sudo=True)
        transport.run(f"systemctl {'start' if active == 'active' else 'stop'} {shlex.quote(unit)}", sudo=True)

    # -- transports / simulation ---------------------------------------------------------------
    def make_transport(self, target, settings=None):
        if target.transport == "simulated":
            state_dir = Path(settings.state_dir) if settings else Path("state")
            return SimulatedLinuxHost(target.id, state_dir)
        return None

    def demo_targets(self):
        from cyberthunder.inventory.targets import Target
        return [Target(
            id="sim-linux-01", name=f"{HOSTNAME} (simulated)", asset_type="linux", transport="simulated",
            simulated=True, sudo=True, tags=["demo"],
            options={"expected_ports": [22], "critical_services": ["sshd"], "known_users": list(KNOWN_USERS),
                     "known_keys": [ADMIN_KEY_BLOB], "admin_users": ["root", "itadmin"]})]

    def reset_simulated(self, target, settings=None) -> bool:
        t = self.make_transport(target, settings)
        if isinstance(t, SimulatedLinuxHost):
            t.reset()
            return True
        return False
