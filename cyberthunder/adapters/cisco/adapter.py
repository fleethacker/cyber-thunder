"""Cisco IOS / IOS-XE adapter: STIG checks and intrusion hunt on the running-config, config-snippet fixes.

Modes
  file       a saved running-config on disk (options.config_path)
  simulated  the demo switch under <state_dir>/simulated/<target_id>.cfg
  fixture    recorded 'show' output (tests, replay of a live session)
  ssh        a live device through its interactive shell. Changes are pushed only when
             options.allow_push is true; otherwise apply() hands back the exact steps for the Sailor
             at the console and changes nothing.

Before every change the full running-config is saved. Rollback writes it back (file, simulated, fixture)
or, on a live device, runs 'configure replace <options.archive_path> force' when an archive is available
and otherwise pushes the computed inverse lines.

Target options used here (all optional):
  config_path, seed_config, allow_push, archive (run 'archive config' before a change), archive_path,
  known_users, known_syslog, known_tunnels, known_next_hops, known_applets, role (switch|router),
  stig_families, plus the organization-defined values listed in rules.resolve_options().
"""
from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import Iterable

from cyberthunder.adapters.base import MODULES, Adapter, AssetFacts, Collected, make_finding, register
from cyberthunder.findings.schema import Finding
from cyberthunder.inventory.targets import Target
from cyberthunder.remediation.library import FixEntry
from cyberthunder.remediation.models import (ApplyResult, BeforeState, HealthCheck, HealthResult, RollbackResult,
                                             VerifyResult)
from cyberthunder.transport.base import Transport, TransportError

from .hunt import HuntHit, hunt_config
from .parser import ConfigModel, parse_config, split_lines
from .rules import Rule, evaluate, families_for, load_rules, resolve_options, rules_by_id
from .snippet import apply_snippet, inverse_snippet, snippet_lines, unified_diff
from .transports import (DEFAULT_SEED, REPO_ROOT, CLI_ERROR_RE, ConfigFileTransport, SimulatedTransport,
                         open_cli, strip_show_output)

log = logging.getLogger(__name__)

ASSET_TYPE = "cisco_ios"
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
ARCHIVE_PATH_RE = re.compile(r"^[A-Za-z0-9_.\-:/]+$")
CONFIG_ARTIFACT = "running_config"

# Lines that never belong in a configuration snippet. A FixEntry carrying one is refused outright.
FORBIDDEN_PREFIXES = ("do ", "tclsh", "reload", "delete ", "erase ", "format ", "copy ", "write erase",
                      "debug ", "crypto key zeroize", "event manager run", "send ", "configure replace",
                      "more ", "test ", "request ")

HUNT_RUNBOOKS = {
    "unknown_user": ("Remove an unexpected local account",
                     ["Confirm with the system owner that the account is not authorized.",
                      "configure terminal / no username <name> / end / write memory",
                      "Check AAA accounting and 'show logging' for logins by that account."]),
    "snmp_community": ("Remove a default or read-write SNMP community",
                       ["configure terminal / no snmp-server community <name> / end / write memory",
                        "Move monitoring to SNMPv3 priv (CISC-ND-001140)."]),
    "http_server": ("Disable the HTTP management server",
                    ["configure terminal / no ip http server / end / write memory"]),
    "eem_applet": ("Remove a suspicious EEM applet",
                   ["Save 'show running-config | section event manager' as evidence.",
                    "configure terminal / no event manager applet <name> / end / write memory"]),
    "kron": ("Remove a suspicious kron schedule",
             ["configure terminal / no kron occurrence <name> / no kron policy-list <name> / end / write memory"]),
    "tunnel": ("Remove an unexpected tunnel interface",
               ["Confirm the tunnel is not an approved link.",
                "configure terminal / no interface <TunnelN> / end / write memory"]),
    "static_route": ("Remove a static route to an unexpected next hop",
                     ["configure terminal / no ip route <prefix> <mask> <next-hop> / end / write memory"]),
    "log_host": ("Stop sending logs to an unknown collector",
                 ["configure terminal / no logging host <address> / end / write memory"]),
    "logging_disabled": ("Re-enable device logging",
                         ["configure terminal / logging on / logging trap informational / end / write memory"]),
    "acl_permit_any": ("Remove a permit-any entry from a boundary ACL",
                       ["Review the ACL with the boundary owner.",
                        "configure terminal / ip access-list extended <name> / no permit ip any any / end"]),
    "telnet_vty": ("Allow SSH only on vty lines",
                   ["Confirm SSH works (crypto key present, ip ssh version 2) before removing telnet.",
                    "configure terminal / line vty <range> / transport input ssh / end / write memory"]),
}


def _sha(text: str | bytes) -> str:
    data = text.encode("utf-8") if isinstance(text, str) else text
    return hashlib.sha256(data).hexdigest()


def runbook_steps(payload: str) -> list[str]:
    """The same change as keystrokes for a Sailor at the console."""
    return ["configure terminal", *snippet_lines(payload), "end", "write memory"]


def validate_payload(payload: str) -> None:
    for raw in split_lines(payload):
        line = raw.strip().lower()
        if any(ch for ch in raw if ord(ch) < 32 and ch != "\t"):
            raise ValueError("snippet contains control characters")
        if any(line.startswith(p) for p in FORBIDDEN_PREFIXES):
            raise ValueError(f"snippet line is not a configuration command: {raw.strip()!r}")


def _is_live(transport: Transport) -> bool:
    return hasattr(transport, "open_shell") and not isinstance(transport, ConfigFileTransport)


@register
class CiscoIOSAdapter(Adapter):
    asset_type = ASSET_TYPE
    display_name = "Cisco IOS / IOS-XE"
    transports = ("ssh", "fixture")
    own_transports = ("file", "simulated")

    def __init__(self) -> None:
        self._dynamic: dict[str, FixEntry] = {}

    # == transports ================================================================================
    @staticmethod
    def _state_dir(settings=None) -> Path:
        if settings is None:
            from cyberthunder.config import Settings
            settings = Settings.from_env()
        return Path(settings.state_dir)

    @staticmethod
    def _seed(target: Target) -> Path:
        s = target.options.get("seed_config")
        if not s:
            return DEFAULT_SEED
        p = Path(s)
        return p if p.is_absolute() else REPO_ROOT / p

    def _sim_path(self, target: Target, settings=None) -> Path:
        if not SAFE_NAME_RE.match(target.id or ""):
            raise TransportError(f"target id {target.id!r} cannot be used as a file name")
        return self._state_dir(settings) / "simulated" / f"{target.id}.cfg"

    def make_transport(self, target: Target, settings=None) -> Transport | None:
        if target.transport == "file":
            path = target.options.get("config_path")
            if not path:
                raise TransportError(f"target {target.id}: file transport needs options.config_path")
            return ConfigFileTransport(path)
        if target.transport == "simulated":
            return SimulatedTransport(self._sim_path(target, settings), seed=self._seed(target))
        return None

    def reset_simulated(self, target: Target, settings=None) -> bool:
        if target.transport != "simulated":
            return False
        SimulatedTransport(self._sim_path(target, settings), seed=self._seed(target)).reset()
        return True

    def demo_targets(self) -> list[Target]:
        return [Target(id="sim-switch-01", name="swi-01 (simulated)", asset_type=ASSET_TYPE, transport="simulated",
                       simulated=True, sudo=False, tags=["demo", "switch"],
                       options={"known_users": ["admin"], "known_syslog": ["10.1.1.5"], "allow_push": False,
                                "log_servers": ["10.1.1.5", "10.1.2.5"],
                                "ntp_servers": ["10.1.1.10", "10.1.2.10"],
                                "aaa_servers": ["10.1.1.20", "10.1.2.20"]},
                       notes="Emulated Catalyst access switch seeded from range/cisco/seeded_switch.cfg")]

    # == config access =============================================================================
    def read_config(self, target: Target, transport: Transport) -> str:
        if isinstance(transport, ConfigFileTransport):
            return transport.read_config()
        if _is_live(transport):
            cli = open_cli(transport)
            try:
                return strip_show_output(cli.show("show running-config", timeout=120))
            finally:
                cli.close()
        if transport.kind == "fixture":
            try:
                data = transport.read_file("running-config")
                return data.decode("utf-8")
            except TransportError:
                pass
        r = transport.run("show running-config", timeout=120)
        if not r.ok:
            raise TransportError(f"show running-config failed on {target.id}: {r.stderr.strip() or r.exit_code}")
        return strip_show_output(r.stdout)

    def _write_config(self, transport: Transport, text: str) -> None:
        if isinstance(transport, ConfigFileTransport):
            transport.write_config(text)
        else:
            transport.write_file("running-config", text.encode("utf-8"))

    def _show(self, transport: Transport, command: str) -> str | None:
        try:
            if _is_live(transport):
                cli = open_cli(transport)
                try:
                    return cli.show(command)
                finally:
                    cli.close()
            r = transport.run(command)
            return r.stdout if r.ok else None
        except TransportError:
            return None

    # == discovery / collection ====================================================================
    def _facts(self, target: Target, model: ConfigModel, show_version: str | None) -> AssetFacts:
        f = AssetFacts(hostname=model.hostname, os_name="Cisco IOS XE", os_version=model.version)
        if show_version:
            m = re.search(r"Version\s+([\w.()]+)", show_version)
            if m:
                f.os_version = m.group(1)
            if "IOS XE" not in show_version and "IOS-XE" not in show_version and "Cisco IOS" in show_version:
                f.os_name = "Cisco IOS"
            mm = re.search(r"Model [Nn]umber\s*:\s*(\S+)", show_version) or \
                re.search(r"^[Cc]isco\s+(\S+)\s+\(.*\)\s+processor", show_version, re.M)
            if mm:
                f.model = mm.group(1)
        f.addresses = [i.ip_address for i in model.interfaces.values() if i.ip_address]
        opts = resolve_options(target.options)
        f.extra = {"families": list(families_for(model, opts)), "interfaces": len(model.interfaces),
                   "role": "switch" if "L2S" in families_for(model, opts) else "router"}
        return f

    def discover(self, target: Target, transport: Transport) -> AssetFacts:
        model = parse_config(self.read_config(target, transport))
        return self._facts(target, model, self._show(transport, "show version"))

    def collect(self, target: Target, transport: Transport, workdir: Path, *,
                modules: Iterable[str] = MODULES, rule_filter: list[str] | None = None) -> Collected:
        workdir = Path(workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        c = Collected(target_id=target.id, asset_type=ASSET_TYPE, workdir=str(workdir), modules=list(modules),
                      rule_filter=rule_filter)
        try:
            text = self.read_config(target, transport)
        except TransportError as e:
            c.errors.append(f"collect: {e}")
            return c
        path = workdir / "running-config.txt"
        with path.open("w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        c.artifacts[CONFIG_ARTIFACT] = str(path)
        sv = self._show(transport, "show version") if (_is_live(transport) or transport.kind == "fixture") else None
        if sv:
            c.raw["show_version"] = sv[:4000]
        model = parse_config(text)
        c.facts = self._facts(target, model, sv)
        c.raw["config_sha256"] = _sha(text)
        return c

    @staticmethod
    def _load(collected: Collected) -> ConfigModel | None:
        p = collected.path(CONFIG_ARTIFACT)
        if p is None or not p.exists():
            return None
        with p.open("r", encoding="utf-8", newline="") as fh:
            return parse_config(fh.read())

    # == detection =================================================================================
    def check(self, target: Target, collected: Collected) -> list[Finding]:
        model = self._load(collected)
        if model is None:
            return []
        out = []
        for rule, passed, evidence in evaluate(model, target.options, collected.rule_filter):
            status = "open" if passed is False else ("not_a_finding" if passed else "not_reviewed")
            fix_ref = None
            if passed is False:
                fix_ref = self._register(self._rule_entry(target, rule, model)).fix_ref
            bench, release = rule.benchmark
            out.append(make_finding(
                target=target, source=ASSET_TYPE, rule_id=rule.rule_id or rule.stig_id, rule_version=rule.stig_id,
                group_id=rule.group_id, title=rule.title, severity=rule.severity, status=status,
                description=rule.check_summary + ("" if rule.confirmed else " (rule text not confirmed against "
                                                                             "the DISA XCCDF)"),
                evidence=evidence, references=[rule.stig_id, *rule.cci], fix_ref=fix_ref,
                check_text=rule.check_summary, fix_text=rule.fix_summary, benchmark=bench,
                benchmark_release=release, tags=[rule.family, f"disruption:{rule.disruption}"],
                raw_ref=collected.artifacts.get(CONFIG_ARTIFACT), collected_at=collected.collected_at))
        return out

    def hunt(self, target: Target, collected: Collected) -> list[Finding]:
        model = self._load(collected)
        if model is None:
            return []
        out = []
        flt = set(collected.rule_filter or [])
        for hit in hunt_config(model, target.options):
            if flt and hit.rule_id not in flt and hit.check_id not in flt:
                continue
            entry = self._register(self._hunt_entry(target, hit))
            out.append(make_finding(
                target=target, source="hunt", rule_id=hit.rule_id, rule_version=hit.check_id, title=hit.title,
                severity=hit.severity, status="open", description=hit.description, evidence=hit.evidence,
                references=hit.attack, fix_ref=entry.fix_ref, benchmark="Cyber Thunder Cisco config hunt",
                tags=["hunt", hit.check], raw_ref=collected.artifacts.get(CONFIG_ARTIFACT),
                collected_at=collected.collected_at))
        return out

    # == fix library ===============================================================================
    def _register(self, entry: FixEntry) -> FixEntry:
        if not entry.fix_ref.startswith("cisco:rule:") and not entry.fix_ref.startswith("hunt:cisco:"):
            self._dynamic[entry.fix_ref] = entry
        return entry

    @staticmethod
    def _rollback_steps(inverse: str) -> list[str]:
        steps = ["Offline (file/simulated): the saved pre-change running-config is written back unchanged.",
                 "Live with options.archive_path: configure replace <archive_path> force.",
                 "Live without an archive: push the inverse lines below, then write memory."]
        return steps + ([f"  {x}" for x in inverse.split("\n")] if inverse else [])

    def _rule_entry(self, target: Target | None, rule: Rule, model: ConfigModel) -> FixEntry:
        opts = target.options if target else {}
        if rule.static_fix:
            return self._static_rule_entry(rule)
        lines = rule.fix_lines(model, opts)
        ref = f"cisco:{target.id}:{rule.stig_id}" if target else f"cisco:rule:{rule.stig_id}"
        common = dict(fix_ref=ref, title=f"{rule.stig_id}: {rule.title}", asset_type=ASSET_TYPE, applies_to=[ref],
                      disruption=rule.disruption, rollback_kind="config_replace",
                      before_state={"commands": {"running_config": "show running-config"}},
                      verify={"rule_ids": [rule.stig_id]}, citations=rule.citations, source="cisco")
        if not lines:
            return FixEntry(kind="runbook", steps=[rule.fix_summary or rule.title,
                                                   "The organization-defined values this fix needs are not set in "
                                                   "the target options (see rules.resolve_options); configure by "
                                                   "hand, then rescan."],
                            rollback_steps=["Restore the saved pre-change running-config."], **common)
        payload = "\n".join(lines)
        inverse = inverse_snippet(model.text, apply_snippet(model.text, payload))
        return FixEntry(kind="config_snippet", payload=payload, rollback_steps=self._rollback_steps(inverse),
                        notes=self._runbook_note(payload), **common)

    @staticmethod
    def _runbook_note(payload: str) -> str:
        return ("Where push is not allowed (options.allow_push false) these steps are produced for the console "
                "instead of being applied: " + " / ".join(runbook_steps(payload)))

    def _static_rule_entry(self, rule: Rule) -> FixEntry:
        ref = f"cisco:rule:{rule.stig_id}"
        common = dict(fix_ref=ref, title=f"{rule.stig_id}: {rule.title}", asset_type=ASSET_TYPE,
                      applies_to=[rule.stig_id, rule.rule_id, rule.group_id], disruption=rule.disruption,
                      rollback_kind="config_replace", before_state={"commands": {"running_config": "show running-config"}},
                      verify={"rule_ids": [rule.stig_id]}, citations=rule.citations, source="cisco")
        if rule.static_fix:
            payload = rule.fix_snippet(parse_config(""), {})
            return FixEntry(kind="config_snippet", payload=payload,
                            rollback_steps=self._rollback_steps(""), notes=self._runbook_note(payload), **common)
        return FixEntry(kind="runbook",
                        steps=[rule.fix_summary or rule.title,
                               "Scan the device: the scan produces a device-specific snippet for this rule "
                               f"(fix_ref cisco:<target>:{rule.stig_id}) that can be approved and applied."],
                        rollback_steps=["Restore the saved pre-change running-config."], **common)

    def _hunt_entry(self, target: Target, hit: HuntHit) -> FixEntry:
        if not hit.remove_lines:
            return self._hunt_runbook(hit.check)
        ref = f"cisco:{target.id}:{hit.rule_id}"
        payload = "\n".join(hit.remove_lines)
        return FixEntry(fix_ref=ref, title=f"{hit.title}: remove", asset_type=ASSET_TYPE, applies_to=[ref],
                        kind="config_snippet", payload=payload, disruption=hit.disruption,
                        rollback_kind="config_replace",
                        rollback_steps=["Restore the saved pre-change running-config (this re-creates the "
                                        "indicator; only roll back if removal broke something approved)."],
                        before_state={"commands": {"running_config": "show running-config"}},
                        verify={"rule_ids": [hit.rule_id]}, citations=list(hit.attack), source="hunt",
                        notes=self._runbook_note(payload))

    @staticmethod
    def _hunt_runbook(check: str) -> FixEntry:
        title, steps = HUNT_RUNBOOKS.get(check, (f"Investigate {check}", ["Investigate and remove by hand."]))
        return FixEntry(fix_ref=f"hunt:cisco:{check}", title=title, asset_type=ASSET_TYPE,
                        applies_to=[f"hunt:cisco:{check}"], kind="runbook", steps=steps, disruption="medium",
                        rollback_kind="manual", rollback_steps=["Restore the saved pre-change running-config."],
                        before_state={"commands": {"running_config": "show running-config"}},
                        verify={"rule_ids": [f"hunt:cisco:{check}"]}, source="hunt")

    def fixes_for(self, target: Target, collected: Collected) -> list[FixEntry]:
        """Device-specific entries for one collected config (also kept for fixes()). For the scanner to add
        to the library after a scan, so the fix_ref on each finding resolves."""
        model = self._load(collected)
        if model is None:
            return []
        out = []
        for rule, passed, _ in evaluate(model, target.options):
            if passed is False:
                out.append(self._register(self._rule_entry(target, rule, model)))
        for hit in hunt_config(model, target.options):
            out.append(self._register(self._hunt_entry(target, hit)))
        return out

    def _entries_for_text(self, target: Target, text: str) -> list[FixEntry]:
        model = parse_config(text)
        out = [self._rule_entry(target, r, model) for r, p, _ in evaluate(model, target.options) if p is False]
        out += [self._hunt_entry(target, h) for h in hunt_config(model, target.options)]
        return out

    def fixes(self) -> list[FixEntry]:
        out: dict[str, FixEntry] = {}
        for rule in load_rules():
            e = self._static_rule_entry(rule)
            out[e.fix_ref] = e
        for check in HUNT_RUNBOOKS:
            e = self._hunt_runbook(check)
            out[e.fix_ref] = e
        for t in self.demo_targets():          # so the demo's findings resolve before the first scan
            try:
                text = self._seed(t).read_text(encoding="utf-8")
            except OSError:
                continue
            for e in self._entries_for_text(t, text):
                out.setdefault(e.fix_ref, e)
        for ref, e in self._dynamic.items():
            out[ref] = e
        return list(out.values())

    # == remediation ===============================================================================
    def capture_before_state(self, target: Target, transport: Transport, fix: FixEntry, finding: Finding,
                             dest: Path) -> BeforeState:
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        text = self.read_config(target, transport)
        with (dest / "running-config.txt").open("w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        notes = []
        archive_out = None
        if _is_live(transport) and target.options.get("archive"):
            cli = open_cli(transport)
            try:
                archive_out = cli.send("archive config")
            finally:
                cli.close()
            notes.append("archive config taken on the device")
        after = apply_snippet(text, fix.payload) if fix.payload else text
        inverse = inverse_snippet(text, after) if fix.payload else ""
        (dest / "rollback-snippet.txt").write_text(inverse + ("\n" if inverse else ""), encoding="utf-8")
        planned = unified_diff(text, after)
        (dest / "planned.diff").write_text(planned, encoding="utf-8")
        return BeforeState(target_id=target.id, fix_ref=fix.fix_ref, dir=str(dest), files=["running-config"],
                           commands={"running_config": "running-config.txt"}, notes="; ".join(notes),
                           extra={"sha256": _sha(text), "mode": transport.kind, "rollback_snippet": inverse,
                                  "archive_path": target.options.get("archive_path"),
                                  "archive_output": archive_out, "planned_diff": planned})

    def _push(self, transport: Transport, payload: str) -> tuple[bool, str]:
        """Type the snippet in configuration mode. Saves with write memory only if every line was accepted."""
        cli = open_cli(transport)
        transcript: list[str] = []
        errors: list[str] = []
        try:
            transcript.append(cli.send("configure terminal"))
            in_banner = False
            delim = ""
            for raw in snippet_lines(payload):
                line = raw
                if not in_banner and raw.strip().startswith("banner "):
                    parts = raw.strip().split(None, 2)
                    rest = parts[2] if len(parts) > 2 else ""
                    delim = "^C" if rest.startswith("^C") else rest[:1]
                    body = rest[len(delim):]
                    line = raw.replace("^C", "^") if delim == "^C" else raw
                    if delim and delim not in body:
                        in_banner = True
                        transcript.append(cli.send(line, expect_prompt=False))
                        continue
                elif in_banner:
                    closing = delim in raw
                    line = raw.replace("^C", "^") if delim == "^C" else raw
                    out = cli.send(line, expect_prompt=closing)
                    transcript.append(out)
                    if closing:
                        in_banner = False
                    continue
                out = cli.send(line)
                transcript.append(out)
                if CLI_ERROR_RE.search(out):
                    errors.append(f"{line.strip()}: {out.strip()}")
            transcript.append(cli.send("end"))
            if not errors:
                transcript.append(cli.send("write memory", timeout=120))
        finally:
            cli.close()
        text = "\n".join(x for x in transcript if x)
        if errors:
            return False, "device rejected: " + " | ".join(errors) + "\n" + text
        return True, text

    def apply(self, target: Target, transport: Transport, fix: FixEntry, finding: Finding,
              before: BeforeState) -> ApplyResult:
        if fix.asset_type != ASSET_TYPE:
            return ApplyResult(ok=False, changed=False, output=f"fix {fix.fix_ref} is not a Cisco fix")
        if fix.kind != "config_snippet" or not fix.payload.strip():
            return ApplyResult(ok=False, changed=False, output="manual fix: follow the steps",
                               details={"mode": "runbook", "steps": list(fix.steps)})
        try:
            validate_payload(fix.payload)
        except ValueError as e:
            return ApplyResult(ok=False, changed=False, output=f"refused: {e}")
        if _is_live(transport):
            if not target.options.get("allow_push"):
                steps = runbook_steps(fix.payload)
                return ApplyResult(ok=False, changed=False,
                                   output="Push is not allowed for this device (options.allow_push is false). "
                                          "Enter these lines at the console, then rescan:\n" + "\n".join(steps),
                                   details={"mode": "runbook", "steps": steps})
            ok, out = self._push(transport, fix.payload)
            return ApplyResult(ok=ok, changed=True, output=out, details={"mode": "ssh"})
        text = self.read_config(target, transport)
        new = apply_snippet(text, fix.payload)
        if new != text:
            self._write_config(transport, new)
        diff = unified_diff(text, new)
        return ApplyResult(ok=True, changed=new != text, output=diff or "no change: already compliant",
                           details={"mode": transport.kind, "diff": diff, "sha256_before": _sha(text),
                                    "sha256_after": _sha(new)})

    def _rule_passes(self, rid: str, model: ConfigModel, opts: dict) -> tuple[bool | None, str]:
        if rid.startswith("hunt:cisco:"):
            hits = [h for h in hunt_config(model, opts) if h.rule_id == rid or h.check_id == rid]
            return (not hits), ("; ".join(h.evidence for h in hits) if hits else f"{rid}: indicator no longer present")
        rules = rules_by_id()
        rule = rules.get(rid) or next((r for r in rules.values() if rid in (r.rule_id, r.group_id)), None)
        if rule is None:
            return None, f"unknown rule {rid}"
        passed, ev = rule.check(model, opts)
        return passed, f"{rule.stig_id}: {ev}"

    def verify(self, target: Target, transport: Transport, fix: FixEntry, finding: Finding) -> VerifyResult:
        health = self.health_check(target, transport)
        try:
            model = parse_config(self.read_config(target, transport))
        except TransportError as e:
            return VerifyResult(ok=False, rule_passed=None, health=health, evidence=f"cannot read config: {e}")
        ids = list(fix.verify.get("rule_ids") or []) or [finding.rule_version or finding.rule_id]
        results = [self._rule_passes(r, model, target.options) for r in ids]
        if any(p is None for p, _ in results):
            rule_passed = None
        else:
            rule_passed = all(p for p, _ in results)
        return VerifyResult(ok=bool(rule_passed) and health.ok, rule_passed=rule_passed, health=health,
                            evidence="\n".join(e for _, e in results), details={"rule_ids": ids})

    def health_check(self, target: Target, transport: Transport) -> HealthResult:
        checks: list[HealthCheck] = []
        try:
            text = self.read_config(target, transport)
            model = parse_config(text)
            ok = bool(model.hostname) and len(model.global_lines) >= 5
            checks.append(HealthCheck("config_parses", ok, f"hostname {model.hostname}, "
                                                           f"{len(model.global_lines)} global lines"))
        except Exception as e:  # noqa: BLE001
            checks.append(HealthCheck("config_parses", False, str(e)))
        if _is_live(transport):
            out = self._show(transport, "show clock")
            checks.append(HealthCheck("cli_responds", bool(out and out.strip()), (out or "no response").strip()[:80]))
        return HealthResult(ok=all(c.ok for c in checks), checks=checks)

    def rollback(self, target: Target, transport: Transport, fix: FixEntry, before: BeforeState) -> RollbackResult:
        saved = Path(before.dir) / before.commands.get("running_config", "running-config.txt")
        if not saved.exists():
            return RollbackResult(ok=False, output=f"before-state missing: {saved}")
        data = saved.read_bytes()
        if not _is_live(transport):
            transport.write_file("running-config", data)
            now = self.read_config(target, transport).encode("utf-8")
            ok = _sha(now) == _sha(data)
            return RollbackResult(ok=ok, output="pre-change running-config restored" if ok else
                                  "restored text does not match the saved copy",
                                  details={"mode": transport.kind, "sha256": _sha(data)})
        if not target.options.get("allow_push"):
            inverse = before.extra.get("rollback_snippet") or ""
            steps = ["configure terminal", *snippet_lines(inverse), "end", "write memory"]
            return RollbackResult(ok=False, output="Push is not allowed; enter these lines at the console:\n"
                                  + "\n".join(steps), details={"mode": "runbook", "steps": steps})
        archive = target.options.get("archive_path") or before.extra.get("archive_path")
        if archive:
            if not ARCHIVE_PATH_RE.match(str(archive)) or ".." in str(archive):
                return RollbackResult(ok=False, output=f"refused: archive path {archive!r} is not a plain device path",
                                      details={"mode": "configure_replace"})
            cli = open_cli(transport)
            try:
                out = cli.send(f"configure replace {archive} force", timeout=180)
            finally:
                cli.close()
            ok = not CLI_ERROR_RE.search(out) and "rollback done" in out.lower()
            return RollbackResult(ok=bool(ok), output=out, details={"mode": "configure_replace", "archive": archive})
        inverse = before.extra.get("rollback_snippet") or ""
        if not inverse:
            return RollbackResult(ok=True, output="nothing to undo", details={"mode": "ssh"})
        try:
            validate_payload(inverse)
        except ValueError as e:
            return RollbackResult(ok=False, output=f"refused inverse lines: {e}; restore the saved "
                                  f"running-config by hand from {saved}", details={"mode": "ssh_inverse"})
        ok, out = self._push(transport, inverse)
        return RollbackResult(ok=ok, output=out, details={"mode": "ssh_inverse"})
