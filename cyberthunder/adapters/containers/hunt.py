"""Container host intrusion indicators. Every finding cites a MITRE ATT&CK technique.

  containers:hunt:host-escape           container mounts /, /etc or /root from the host           T1611
  containers:hunt:untrusted-registry    image from a registry not in options.allowed_registries     T1525
  containers:hunt:miner                 command line of a cryptominer                               T1496
  containers:hunt:suspicious-command    downloader / reverse shell / 'sh -c' command line          T1059.004
  containers:hunt:unexpected-container  started in the last 24 h and not in options.expected_containers  T1610
  containers:hunt:privileged-hostnet    privileged and on the host network at the same time        T1611
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from cyberthunder.adapters.base import Collected
from cyberthunder.findings.schema import Finding

from .checks import HUNT_HOST_DIRS, Rule, active_containers, finding
from .images import registry_allowed

SOURCE = "hunt"
RE_MINER = re.compile(r"\b(xmrig|minerd|cpuminer|xmr-stak|ethminer|nbminer)\b|stratum\+tcp://", re.I)
RE_SUSPICIOUS = re.compile(r"\b(nc|ncat|curl|wget|socat)\b|\b(sh|bash|ash|dash)\s+-c\b|/dev/tcp/")


def _rule(base: str, title: str, severity: str, technique: str, why: str) -> Rule:
    return Rule(base=f"containers:hunt:{base}", title=title, severity=severity, refs=[technique],
                description=f"ATT&CK {technique}. {why}", benchmark="Cyber Thunder hunt")


HUNT_RULES = {
    "escape": _rule("host-escape", "Container mounts the host filesystem", "high", "T1611",
                    "With the host's /, /etc or /root mounted, a process in the container can edit host accounts, "
                    "keys and services (escape to host)."),
    "registry": _rule("untrusted-registry", "Image from an unapproved registry", "high", "T1525",
                      "Only images mirrored into the enclave's approved registries should run (implant internal image)."),
    "miner": _rule("miner", "Cryptominer running in a container", "high", "T1496",
                   "The command line matches a known cryptocurrency miner (resource hijacking)."),
    "command": _rule("suspicious-command", "Container runs a downloader or shell one-liner", "medium", "T1059.004",
                     "curl/wget/nc or an 'sh -c' one-liner as the container command is typical of a dropped implant "
                     "(command and scripting interpreter: Unix shell)."),
    "unexpected": _rule("unexpected-container", "Recently started container not on the expected list", "high", "T1610",
                        "A container started in the last 24 hours that the host owner did not list (deploy container)."),
    "privnet": _rule("privileged-hostnet", "Privileged container on the host network", "high", "T1611",
                     "Privileged plus host networking is full control of the host's devices and interfaces "
                     "(escape to host)."),
}


def _parse_time(s: str) -> datetime | None:
    if not s or s.startswith("0001-"):
        return None
    s = s.strip().replace("Z", "+00:00")
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(.*)$", s)
    if not m:
        return None
    frac = (m.group(2) or "")[:7]
    try:
        return datetime.fromisoformat(m.group(1) + frac + (m.group(3) or "+00:00"))
    except ValueError:
        return None


def run_hunt(target, collected: Collected, now: datetime | None = None) -> list[Finding]:
    opts = target.options or {}
    allowed = list(opts.get("allowed_registries") or [])
    expected = opts.get("expected_containers")
    now = now or datetime.now(timezone.utc)
    out: list[Finding] = []
    for c in active_containers(collected):
        where = f"{c.name} ({c.image})"
        tag = lambda t: [f"attack:{t}"]  # noqa: E731
        escape = [s for s in c.mount_sources() if s.rstrip("/") in {d.rstrip("/") for d in HUNT_HOST_DIRS}]
        if escape:
            out.append(finding(target, HUNT_RULES["escape"], c, f"{where}: host path(s) {', '.join(escape)} mounted",
                               source=SOURCE, tags=tag("T1611")))
        if allowed and c.image and not registry_allowed(c.image, allowed):
            out.append(finding(target, HUNT_RULES["registry"], c, f"{where}: registry not in {', '.join(allowed)}",
                               source=SOURCE, tags=tag("T1525")))
        cmd = c.command
        if RE_MINER.search(cmd):
            out.append(finding(target, HUNT_RULES["miner"], c, f"{where}: {cmd[:300]}", source=SOURCE, tags=tag("T1496")))
        elif RE_SUSPICIOUS.search(cmd):
            out.append(finding(target, HUNT_RULES["command"], c, f"{where}: {cmd[:300]}", source=SOURCE,
                               tags=tag("T1059.004")))
        if expected is not None and c.name not in expected:
            started = _parse_time((c.inspect.get("State") or {}).get("StartedAt", ""))
            if started and now - started < timedelta(hours=24):
                hours = (now - started).total_seconds() / 3600
                out.append(finding(target, HUNT_RULES["unexpected"], c,
                                   f"{where}: started {hours:.1f} h ago, not in expected_containers",
                                   source=SOURCE, tags=tag("T1610")))
        if c.host_config.get("Privileged") and c.host_config.get("NetworkMode") == "host":
            out.append(finding(target, HUNT_RULES["privnet"], c, f"{where}: Privileged=true and NetworkMode=host",
                               source=SOURCE, tags=tag("T1611")))
    for f in out:
        f.collected_at = collected.collected_at
    return out
