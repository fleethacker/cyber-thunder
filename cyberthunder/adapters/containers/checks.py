"""Container host checks from `docker inspect` (or podman). Pure functions of the collected JSON.

There is no DISA STIG for a generic docker/podman host, so findings cite CIS Docker Benchmark v1.6
sections as "CIS-Docker-<n>" plus CCI-000366 (configuration settings) unless a better CCI is obvious.

Only active containers are evaluated: running, or set to restart automatically (they come back after a
reboot). A container that was stopped and had its restart policy set to 'no' is no longer a risk on this
host, which is also how the stop-and-disable fix is verified.

  rule_id      containers:<base>:<container name>
  rule_version CIS-Docker-<n> or containers:<local rule>   (the fix library keys on this)
  tags         container:<name>, container-id:<id>
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Iterable, Iterator

from cyberthunder.adapters.base import Collected, make_finding
from cyberthunder.findings.schema import Finding

from .images import registry_allowed, uses_latest_or_untagged

SOURCE = "containers"
NAME_TAG = "container:"
ID_TAG = "container-id:"
RE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
RE_ID = re.compile(r"^[0-9a-f]{12,64}$")

ENGINE_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock", "/var/run/podman/podman.sock", "/run/podman/podman.sock",
                  "/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock")
HUNT_HOST_DIRS = ("/", "/etc", "/root")          # reported by the hunt module (T1611)
SENSITIVE_DIRS = ("/boot", "/dev", "/lib", "/proc", "/sys", "/usr", "/var/lib/docker", "/var/lib/containers")
DANGEROUS_CAPS = ("SYS_ADMIN", "ALL", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH")


@dataclass
class Rule:
    base: str
    title: str
    severity: str
    refs: list[str]
    description: str
    benchmark: str = "CIS Docker Benchmark v1.6"


def cis(section: str, title: str, severity: str, why: str, refs: Iterable[str] = ("CCI-000366",)) -> Rule:
    return Rule(base=f"CIS-Docker-{section}", title=title, severity=severity, refs=[f"CIS-Docker-{section}", *refs],
                description=f"CIS Docker Benchmark v1.6 section {section}. {why} No DISA STIG covers a generic "
                            "container host, so this cites the CIS section and the configuration-settings CCI.")


RULES = {
    "privileged": cis("5.4", "Privileged container", "high",
                      "--privileged gives the container every capability and the host's devices."),
    "socket": cis("5.31", "Container engine socket mounted into a container", "high",
                  "Whoever controls the engine socket controls every container and, through them, the host."),
    "sensitive": cis("5.5", "Sensitive host directory mounted", "medium",
                     "Host system directories mounted into a container can be read or changed from inside it."),
    "hostnet": cis("5.9", "Container shares the host network namespace", "medium",
                   "--network host bypasses container network isolation and exposes host-local services."),
    "hostpid": cis("5.15", "Container shares the host PID namespace", "high",
                   "--pid host lets the container see and signal every host process."),
    "hostipc": cis("5.16", "Container shares the host IPC namespace", "medium",
                   "--ipc host exposes host shared memory to the container."),
    "caps": cis("5.3", "Dangerous Linux capability added", "high",
                "SYS_ADMIN, NET_ADMIN and similar capabilities are close to root on the host."),
    "readonly": cis("5.12", "Root filesystem is writable", "low",
                    "A read-only root filesystem stops an intruder from changing binaries inside the container."),
    "root": cis("4.1", "Container runs as root", "medium",
                "No USER is set, so the process runs as root inside the container and a breakout lands as root."),
    "limits": cis("5.10", "No memory or CPU limit", "low",
                  "Without limits one container can exhaust the host (denial of service).",
                  refs=("CIS-Docker-5.11", "CCI-002385")),
    "ports": cis("5.13", "Port published on all host interfaces", "medium",
                 "A port bound to 0.0.0.0 that is not on the host's expected list is reachable from every network "
                 "the host is on."),
    "restart": cis("5.14", "Unknown image set to restart always", "info",
                   "An image from an unapproved registry that restarts automatically will survive reboots."),
    "latest": Rule(base="containers:ct:image-latest", title="Image uses :latest or no tag", severity="low",
                   refs=["CCI-000366"], benchmark="Cyber Thunder container checks",
                   description="A mutable tag means the running code can change on the next pull without review. "
                               "No CIS Docker section covers this exactly; cited against CCI-000366."),
}


@dataclass
class Container:
    id: str
    name: str
    image: str
    inspect: dict

    @property
    def host_config(self) -> dict:
        return self.inspect.get("HostConfig") or {}

    @property
    def config(self) -> dict:
        return self.inspect.get("Config") or {}

    @property
    def running(self) -> bool:
        return bool((self.inspect.get("State") or {}).get("Running"))

    @property
    def restart_policy(self) -> str:
        return ((self.host_config.get("RestartPolicy") or {}).get("Name") or "no")

    @property
    def active(self) -> bool:
        return self.running or self.restart_policy in ("always", "unless-stopped")

    @property
    def command(self) -> str:
        parts = [self.inspect.get("Path") or "", *(self.inspect.get("Args") or [])]
        return " ".join(str(p) for p in parts if p)

    def mount_sources(self) -> list[str]:
        srcs = [m.get("Source", "") for m in self.inspect.get("Mounts") or [] if m.get("Type", "bind") == "bind"]
        for b in self.host_config.get("Binds") or []:
            s = b.split(":", 1)[0]
            if s.startswith("/") and s not in srcs:
                srcs.append(s)
        return srcs


def load_containers(collected: Collected) -> list[Container]:
    p = collected.path("inspect")
    if not p or not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        collected.errors.append("inspect: not JSON")
        return []
    out = []
    for d in data if isinstance(data, list) else []:
        name = (d.get("Name") or "").lstrip("/")
        cid = d.get("Id") or ""
        if not RE_NAME.match(name) or not RE_ID.match(cid):
            collected.errors.append(f"inspect: skipped container with unexpected name/id {name!r}")
            continue
        out.append(Container(cid, name, (d.get("Config") or {}).get("Image") or d.get("ImageName") or "", d))
    return out


def active_containers(collected: Collected) -> Iterator[Container]:
    for c in load_containers(collected):
        if c.active:
            yield c


def finding(target, rule: Rule, c: Container, evidence: str, *, source: str = SOURCE, tags: Iterable[str] = (),
            collected_at: str | None = None) -> Finding:
    base = rule.base if rule.base.startswith("containers:") else f"containers:cis:{rule.base.split('-')[-1]}"
    return make_finding(target=target, source=source, rule_id=f"{base}:{c.name}", title=f"{rule.title}: {c.name}",
                        severity=rule.severity, description=rule.description, evidence=evidence,
                        references=rule.refs, rule_version=rule.base, benchmark=rule.benchmark,
                        tags=["containers", NAME_TAG + c.name, ID_TAG + c.id, *tags], collected_at=collected_at)


def run_checks(target, collected: Collected) -> list[Finding]:
    opts = target.options or {}
    expected_ports = {str(p) for p in opts.get("expected_ports") or []}
    allowed = list(opts.get("allowed_registries") or [])
    out: list[Finding] = []
    for c in active_containers(collected):
        hc, cfg = c.host_config, c.config
        where = f"{c.name} ({c.image})"
        if hc.get("Privileged"):
            out.append(finding(target, RULES["privileged"], c, f"{where}: HostConfig.Privileged=true"))
        srcs = c.mount_sources()
        socks = [s for s in srcs if s in ENGINE_SOCKETS]
        if socks:
            out.append(finding(target, RULES["socket"], c, f"{where}: bind mount {', '.join(socks)}"))
        sens = [s for s in srcs if s not in HUNT_HOST_DIRS and any(s == d or s.startswith(d + "/") for d in SENSITIVE_DIRS)]
        if sens:
            out.append(finding(target, RULES["sensitive"], c, f"{where}: bind mount {', '.join(sens)}"))
        if hc.get("NetworkMode") == "host":
            out.append(finding(target, RULES["hostnet"], c, f"{where}: NetworkMode=host"))
        if hc.get("PidMode") == "host":
            out.append(finding(target, RULES["hostpid"], c, f"{where}: PidMode=host"))
        if hc.get("IpcMode") == "host":
            out.append(finding(target, RULES["hostipc"], c, f"{where}: IpcMode=host"))
        caps = [x.upper().removeprefix("CAP_") for x in hc.get("CapAdd") or []]
        bad_caps = [x for x in caps if x in DANGEROUS_CAPS]
        if bad_caps:
            out.append(finding(target, RULES["caps"], c, f"{where}: CapAdd {', '.join(bad_caps)}"))
        if not hc.get("ReadonlyRootfs"):
            out.append(finding(target, RULES["readonly"], c, f"{where}: ReadonlyRootfs=false"))
        user = str(cfg.get("User") or "")
        if user in ("", "root", "0") or user.startswith("0:") or user.startswith("root:"):
            out.append(finding(target, RULES["root"], c, f"{where}: Config.User={user or 'unset'}"))
        if not hc.get("Memory") or not (hc.get("NanoCpus") or hc.get("CpuQuota") or hc.get("CpuShares")):
            out.append(finding(target, RULES["limits"], c, f"{where}: Memory={hc.get('Memory') or 0}, "
                                                            f"NanoCpus={hc.get('NanoCpus') or 0}"))
        if c.image and uses_latest_or_untagged(c.image):
            out.append(finding(target, RULES["latest"], c, f"{where}: image tag is latest or missing"))
        open_ports = []
        for cport, binds in (hc.get("PortBindings") or {}).items():
            for b in binds or []:
                if (b.get("HostIp") or "0.0.0.0") in ("0.0.0.0", "::", "") and str(b.get("HostPort")) not in expected_ports:
                    open_ports.append(f"0.0.0.0:{b.get('HostPort')}->{cport}")
        if open_ports:
            out.append(finding(target, RULES["ports"], c, f"{where}: {', '.join(open_ports)}"))
        if allowed and c.restart_policy == "always" and c.image and not registry_allowed(c.image, allowed):
            out.append(finding(target, RULES["restart"], c, f"{where}: restart=always, registry not approved"))
    for f in out:
        f.collected_at = collected.collected_at
    return out
