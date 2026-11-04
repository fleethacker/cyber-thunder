"""Simulated docker host for the offline demo and the tests.

Persisted to <state_dir>/simulated/<target_id>.json. Answers the docker subset the adapter uses:
version, info, ps, images, inspect, stop, start, update --restart. The seed matches
range/answer_key/containers.json (three misconfigurations, three intrusion indicators).
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import shlex
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cyberthunder.transport.base import CommandResult, Transport, TransportError

_LOCK = threading.Lock()
DAY = 86400


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f000Z")


def cid(name: str) -> str:
    return hashlib.sha256(f"ct-sim/{name}".encode()).hexdigest()


def _container(name, image, cmd, *, user="1000", privileged=False, binds=(), network="bridge", pid="", ipc="private",
               cap_add=None, readonly=True, memory=268435456, nano_cpus=500000000, ports=None, restart="unless-stopped",
               started_ago_s=20 * DAY, dynamic_start=False):
    mounts = []
    for b in binds:
        src, dst, *mode = b.split(":")
        mounts.append({"Type": "bind", "Source": src, "Destination": dst, "Mode": mode[0] if mode else "",
                       "RW": not (mode and "ro" in mode[0]), "Propagation": "rprivate"})
    port_bindings = {}
    for p in ports or []:
        host_ip, host_port, cport = p
        port_bindings[f"{cport}/tcp"] = [{"HostIp": host_ip, "HostPort": str(host_port)}]
    c = {
        "Id": cid(name), "Name": "/" + name, "Created": "2026-10-14T09:00:00.000000000Z",
        "Path": cmd[0], "Args": cmd[1:],
        "State": {"Status": "running", "Running": True, "Paused": False, "Restarting": False, "Pid": 4000 + len(name),
                  "ExitCode": 0, "StartedAt": "", "FinishedAt": "0001-01-01T00:00:00Z"},
        "Image": "sha256:" + hashlib.sha256(image.encode()).hexdigest(),
        "HostConfig": {"Binds": list(binds) or None, "NetworkMode": network, "PortBindings": port_bindings,
                       "RestartPolicy": {"Name": restart, "MaximumRetryCount": 0}, "CapAdd": cap_add, "CapDrop": None,
                       "IpcMode": ipc, "PidMode": pid, "Privileged": privileged, "ReadonlyRootfs": readonly,
                       "Memory": memory, "NanoCpus": nano_cpus, "CpuShares": 0, "CpuQuota": 0, "SecurityOpt": None},
        "Mounts": mounts,
        "Config": {"Hostname": name, "User": user, "Image": image, "Cmd": cmd, "Entrypoint": None,
                   "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"], "Labels": {}},
        "NetworkSettings": {"Ports": {k: v for k, v in port_bindings.items()}},
    }
    if dynamic_start:
        c["_started_ago_s"] = started_ago_s
    else:
        c["State"]["StartedAt"] = "2026-10-15T06:00:00.000000000Z"
    return c


def seed_containers() -> list[dict]:
    return [
        _container("web", "docker.io/library/nginx:1.25.3", ["nginx", "-g", "daemon off;"], user="101",
                   ports=[("0.0.0.0", 443, 443)], restart="always"),
        # M1 privileged
        _container("ops-agent", "registry.local/ops/agent:3.2", ["/usr/bin/ops-agent", "--interval", "60"], privileged=True),
        # M2 docker socket
        _container("ops-dashboard", "registry.local/ops/dashboard:1.4", ["/dashboard", "--port", "9000"],
                   binds=["/var/run/docker.sock:/var/run/docker.sock"]),
        # M3 host network
        _container("metrics-relay", "registry.local/ops/relay:2.0", ["/relay", "--listen", ":9100"], network="host"),
        # I1 cryptominer posing as a system service
        _container("systemd-update", "docker.io/xmrig/xmrig:6.21.0",
                   ["sh", "-c", "xmrig -o stratum+tcp://10.10.10.10:3333 -u enclave --donate-level 0 --background"],
                   user="", readonly=False, memory=0, nano_cpus=0, restart="always", started_ago_s=9 * DAY),
        # I2 host root filesystem mounted read-write
        _container("backup-agent", "registry.local/ops/backup:1.0", ["/usr/bin/backup", "--src", "/host/etc"],
                   binds=["/:/host"]),
        # I3 container started recently, not in the expected list, from an unknown registry
        _container("cache-sync", "203.0.113.50:5000/cache-sync:0.3", ["/usr/bin/cache-sync", "--peer", "203.0.113.50:7000"],
                   started_ago_s=2 * 3600, dynamic_start=True),
    ]


def seed_images() -> list[dict]:
    out = []
    for c in seed_containers():
        repo, _, tag = c["Config"]["Image"].rpartition(":")
        out.append({"Repository": repo, "Tag": tag, "ID": c["Image"][7:19], "CreatedSince": "3 weeks ago", "Size": "48.2MB"})
    return out


class SimulatedDockerHost:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.state: dict = {}

    def load(self) -> None:
        if self.path.exists():
            self.state = json.loads(self.path.read_text(encoding="utf-8"))
        else:
            self.reset()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, indent=1, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.path)

    def reset(self) -> None:
        self.state = {"engine": "docker", "version": "24.0.9", "containers": seed_containers(), "images": seed_images()}
        self.save()

    def find(self, ref: str) -> dict | None:
        for c in self.state["containers"]:
            if c["Id"] == ref or (len(ref) >= 12 and c["Id"].startswith(ref)) or c["Name"].lstrip("/") == ref:
                return c
        return None

    @staticmethod
    def render(c: dict) -> dict:
        o = copy.deepcopy(c)
        ago = o.pop("_started_ago_s", None)
        if ago is not None:
            o["State"]["StartedAt"] = _iso(_now() - timedelta(seconds=ago))
        return o

    def handle(self, argv: list[str]) -> tuple[int, str, str]:
        if not argv:
            return 127, "", "empty command"
        if argv[:2] == ["command", "-v"]:
            return (0, "/usr/bin/docker\n", "") if argv[2:] == ["docker"] else (1, "", "")
        if argv[0] != "docker":
            return 127, "", f"sh: {argv[0]}: command not found"
        verb, rest = (argv[1] if len(argv) > 1 else ""), argv[2:]
        if verb == "version":
            return 0, json.dumps({"Client": {"Version": self.state["version"]},
                                  "Server": {"Version": self.state["version"], "Os": "linux", "Arch": "amd64"}}), ""
        if verb == "info":
            running = sum(1 for c in self.state["containers"] if c["State"]["Running"])
            return 0, json.dumps({"ServerVersion": self.state["version"], "Containers": len(self.state["containers"]),
                                  "ContainersRunning": running, "OperatingSystem": "Rocky Linux 9.4 (Blue Onyx)",
                                  "Name": "rocky-01", "SecurityOptions": ["name=seccomp,profile=builtin", "name=selinux"],
                                  "LiveRestoreEnabled": False}), ""
        if verb == "ps":
            lines = []
            for c in self.state["containers"]:
                if "-a" not in rest and not c["State"]["Running"]:
                    continue
                r = self.render(c)
                ports = ", ".join(f"{b['HostIp'] or '0.0.0.0'}:{b['HostPort']}->{k}"
                                  for k, v in (r["HostConfig"]["PortBindings"] or {}).items() for b in v)
                lines.append(json.dumps({"ID": r["Id"] if "--no-trunc" in rest else r["Id"][:12],
                                         "Names": r["Name"].lstrip("/"), "Image": r["Config"]["Image"],
                                         "Command": json.dumps(" ".join([r["Path"], *r["Args"]])),
                                         "CreatedAt": r["Created"], "State": r["State"]["Status"],
                                         "Status": "Up" if r["State"]["Running"] else "Exited (0)", "Ports": ports}))
            return 0, "\n".join(lines) + ("\n" if lines else ""), ""
        if verb == "images":
            return 0, "\n".join(json.dumps(i) for i in self.state["images"]) + "\n", ""
        if verb == "inspect":
            ids = [a for a in rest if not a.startswith("-")]
            out, missing = [], []
            for i in ids:
                c = self.find(i)
                (out.append(self.render(c)) if c else missing.append(i))
            if missing:
                return 1, json.dumps(out, indent=2), f"Error: No such object: {missing[0]}"
            return 0, json.dumps(out, indent=2), ""
        if verb in ("stop", "start"):
            outs = []
            for i in [a for a in rest if not a.startswith("-")]:
                c = self.find(i)
                if c is None:
                    return 1, "", f"Error response from daemon: No such container: {i}"
                c.pop("_started_ago_s", None)
                if verb == "stop":
                    c["State"].update({"Status": "exited", "Running": False, "Pid": 0, "FinishedAt": _iso(_now())})
                else:
                    c["State"].update({"Status": "running", "Running": True, "Pid": 5000 + len(c["Name"]),
                                       "StartedAt": _iso(_now())})
                outs.append(i)
            return 0, "\n".join(outs) + "\n", ""
        if verb == "update":
            policy, ids = None, []
            it = iter(rest)
            for a in it:
                if a.startswith("--restart="):
                    policy = a.split("=", 1)[1]
                elif a == "--restart":
                    policy = next(it, None)
                elif not a.startswith("-"):
                    ids.append(a)
            if not policy or not ids:
                return 1, "", "docker update: --restart=<policy> and a container are required"
            name, _, count = policy.partition(":")
            if name not in ("no", "always", "unless-stopped", "on-failure"):
                return 1, "", f"invalid restart policy {policy!r}"
            for i in ids:
                c = self.find(i)
                if c is None:
                    return 1, "", f"Error response from daemon: No such container: {i}"
                c["HostConfig"]["RestartPolicy"] = {"Name": name, "MaximumRetryCount": int(count or 0)}
            return 0, "\n".join(ids) + "\n", ""
        return 127, "", f"simulated docker host: unsupported command {' '.join(argv)!r}"


class SimulatedDockerTransport(Transport):
    """Transport kind 'simulated' for the containers adapter."""
    kind = "simulated"

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.calls: list[str] = []

    def host(self) -> SimulatedDockerHost:
        h = SimulatedDockerHost(self.path)
        h.load()
        return h

    def reset(self) -> None:
        with _LOCK:
            SimulatedDockerHost(self.path).reset()

    def run(self, command: str, *, timeout: int = 120, sudo: bool = False) -> CommandResult:
        self.calls.append(command)
        try:
            argv = shlex.split(command, posix=True)
        except ValueError as e:
            return CommandResult(command, 2, "", f"cannot parse command: {e}")
        with _LOCK:
            h = self.host()
            before = json.dumps(h.state, sort_keys=True)
            code, out, err = h.handle(argv)
            if json.dumps(h.state, sort_keys=True) != before:
                h.save()
        return CommandResult(command, code, out, err)

    def read_file(self, path: str) -> bytes:
        raise TransportError("simulated docker host has no file access")

    def write_file(self, path: str, data: bytes, *, mode: int | None = None, sudo: bool = False) -> None:
        raise TransportError("simulated docker host has no file access")
