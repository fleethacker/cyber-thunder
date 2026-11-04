"""Vetted container-host remediations.

stop-and-disable is the only fix the tool runs: it sets the restart policy to 'no' and stops the container.
Before that it saves `docker inspect`; rollback restores the saved restart policy and starts the container
again if it was running. <id> is filled from the finding's validated container id and nothing else.

Configuration problems (privileged, socket mounts, host namespaces ...) can only be fixed by re-creating the
container with different flags, which loses its writable layer, so those are runbooks. When the runbook is
"applied" the adapter reads `docker inspect` and prints the exact corrected `docker run` command and the
compose change for the operator; it does not run them.
"""
from __future__ import annotations

import shlex

from cyberthunder.remediation.library import FixEntry

from .checks import ENGINE_SOCKETS, HUNT_HOST_DIRS, RULES, SENSITIVE_DIRS, DANGEROUS_CAPS
from .hunt import HUNT_RULES

ASSET = "containers"
RESTART_POLICIES = ("no", "always", "unless-stopped", "on-failure")

STOP_APPLIES = ["containers:hunt:host-escape", "containers:hunt:miner", "containers:hunt:suspicious-command",
                "containers:hunt:unexpected-container", "containers:hunt:privileged-hostnet",
                "containers:hunt:untrusted-registry"]

# runbook fix_ref -> (correction key, compose snippet)
RECREATE: dict[str, tuple[str, str]] = {}


def _recreate(key: str, rule, title: str, compose: str) -> FixEntry:
    fix_ref = f"containers:runbook:recreate-{key}"
    RECREATE[fix_ref] = (key, compose)
    return FixEntry(
        fix_ref=fix_ref, title=title, asset_type=ASSET, applies_to=[rule.base], kind="runbook",
        steps=["Save the current definition: docker inspect <name> > <name>.inspect.json",
               "Confirm with the system owner that the container can be re-created (its writable layer is lost; "
               "data on volumes is kept).",
               "docker stop <name> && docker rename <name> <name>-old",
               "Start the replacement with the corrected command printed when this runbook is applied "
               "(generated from docker inspect).",
               f"If the container is managed by compose, change the service instead: {compose}",
               "Check the service works, then remove the old container: docker rm <name>-old. Re-run the scan."],
        disruption="medium", restarts_services=["container <name> (re-created)"], rollback_kind="manual",
        rollback_steps=["docker stop <name> && docker rm <name>", "docker rename <name>-old <name> && docker start <name>",
                        "Re-run the scan."],
        verify={"rule_ids": [rule.base]}, citations=list(rule.refs), source="containers")


def container_fixes() -> list[FixEntry]:
    RECREATE.clear()
    stop = FixEntry(
        fix_ref="containers:fix:stop-and-disable", title="Stop the container and disable its restart policy",
        asset_type=ASSET, applies_to=STOP_APPLIES, kind="script",
        payload="docker update --restart=no <id>\ndocker stop <id>",
        disruption="medium", restarts_services=[], rollback_kind="command",
        rollback_steps=["docker update --restart=<saved policy> <id>", "docker start <id>  (only if it was running)"],
        before_state={"commands": {"inspect": "docker inspect <id>"}}, verify={"rule_ids": STOP_APPLIES},
        citations=[r for k in ("escape", "miner", "command", "unexpected", "registry") for r in HUNT_RULES[k].refs],
        source="hunt",
        notes="The container and its filesystem are kept for forensics (docker export / docker diff). Nothing is "
              "deleted; whatever service it provided stops.")
    return [
        stop,
        _recreate("privileged", RULES["privileged"], "Re-create the container without --privileged",
                  "remove 'privileged: true'; add only the device or capability it needs (devices: / cap_add:)"),
        _recreate("engine-socket", RULES["socket"], "Re-create the container without the engine socket mount",
                  "remove the '/var/run/docker.sock' entry from volumes:"),
        _recreate("sensitive-mount", RULES["sensitive"], "Re-create the container without sensitive host mounts",
                  "remove host system directories from volumes:, or mount the narrowest path with ':ro'"),
        _recreate("host-network", RULES["hostnet"], "Re-create the container on a bridge network",
                  "remove 'network_mode: host' and publish only the needed ports under ports:"),
        _recreate("host-pid", RULES["hostpid"], "Re-create the container without the host PID namespace",
                  "remove 'pid: host'"),
        _recreate("host-ipc", RULES["hostipc"], "Re-create the container without the host IPC namespace",
                  "remove 'ipc: host'"),
        _recreate("capabilities", RULES["caps"], "Re-create the container without dangerous capabilities",
                  "remove SYS_ADMIN/NET_ADMIN/ALL from cap_add: and add 'cap_drop: [ALL]'"),
        _recreate("read-only", RULES["readonly"], "Re-create the container with a read-only root filesystem",
                  "add 'read_only: true' and a tmpfs: entry for any path the app writes to"),
        _recreate("non-root", RULES["root"], "Re-create the container as a non-root user",
                  "add 'user: \"10001:10001\"' (or the image's unprivileged user)"),
        _recreate("limits", RULES["limits"], "Re-create the container with memory and CPU limits",
                  "add 'mem_limit: 512m' and 'cpus: 1.0' (size from docker stats)"),
        _recreate("bind-interface", RULES["ports"], "Publish the port on a specific interface",
                  "change '- \"PORT:PORT\"' to '- \"<host address>:PORT:PORT\"' under ports:"),
        _recreate("pin-image", RULES["latest"], "Pin the image to a version or digest",
                  "change image: to the exact tag or @sha256 digest mirrored into the enclave registry"),
    ]


def corrected_run(inspect: dict, key: str, engine: str = "docker") -> str:
    """The `docker run` command that re-creates this container with the problem corrected.

    Built only from docker inspect fields; every value is shell-quoted. For the operator to review and run."""
    hc, cfg = inspect.get("HostConfig") or {}, inspect.get("Config") or {}
    name = (inspect.get("Name") or "").lstrip("/")
    q = shlex.quote
    args = [engine, "run", "-d", "--name", q(name)]
    rp = (hc.get("RestartPolicy") or {}).get("Name") or "no"
    if rp in RESTART_POLICIES and rp != "no":
        args += ["--restart", rp]
    if hc.get("Privileged") and key != "privileged":
        args.append("--privileged")
    net = hc.get("NetworkMode") or "default"
    if net not in ("default", "bridge") and not (net == "host" and key == "host-network"):
        args += ["--network", q(net)]
    if hc.get("PidMode") == "host" and key != "host-pid":
        args += ["--pid", "host"]
    if hc.get("IpcMode") == "host" and key != "host-ipc":
        args += ["--ipc", "host"]
    for cap in hc.get("CapAdd") or []:
        if key == "capabilities" and cap.upper().removeprefix("CAP_") in DANGEROUS_CAPS:
            continue
        args += ["--cap-add", q(cap)]
    if key == "capabilities":
        args += ["--cap-drop", "ALL"]
    user = str(cfg.get("User") or "")
    if key == "non-root":
        args += ["--user", "10001:10001"]
    elif user:
        args += ["--user", q(user)]
    if hc.get("ReadonlyRootfs") or key == "read-only":
        args.append("--read-only")
    if key == "limits":
        args += ["--memory", q(str(hc["Memory"])) if hc.get("Memory") else "512m",
                 "--cpus", q(f"{hc['NanoCpus'] / 1e9:g}") if hc.get("NanoCpus") else "1.0"]
    else:
        if hc.get("Memory"):
            args += ["--memory", q(str(hc["Memory"]))]
        if hc.get("NanoCpus"):
            args += ["--cpus", q(f"{hc['NanoCpus'] / 1e9:g}")]
    if not (net == "host" and key != "host-network"):
        for cport, binds in (hc.get("PortBindings") or {}).items():
            for b in binds or []:
                ip = b.get("HostIp") or ""
                if key == "bind-interface" and ip in ("", "0.0.0.0", "::"):
                    ip = "127.0.0.1"
                hp = f"{ip}:{b.get('HostPort')}" if ip else str(b.get("HostPort"))
                args += ["-p", q(f"{hp}:{cport.split('/')[0]}")]
    for m in inspect.get("Mounts") or []:
        src, dst = m.get("Source", ""), m.get("Destination", "")
        if m.get("Type") == "volume":
            args += ["-v", q(f"{m.get('Name')}:{dst}")]
            continue
        if key == "engine-socket" and src in ENGINE_SOCKETS:
            continue
        if key == "sensitive-mount" and (src in HUNT_HOST_DIRS or any(src == d or src.startswith(d + "/") for d in SENSITIVE_DIRS)):
            continue
        args += ["-v", q(f"{src}:{dst}" + ("" if m.get("RW", True) else ":ro"))]
    for e in cfg.get("Env") or []:
        if not e.startswith("PATH="):
            args += ["-e", q(e)]
    image = cfg.get("Image") or ""
    args.append(q(image))
    cmd = list(cfg.get("Cmd") or [])
    if cfg.get("Entrypoint"):
        args[-1:-1] = ["--entrypoint", q(cfg["Entrypoint"][0])]
        cmd = list(cfg["Entrypoint"][1:]) + cmd
    args += [q(str(c)) for c in cmd]
    line = " ".join(args)
    if key == "pin-image":
        line += "\n# replace the image reference above with an exact version or @sha256 digest from the enclave registry"
    return line
