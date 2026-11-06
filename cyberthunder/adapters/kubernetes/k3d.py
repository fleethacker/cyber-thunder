"""Opt-in local k3d server reads; no configurable executable, daemon, container or command."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from . import k3s


def guard(target):
    from cyberthunder.config import Settings
    from cyberthunder.control.killswitch import KillSwitch
    from cyberthunder.inventory.targets import Inventory

    settings = Settings.from_env()
    KillSwitch(settings.state_dir).guard("scan.k3d.read")
    current = Inventory.load(Path(settings.state_dir) / "targets.yaml").assert_in_scope(target.id)
    if current.to_dict() != target.to_dict() or not target.in_scope or target.transport != "kubeconfig":
        raise ValueError("k3d target scope or configuration changed")


def _docker(target, args: list[str]) -> str:
    guard(target)
    # Ignore DOCKER_HOST/context environment overrides: only the local default daemon.
    import os
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("DOCKER_")}
    try:
        result = subprocess.run(["docker", "--context", "default", *args], capture_output=True,
                                text=True, encoding="utf-8", errors="strict", timeout=30, env=env)
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        raise ValueError("local Docker command unavailable or timed out") from None
    if result.returncode:
        # Neither stderr nor raw inspect/config may be persisted (tokens can occur in either).
        raise ValueError("local Docker read failed")
    if len(result.stdout) > k3s.MAX_FILES * k3s.MAX_CONFIG:
        raise ValueError("local Docker response exceeds collection limit")
    return result.stdout


def collect(target, data) -> list[dict]:
    cluster = (target.options or {}).get("k3d_cluster")
    if not isinstance(cluster, str) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?", cluster):
        raise ValueError("invalid k3d_cluster (1-40 lowercase letters, digits or internal hyphens)")
    if target.transport != "kubeconfig" or not target.in_scope:
        raise ValueError("k3d collection requires an in-scope kubeconfig target")
    if (target.options or {}).get("node_target"):
        raise ValueError("configure either k3d_cluster or node_target")
    version = (data.doc("version") or {}).get("serverVersion", {}).get("gitVersion", "")
    if not isinstance(version, str) or "+k3s" not in version:
        raise ValueError("cluster API did not identify a k3s server")
    nodes = data.doc("nodes")
    if (not isinstance(nodes, dict) or not isinstance(nodes.get("items"), list)
            or (nodes.get("metadata") or {}).get("continue")):
        raise ValueError("complete cluster node list was not collected")
    names = []
    for node in data.items("nodes"):
        meta = node.get("metadata") or {}
        labels = meta.get("labels") or {}
        if not any(k in labels for k in ("node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master")):
            continue
        name = meta.get("name", "")
        if not re.fullmatch(re.escape(f"k3d-{cluster}-server-") + r"[0-9]{1,3}", name):
            raise ValueError("cluster control-plane node does not match k3d_cluster")
        names.append(name)
    if not names or len(names) > 16 or len(names) != len(set(names)):
        raise ValueError("no unique bounded k3d server node set was collected")
    out = []
    for name in sorted(names):
        try:
            records = json.loads(_docker(target, ["inspect", "--type", "container", name]))
            if not isinstance(records, list) or len(records) != 1:
                raise ValueError
            doc = records[0]
            labels = doc["Config"]["Labels"]
            cid = doc["Id"]
            if (doc["Name"] != "/" + name or labels.get("k3d.cluster") != cluster
                    or labels.get("k3d.role") != "server" or doc["State"]["Running"] is not True
                    or not re.fullmatch(r"[a-f0-9]{64}", cid)):
                raise ValueError
            env = doc["Config"].get("Env") or []
            if not isinstance(env, list) or any(not isinstance(e, str) for e in env):
                raise ValueError
            k3s.check_environment(env)
        except (KeyError, TypeError, ValueError, AttributeError):
            raise ValueError("Docker container identity, labels, state or environment did not validate") from None
        # Use the immutable inspected ID, never a user-supplied container identifier.
        argv = _docker(target, ["exec", cid, "cat", "/proc/1/cmdline"]).rstrip("\0").split("\0")
        if k3s.k3s_role(argv) != "server":
            raise ValueError("container PID 1 is not k3s server")
        k3s.check_environment(_docker(target, ["exec", cid, "cat", "/proc/1/environ"]).split("\0"))
        # Validate custom paths before any file collection.
        k3s.execstart_args(argv)
        bundle = _docker(target, ["exec", cid, "sh", "-c", k3s.READ_CONFIG])
        flags = k3s.effective_flags(None, None, files=k3s.config_bundle(bundle), argv=argv)
        flags.update(node=name, container_id=cid, cluster=cluster)
        out.append(flags)
    return out
