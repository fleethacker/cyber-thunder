"""Control-plane flags on k3s, read from the server node.

k3s runs the API server, controller manager and kubelet inside the k3s process, so they never show up as
kube-system pods and the API cannot report their flags. When a kubernetes target names its k3s server node
(options.node_target, an inventory linux target id), the adapter reads two things over that node's
transport, both read-only:

  cat /etc/rancher/k3s/config.yaml                           (sudo; the file is 0600 root)
  systemctl show k3s --property=ExecStart --value            (the k3s server command line)

Only the per-component argument lists are kept (kube-apiserver-arg, kube-controller-manager-arg,
kubelet-arg). Everything else in the file, the join token in particular, is dropped before anything is
written to disk. Precedence is the one k3s uses: k3s built-in defaults, then the config file, then the
command line. Drop-in files under /etc/rancher/k3s/config.yaml.d/ are not read.
"""
from __future__ import annotations

import re
import shlex

CONFIG_PATH = "/etc/rancher/k3s/config.yaml"
READ_CONFIG = f"cat {CONFIG_PATH}"
READ_EXECSTART = "systemctl show k3s --property=ExecStart --value"

COMPONENTS = {"kube-apiserver-arg": "kube-apiserver", "kube-controller-manager-arg": "kube-controller-manager",
              "kubelet-arg": "kubelet"}

# Flags k3s sets on its embedded components when the operator does not (k3s CIS self-assessment guide).
# Anything not listed here is unset, which is how an absent --audit-log-path is detected.
K3S_DEFAULTS = {
    "kube-apiserver": {"anonymous-auth": "false", "authorization-mode": "Node,RBAC", "profiling": "false"},
    "kube-controller-manager": {"use-service-account-credentials": "true", "profiling": "false"},
    "kubelet": {"anonymous-auth": "false", "read-only-port": "0", "authorization-mode": "Webhook"},
}

RE_ARGV = re.compile(r"argv\[\]=(.*?)\s;\s")


def _kv(arg: str) -> tuple[str, str] | None:
    a = str(arg).strip().lstrip("-")
    if not a:
        return None
    k, _, v = a.partition("=")
    return k.strip(), (v.strip() if _ else "true")


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    return [str(v)]


def config_args(text: str) -> dict[str, list[str]]:
    """Component argument lists from config.yaml text. Raises ValueError when the text is not a YAML mapping."""
    import yaml
    try:
        doc = yaml.safe_load(text or "") or {}
    except yaml.YAMLError as e:
        raise ValueError(f"{CONFIG_PATH} is not valid YAML: {e}") from None
    if not isinstance(doc, dict):
        raise ValueError(f"{CONFIG_PATH} is not a YAML mapping")
    out: dict[str, list[str]] = {}
    for key, val in doc.items():
        comp = COMPONENTS.get(str(key).rstrip("+"))
        if comp:
            out.setdefault(comp, []).extend(_as_list(val))
    return out


def execstart_argv(text: str) -> list[str]:
    """argv of the k3s unit from 'systemctl show --property=ExecStart --value' (or a bare command line)."""
    t = (text or "").strip()
    if not t:
        return []
    m = RE_ARGV.search(t + " ; ")
    line = m.group(1) if m else t
    try:
        return shlex.split(line)
    except ValueError:
        return line.split()


def execstart_args(argv: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    i = 0
    while i < len(argv):
        a = argv[i]
        name, eq, val = a.lstrip("-").partition("=")
        comp = COMPONENTS.get(name) if a.startswith("--") else None
        if comp:
            if not eq and i + 1 < len(argv):
                val = argv[i + 1]
                i += 1
            out.setdefault(comp, []).append(val)
        i += 1
    return out


def k3s_role(argv: list[str]) -> str | None:
    for a in argv[1:]:
        if a in ("server", "agent"):
            return a
    return None


def effective_flags(config_text: str | None, execstart_text: str | None) -> dict:
    """{"role": server|agent|None, "sources": [...], "<component>": {flag: value}} for each component."""
    argv = execstart_argv(execstart_text or "")
    role = k3s_role(argv)
    layers: list[dict[str, list[str]]] = []
    sources: list[str] = []
    if config_text is not None:
        layers.append(config_args(config_text))
        sources.append(CONFIG_PATH)
    if argv:
        layers.append(execstart_args(argv))
        sources.append("k3s.service ExecStart")
    out: dict = {"role": role, "sources": sources}
    for comp, defaults in K3S_DEFAULTS.items():
        if role == "agent" and comp != "kubelet":
            continue
        flags = dict(defaults)
        for layer in layers:
            for arg in layer.get(comp, []):
                kv = _kv(arg)
                if kv:
                    flags[kv[0]] = kv[1]
        out[comp] = flags
    return out
