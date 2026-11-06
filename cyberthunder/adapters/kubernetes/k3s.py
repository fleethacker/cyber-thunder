"""Read-only k3s configuration parsing. Never persist the raw config or join token."""
from __future__ import annotations

import re
import shlex

CONFIG_PATH = "/etc/rancher/k3s/config.yaml"
MAX_CONFIG = 1024 * 1024
MAX_FILES = 128
# A fixed script, with no target-supplied text. NUL frames preserve YAML newlines.
# Missing files are distinct from unreadable files. Never follow config symlinks.
READ_CONFIG = r'''set -eu
export LC_ALL=C
for d in /etc /etc/rancher /etc/rancher/k3s /etc/rancher/k3s/config.yaml.d; do
    if [ -e "$d" ] || [ -L "$d" ]; then
        [ -d "$d" ] && [ -r "$d" ] && [ -x "$d" ] && [ ! -L "$d" ] || exit 1
    fi
done
printf 'CT_K3S_CONFIG_V1\000'
n=0
for f in /etc/rancher/k3s/config.yaml /etc/rancher/k3s/config.yaml.d/*.yaml /etc/rancher/k3s/config.yaml.d/.yaml /etc/rancher/k3s/config.yaml.d/.*.yaml; do
    if [ ! -e "$f" ] && [ ! -L "$f" ]; then continue; fi
    n=$((n + 1))
    [ "$n" -le 128 ] && [ -f "$f" ] && [ -r "$f" ] && [ ! -L "$f" ] || exit 1
    [ "$(wc -c < "$f")" -le 1048576 ] || exit 1
    printf '%s\000' "$f"
    cat "$f" || exit 1
    printf '\000'
done
printf 'CT_END\000'
'''
READ_EXECSTART = "systemctl show k3s --property=ExecStart --value"
READ_ENVIRONMENT = "systemctl show k3s --property=Environment --property=EnvironmentFiles --value"

COMPONENTS = {"kube-apiserver-arg": "kube-apiserver", "kube-controller-manager-arg": "kube-controller-manager",
              "kubelet-arg": "kubelet"}
K3S_DEFAULTS = {
    "kube-apiserver": {"anonymous-auth": "false", "authorization-mode": "Node,RBAC", "profiling": "false"},
    "kube-controller-manager": {"use-service-account-credentials": "true", "profiling": "false"},
    "kubelet": {"anonymous-auth": "false", "read-only-port": "0", "authorization-mode": "Webhook"},
}
RE_ARGV = re.compile(r"argv\[\]=(.*?)\s;\s")


def config_bundle(text: str) -> list[tuple[str, str]]:
    parts = text.split("\0")
    if (len(text) > MAX_CONFIG * MAX_FILES or parts[0] != "CT_K3S_CONFIG_V1"
            or parts[-2:] != ["CT_END", ""] or len(parts[1:-2]) % 2):
        raise ValueError("incomplete k3s configuration collection")
    files = list(zip(parts[1:-2:2], parts[2:-2:2]))
    if len(files) > MAX_FILES or len({p for p, _ in files}) != len(files):
        raise ValueError("invalid k3s configuration file count")
    for path, body in files:
        if path != CONFIG_PATH and not re.fullmatch(re.escape(CONFIG_PATH) + r"\.d/[^/\x00-\x1f]*\.yaml", path):
            raise ValueError("unexpected k3s configuration path")
        if len(body.encode()) > MAX_CONFIG:
            raise ValueError("k3s configuration file is too large")
    return sorted(files, key=lambda item: item[0].encode())


def _config(text: str) -> dict:
    import yaml

    class UniqueLoader(yaml.SafeLoader):
        pass

    def mapping(loader, node):
        out = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node)
            if not isinstance(key, str) or key in out:
                raise ValueError("duplicate or non-string k3s configuration key")
            out[key] = loader.construct_object(value_node)
        return out

    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try:
        doc = yaml.load(text or "", Loader=UniqueLoader)
    except (yaml.YAMLError, RecursionError, TypeError):
        # YAML diagnostics can contain the join token. Never include source snippets.
        raise ValueError("invalid k3s configuration YAML") from None
    if doc is None:
        return {}
    if not isinstance(doc, dict):
        raise ValueError("k3s configuration is not a YAML mapping")
    if any(key in doc and key + "+" in doc for key in COMPONENTS):
        raise ValueError("ambiguous replace/append keys in one k3s configuration file")
    if "config" in doc or "config+" in doc:
        raise ValueError("custom k3s configuration paths are unsupported")
    if any(key.removesuffix("+") in ("disable-apiserver", "disable-controller-manager", "disable-agent") for key in doc):
        raise ValueError("disabled k3s components require manual review")
    return doc


def _args(value) -> list[str]:
    values = value if isinstance(value, list) else [value]
    if any(not isinstance(v, str) or not v.strip() or len(v) > 4096 for v in values):
        raise ValueError("invalid k3s component argument list")
    return values


def config_args(text: str) -> dict[str, list[str]]:
    return _merge_config([(CONFIG_PATH, text)])


def _merge_config(files: list[tuple[str, str]]) -> dict[str, list[str]]:
    merged = {}
    for _, text in sorted(files, key=lambda item: item[0].encode()):
        for key, value in _config(text).items():
            comp = COMPONENTS.get(key.removesuffix("+"))
            if comp:
                args = _args(value)
                merged[comp] = merged.get(comp, []) + args if key.endswith("+") else args
    return merged


def execstart_argv(text: str) -> list[str]:
    match = RE_ARGV.search(text.strip() + " ; ")
    try:
        return shlex.split(match.group(1) if match else text.strip())
    except ValueError:
        raise ValueError("invalid k3s command line") from None


def execstart_args(argv: list[str]) -> dict[str, list[str]]:
    out = {}
    i = 0
    while i < len(argv):
        arg = argv[i]
        name, eq, val = arg.partition("=")
        if name in ("--config", "-c") or (arg.startswith("-c") and not arg.startswith("--")):
            raise ValueError("custom k3s configuration paths are unsupported")
        if name in ("--disable-apiserver", "--disable-controller-manager", "--disable-agent"):
            raise ValueError("disabled k3s components require manual review")
        comp = COMPONENTS.get(name[2:]) if name.startswith("--") else None
        if comp:
            if not eq:
                i += 1
                if i >= len(argv) or argv[i].startswith("--"):
                    raise ValueError("missing k3s component argument")
                val = argv[i]
            out.setdefault(comp, []).extend(_args(val))
        i += 1
    return out


def k3s_role(argv: list[str]) -> str | None:
    if len(argv) >= 2 and argv[0].rsplit("/", 1)[-1] == "k3s" and argv[1] in ("server", "agent"):
        return argv[1]
    return None


def check_environment(env: list[str]) -> None:
    if any(e.partition("=")[0] in {"K3S_CONFIG_FILE", "K3S_KUBE_APISERVER_ARG",
                                   "K3S_KUBE_CONTROLLER_MANAGER_ARG", "K3S_KUBELET_ARG"} for e in env):
        raise ValueError("k3s component/config environment overrides are unsupported")


def effective_flags(config_text: str | None, execstart_text: str | None, *,
                    files: list[tuple[str, str]] | None = None, argv: list[str] | None = None) -> dict:
    argv = execstart_argv(execstart_text or "") if argv is None else argv
    role = k3s_role(argv)
    if role is None:
        raise ValueError("k3s server/agent command line was not collected")
    files = files if files is not None else ([(CONFIG_PATH, config_text)] if config_text is not None else [])
    config = _merge_config(files)
    # CLI component lists replace the whole configured list, as k3s does.
    config.update(execstart_args(argv))
    out = {"role": role, "complete": True, "sources": [p for p, _ in sorted(files)] + ["k3s command line"],
           "limitations": ["Configured flags and documented k3s defaults; runtime activation is not verified."]}
    for comp, defaults in K3S_DEFAULTS.items():
        if role == "agent" and comp != "kubelet":
            continue
        flags = dict(defaults)
        for arg in config.get(comp, []):
            key, eq, value = arg.strip().lstrip("-").partition("=")
            if not re.fullmatch(r"[a-z][a-z0-9-]*", key):
                raise ValueError("invalid k3s component flag")
            flags[key] = value if eq else "true"
            if key in ("anonymous-auth", "profiling", "use-service-account-credentials") and flags[key].lower() not in ("true", "false"):
                raise ValueError("invalid k3s boolean component flag")
            if key in ("insecure-port", "read-only-port") and (not flags[key].isdigit() or not 0 <= int(flags[key]) <= 65535):
                raise ValueError("invalid k3s port component flag")
        out[comp] = flags
    return out
