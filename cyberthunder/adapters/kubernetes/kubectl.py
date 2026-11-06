"""kubectl command handling shared by the live (kubeconfig) and simulated transports.

Commands the adapter issues are plain strings that start with 'kubectl'. A manifest is passed on stdin
with a quoted here-doc, exactly as an operator would type it:

    kubectl apply -f - <<'CT_EOF'
    {"apiVersion": "v1", ...}
    CT_EOF

The live transport never hands the string to a shell: it splits the first line with shlex, prefixes
'--kubeconfig', and feeds the here-doc body to kubectl on stdin. Shell metacharacters therefore have
no effect.

Object references ("<namespace>/<kind>/<name>[/<container>]") travel on findings as tags. Fix payloads
are templates with <namespace>, <kind>, <name>, <container> placeholders; every value is checked against
the Kubernetes naming rules before it is substituted, so nothing else can reach a command line.
"""
from __future__ import annotations

import copy
import re
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from cyberthunder.transport.base import CommandResult, TransportError
from cyberthunder.transport.local import LocalTransport

EOF_TAG = "CT_EOF"
HEREDOC_RE = re.compile(r"<<-?\s*'?(?P<tag>[A-Za-z_][A-Za-z0-9_]*)'?\s*$")

# DNS-1123 subdomain (object names, namespaces) and label (container names).
RE_K8S_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
RE_K8S_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
# RBAC objects (roles, bindings, cluster or namespaced) are path-segment names and carry ':'
# (system:controller:bootstrap-signer in kube-system); still no spaces or shell characters
RE_RBAC_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.:]{0,251}[a-z0-9])?$")

# kind aliases -> canonical plural resource
KIND_ALIASES = {
    "po": "pods", "pod": "pods", "pods": "pods",
    "deploy": "deployments", "deployment": "deployments", "deployments": "deployments",
    "sa": "serviceaccounts", "serviceaccount": "serviceaccounts", "serviceaccounts": "serviceaccounts",
    "ns": "namespaces", "namespace": "namespaces", "namespaces": "namespaces",
    "no": "nodes", "node": "nodes", "nodes": "nodes",
    "cj": "cronjobs", "cronjob": "cronjobs", "cronjobs": "cronjobs",
    "clusterrole": "clusterroles", "clusterroles": "clusterroles",
    "clusterrolebinding": "clusterrolebindings", "clusterrolebindings": "clusterrolebindings",
    "role": "roles", "roles": "roles",
    "rolebinding": "rolebindings", "rolebindings": "rolebindings",
    "netpol": "networkpolicies", "networkpolicy": "networkpolicies", "networkpolicies": "networkpolicies",
    "secret": "secrets", "secrets": "secrets",
    "svc": "services", "service": "services", "services": "services",
}
CLUSTER_SCOPED = {"namespaces", "nodes", "clusterroles", "clusterrolebindings"}
RBAC_KINDS = {"roles", "rolebindings", "clusterroles", "clusterrolebindings"}
# canonical plural -> (singular used in commands, API kind, apiVersion)
KIND_INFO = {
    "pods": ("pod", "Pod", "v1"),
    "deployments": ("deployment", "Deployment", "apps/v1"),
    "serviceaccounts": ("serviceaccount", "ServiceAccount", "v1"),
    "namespaces": ("namespace", "Namespace", "v1"),
    "nodes": ("node", "Node", "v1"),
    "cronjobs": ("cronjob", "CronJob", "batch/v1"),
    "clusterroles": ("clusterrole", "ClusterRole", "rbac.authorization.k8s.io/v1"),
    "clusterrolebindings": ("clusterrolebinding", "ClusterRoleBinding", "rbac.authorization.k8s.io/v1"),
    "roles": ("role", "Role", "rbac.authorization.k8s.io/v1"),
    "rolebindings": ("rolebinding", "RoleBinding", "rbac.authorization.k8s.io/v1"),
    "networkpolicies": ("networkpolicy", "NetworkPolicy", "networking.k8s.io/v1"),
    "secrets": ("secret", "Secret", "v1"),
    "services": ("service", "Service", "v1"),
}
API_KIND_TO_PLURAL = {v[1]: k for k, v in KIND_INFO.items()}

# fields the API server owns; removed before an object is re-applied during rollback
SERVER_FIELDS = ("resourceVersion", "uid", "creationTimestamp", "managedFields", "generation", "selfLink")


def canonical_kind(kind: str) -> str | None:
    return KIND_ALIASES.get((kind or "").lower().split(".", 1)[0])


@dataclass(frozen=True)
class ObjRef:
    """A Kubernetes object, optionally narrowed to one container. namespace is None for cluster-scoped kinds."""
    namespace: str | None
    kind: str          # singular, lower case: deployment, pod, cronjob, clusterrolebinding ...
    name: str
    container: str | None = None

    def __post_init__(self) -> None:
        plural = canonical_kind(self.kind)
        if plural is None:
            raise ValueError(f"unsupported kind {self.kind!r}")
        object.__setattr__(self, "kind", KIND_INFO[plural][0])
        name_re = RE_RBAC_NAME if plural in RBAC_KINDS else RE_K8S_NAME
        if plural in CLUSTER_SCOPED:
            object.__setattr__(self, "namespace", None)
            if not name_re.match(self.name or ""):
                raise ValueError(f"invalid object name {self.name!r}")
        else:
            if not self.namespace or not RE_K8S_NAME.match(self.namespace):
                raise ValueError(f"invalid namespace {self.namespace!r}")
            if not name_re.match(self.name or ""):
                raise ValueError(f"invalid object name {self.name!r}")
        if self.container is not None and not RE_K8S_LABEL.match(self.container):
            raise ValueError(f"invalid container name {self.container!r}")

    @property
    def plural(self) -> str:
        return canonical_kind(self.kind)  # type: ignore[return-value]

    def key(self) -> str:
        return f"{self.namespace or '-'}/{self.kind}/{self.name}"

    def to_str(self) -> str:
        return self.key() + (f"/{self.container}" if self.container else "")

    @classmethod
    def parse(cls, text: str) -> "ObjRef":
        parts = text.split("/")
        if len(parts) not in (3, 4):
            raise ValueError(f"bad object reference {text!r}")
        ns = None if parts[0] == "-" else parts[0]
        return cls(ns, parts[1], parts[2], parts[3] if len(parts) == 4 else None)

    def get_command(self) -> str:
        ns = f" -n {self.namespace}" if self.namespace else ""
        return f"kubectl get {self.kind} {self.name}{ns} -o json"


OBJ_TAG = "k8s-object:"


def ref_from_finding(finding) -> ObjRef:
    for t in finding.tags:
        if t.startswith(OBJ_TAG):
            return ObjRef.parse(t[len(OBJ_TAG):])
    raise ValueError(f"finding {finding.id} carries no Kubernetes object reference")


def render(template: str, ref: ObjRef) -> str:
    """Fill a FixEntry payload template for one validated object."""
    text = template
    if ref.namespace is None:
        text = text.replace(" -n <namespace>", "")
    else:
        text = text.replace("<namespace>", ref.namespace)
    if "<container>" in text:
        if not ref.container:
            raise ValueError("this fix needs a container name and the finding has none")
        text = text.replace("<container>", ref.container)
    return text.replace("<kind>", ref.kind).replace("<name>", ref.name)


def strip_server_fields(obj: dict) -> dict:
    """Copy of obj without server-owned metadata and status, ready for kubectl replace/apply."""
    o = copy.deepcopy(obj)
    o.pop("status", None)
    md = o.get("metadata", {})
    for k in SERVER_FIELDS:
        md.pop(k, None)
    ann = md.get("annotations")
    if isinstance(ann, dict):
        ann.pop("kubectl.kubernetes.io/last-applied-configuration", None)
        ann.pop("deployment.kubernetes.io/revision", None)
        if not ann:
            md.pop("annotations")
    return o


# -- command strings ----------------------------------------------------------------------------
def heredoc(command: str, body: str) -> str:
    return f"{command} <<'{EOF_TAG}'\n{body}\n{EOF_TAG}"


def split_commands(payload: str) -> list[str]:
    """Split a multi-line payload into commands, keeping here-doc bodies with their command."""
    lines = payload.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line or line.startswith("#"):
            continue
        m = HEREDOC_RE.search(line)
        if m:
            tag = m.group("tag")
            body: list[str] = []
            while i < len(lines) and lines[i].strip() != tag:
                body.append(lines[i])
                i += 1
            i += 1
            out.append(line + "\n" + "\n".join(body) + "\n" + tag)
        else:
            out.append(line)
    return out


def parse_command(command: str) -> tuple[list[str], str | None]:
    """(argv, stdin) for a command string, honouring one trailing here-doc."""
    first, _, rest = command.partition("\n")
    stdin = None
    m = HEREDOC_RE.search(first)
    if m:
        tag = m.group("tag")
        first = first[: m.start()].strip()
        body = rest.split("\n")
        if body and body[-1].strip() == tag:
            body = body[:-1]
        stdin = "\n".join(body)
    return shlex.split(first, posix=True), stdin


class KubectlTransport(LocalTransport):
    """Runs the adapter's kubectl commands against a cluster through a kubeconfig file.

    Only commands whose first word is 'kubectl' are accepted. No shell is involved."""
    kind = "kubeconfig"

    def __init__(self, kubeconfig: str | Path, context: str | None = None, kubectl: str = "kubectl",
                 *, namespaces: list[str] | None = None):
        super().__init__()
        self.kubeconfig = str(kubeconfig)
        self.context = context
        self.kubectl = kubectl
        self.account_binding = None
        self.account_guard = None
        from .scope import namespace_scope
        self._namespace_scope = namespace_scope({"namespaces": namespaces}) if namespaces is not None else None
        self.namespace_guard = None

    @property
    def namespace_scope(self):
        return self._namespace_scope

    def build_argv(self, command: str) -> tuple[list[str], str | None]:
        if self.namespace_guard is not None:
            self.namespace_guard()
        argv, stdin = parse_command(command)
        if not argv or argv[0] != "kubectl":
            raise TransportError("kubeconfig transport only runs kubectl commands")
        if self.namespace_scope is not None:
            from .scope import guard_command
            if "\n" in command or "\r" in command:
                raise PermissionError("namespace transport refuses multiline commands")
            guard_command(argv, stdin, self.namespace_scope)
        if self.account_binding is not None:
            from cyberthunder.security.kube_credentials import guard_kubeconfig, validate_kubectl_args
            self.account_guard()
            guard_kubeconfig(self.account_binding)
            args = validate_kubectl_args(argv[1:])
            return ["kubectl", *self.account_binding.kubectl_args(), *args], stdin
        full = [self.kubectl, "--kubeconfig", self.kubeconfig]
        if self.context:
            full += ["--context", self.context]
        return full + argv[1:], stdin

    def run(self, command: str, *, timeout: int = 120, sudo: bool = False) -> CommandResult:
        if self.namespace_scope is not None and sudo:
            raise PermissionError("namespace collection does not permit privilege elevation")
        try:
            argv, stdin = self.build_argv(command)
        except (ValueError, TransportError) as e:
            return CommandResult(command, 126, "", str(e))
        t0 = time.time()
        options = {}
        if self.account_binding is not None:
            from cyberthunder.security.kube_credentials import kube_subprocess_env
            self.account_guard()
            options["env"] = kube_subprocess_env()
        try:
            p = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout,
                               encoding="utf-8", errors="replace", **options)
            return CommandResult(command, p.returncode, p.stdout, p.stderr, time.time() - t0, t0)
        except FileNotFoundError:
            return CommandResult(command, 127, "", f"{self.kubectl} not found on this machine", time.time() - t0, t0)
        except subprocess.TimeoutExpired:
            return CommandResult(command, 124, "", f"timeout after {timeout}s", time.time() - t0, t0)
        finally:
            if self.account_guard is not None:
                self.account_guard()

    def read_file(self, path: str) -> bytes:
        raise TransportError("kubeconfig transport has no file access; use kubectl")

    def write_file(self, path: str, data: bytes, *, mode: int | None = None, sudo: bool = False) -> None:
        raise TransportError("kubeconfig transport has no file access; use kubectl")
