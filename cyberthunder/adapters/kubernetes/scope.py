"""Explicit, bounded namespace collection. This mode never authorizes remediation."""
from __future__ import annotations

import copy
import json
import re

MAX_NAMESPACES = 16
MAX_LIST_BYTES = 8 * 1024 * 1024
MAX_LIST_ITEMS = 10000
NAMESPACED_RESOURCES = (
    "pods", "deployments", "serviceaccounts", "rolebindings", "networkpolicies", "cronjobs", "services",
)
SCOPE_KEY = "kubernetes_scope"
READ_ONLY = "Namespace collection is read-only; capture, apply, verification and rollback are unavailable."
UNAVAILABLE_INPUTS = ("nodes", "namespaces", "roles", "clusterroles", "clusterrolebindings", "configz", "node configuration")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def namespace_scope(options) -> tuple[str, ...] | None:
    """Absent means legacy cluster mode; any present invalid value fails closed."""
    if not isinstance(options, dict):
        raise ValueError("Kubernetes target options must be a mapping")
    if "namespaces" not in options:
        return None
    value = options["namespaces"]
    if (not isinstance(value, list) or not 1 <= len(value) <= MAX_NAMESPACES
            or any(not isinstance(n, str) or not _LABEL.fullmatch(n) for n in value)
            or len(set(value)) != len(value)):
        raise ValueError(f"options.namespaces requires 1..{MAX_NAMESPACES} distinct DNS labels (1..63 characters)")
    return tuple(sorted(value))


def list_command(resource: str, namespace: str) -> str:
    return f"kubectl get {resource} -n {namespace} -o json"


def guard_command(argv, stdin, namespaces):
    # A deliberately closed grammar: no aliases, extra flags, discovery, raw paths,
    # input files, individual object reads, selectors, or kubectl connection overrides.
    if (stdin is not None or len(argv) != 7 or argv[:2] != ["kubectl", "get"]
            or argv[2] not in NAMESPACED_RESOURCES or argv[3] != "-n"
            or argv[4] not in namespaces or argv[5:] != ["-o", "json"]):
        raise PermissionError("namespace transport only permits declared namespaced collection reads")


def complete_items(document, resource, namespace):
    """Accept only a complete list whose object identities match this exact request."""
    from .kubectl import KIND_INFO, RE_K8S_NAME, RE_RBAC_NAME

    _, kind, api = KIND_INFO[resource]
    if (not isinstance(document, dict) or document.get("kind") not in {"List", kind + "List"}
            or document.get("apiVersion") not in ({"v1", api} if document.get("kind") == "List" else {api})
            or not isinstance(document.get("metadata"), dict)
            or not isinstance(document.get("items"), list) or len(document["items"]) > MAX_LIST_ITEMS):
        raise ValueError("malformed Kubernetes list envelope")
    md = document["metadata"]
    if (md.get("continue", "") != "" or type(md.get("remainingItemCount", 0)) is not int
            or md.get("remainingItemCount", 0) != 0):
        raise ValueError("incomplete or malformed pagination metadata")
    seen = set()
    for item in document["items"]:
        if (not isinstance(item, dict) or item.get("kind") != kind or item.get("apiVersion") != api
                or not isinstance(item.get("metadata"), dict)):
            raise ValueError("malformed resource identity")
        meta = item["metadata"]
        if meta.get("namespace") != namespace or not isinstance(meta.get("name"), str):
            raise ValueError("returned object is outside the requested namespace or lacks an identity")
        name_rule = RE_RBAC_NAME if resource == "rolebindings" else RE_K8S_NAME
        if not name_rule.fullmatch(meta["name"]):
            raise ValueError("malformed object name")
        if meta["name"] in seen:
            raise ValueError("duplicate object identity")
        seen.add(meta["name"])
        _shapes(item)
        if resource in {"pods", "deployments", "cronjobs", "services", "networkpolicies"}:
            if not isinstance(item.get("spec"), dict):
                raise ValueError("resource specification unavailable")
        if resource in {"pods", "deployments", "cronjobs"}:
            spec = item["spec"]
            if resource == "cronjobs":
                spec = spec.get("jobTemplate", {}).get("spec", {})
            if resource != "pods":
                spec = spec.get("template", {}).get("spec", {})
            if not spec.get("containers"):
                raise ValueError("workload containers unavailable")
            for container in spec.get("containers", []) + spec.get("initContainers", []):
                if (not isinstance(container.get("name"), str) or not _LABEL.fullmatch(container["name"])
                        or not isinstance(container.get("image"), str) or not container["image"]):
                    raise ValueError("malformed workload container")
        if resource == "rolebindings":
            role = item.get("roleRef")
            if (not isinstance(role, dict) or role.get("kind") not in {"Role", "ClusterRole"}
                    or role.get("apiGroup") != "rbac.authorization.k8s.io" or not isinstance(role.get("name"), str)
                    or not RE_RBAC_NAME.fullmatch(role["name"])):
                raise ValueError("binding role reference unavailable")
            for subject in item.get("subjects", []):
                if (subject.get("kind") not in ("ServiceAccount", "User", "Group")
                        or not isinstance(subject.get("name"), str) or not subject["name"]
                        or ("namespace" in subject and (not isinstance(subject["namespace"], str)
                            or (subject["namespace"] != "" and not _LABEL.fullmatch(subject["namespace"]))))
                        or ("apiGroup" in subject and not isinstance(subject["apiGroup"], str))):
                    raise ValueError("binding subject unavailable")
    return document["items"]


def _shapes(value):
    """Reject malformed structures consumed by native checks; not an API schema validator."""
    maps = {"metadata", "spec", "template", "jobTemplate", "securityContext", "resources", "limits", "requests",
            "hostPath", "valueFrom", "secretKeyRef", "secretRef", "roleRef", "labels", "annotations", "selector"}
    lists = {"containers", "initContainers", "volumes", "env", "envFrom", "ports", "subjects", "ownerReferences"}
    for key, child in value.items():
        if key in maps and not isinstance(child, dict):
            raise ValueError("malformed resource mapping")
        if key in lists and (not isinstance(child, list) or any(not isinstance(x, dict) for x in child)):
            raise ValueError("malformed resource sequence")
        if key in {"command", "args"} and (not isinstance(child, list) or any(not isinstance(x, str) for x in child)):
            raise ValueError("malformed container command")
        if key in {"hostPID", "hostIPC", "hostNetwork", "privileged", "allowPrivilegeEscalation", "runAsNonRoot",
                   "automountServiceAccountToken"} and type(child) is not bool:
            raise ValueError("malformed security boolean")
        if key in {"hostPort", "containerPort", "runAsUser"} and type(child) is not int:
            raise ValueError("malformed numeric resource field")
        if isinstance(child, dict) and key not in {"labels", "annotations", "selector", "limits", "requests"}:
            _shapes(child)
        elif isinstance(child, list):
            for item in child:
                if isinstance(item, dict):
                    _shapes(item)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("invalid JSON constant")


def collection_coverage(namespaces):
    return {"mode": "namespace", "namespaces": list(namespaces), "read_only": True,
            "status": "partial", "cluster_complete": False, "resources": {},
            "unavailable_inputs": list(UNAVAILABLE_INPUTS)}


def collect_lists(col, transport, namespaces):
    from pathlib import Path

    coverage = collection_coverage(namespaces)
    col.raw[SCOPE_KEY] = coverage
    col.errors.append("Namespace coverage only; cluster-scoped inputs and node configuration unavailable by scope.")
    for resource in NAMESPACED_RESOURCES:
        rows, items = {}, []
        coverage["resources"][resource] = rows
        for ns in namespaces:
            command = list_command(resource, ns)
            result = transport.run(command)
            try:
                if not result.ok:
                    # Keep credential-bearing stderr and unexpected response bodies out of evidence.
                    raise ValueError(f"collection unavailable (exit {result.exit_code})")
                if len(result.stdout.encode("utf-8")) > MAX_LIST_BYTES:
                    raise ValueError("namespace list exceeds collection size limit")
                document = json.loads(result.stdout, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
                returned = complete_items(document, resource, ns)
            except (ValueError, TypeError, RecursionError) as error:
                reason = "malformed JSON" if isinstance(error, json.JSONDecodeError) else str(error)
                if isinstance(error, (TypeError, RecursionError)):
                    reason = "malformed resource response"
                rows[ns] = {"status": "unavailable", "reason": reason}
                col.errors.append(f"{resource}/{ns}: {reason}")
                continue
            rows[ns] = {"status": "collected", "item_count": len(returned)}
            items.extend(returned)
        if any(row["status"] == "collected" for row in rows.values()):
            path = Path(col.workdir) / f"{resource}.json"
            items.sort(key=lambda item: (item["metadata"]["namespace"], item["metadata"]["name"]))
            path.write_text(json.dumps({"apiVersion": "v1", "kind": "List", "metadata": {}, "items": items},
                                       sort_keys=True), encoding="utf-8")
            col.artifacts[resource] = str(path)
    coverage["namespace_lists_complete"] = all(
        row["status"] == "collected" for rows in coverage["resources"].values() for row in rows.values())
    if not col.artifacts:
        coverage["status"] = "unavailable"


def annotate(findings, collected):
    coverage = collected.raw.get(SCOPE_KEY)
    if coverage is None:
        return findings
    scope_text = "Namespace coverage: " + ", ".join(coverage["namespaces"]) + "; cluster coverage incomplete. " + READ_ONLY
    for finding in findings:
        finding.collection_provenance = dict(finding.collection_provenance or {})
        finding.collection_provenance[SCOPE_KEY] = copy.deepcopy(coverage)
        finding.tags += ["k8s:namespace-read-only", *["k8s-coverage:" + ns for ns in coverage["namespaces"]]]
        finding.evidence = (finding.evidence or "") + "\n" + scope_text
        if any("/rolebinding/" in tag for tag in finding.tags):
            finding.evidence += "\nBinding declaration only; referenced roles and effective permissions were not collected."
        finding.fix_ref = "k8s:runbook:namespace-read-only"
    return findings
