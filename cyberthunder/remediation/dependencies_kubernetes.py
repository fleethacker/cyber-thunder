"""Namespace-scoped Kubernetes dependency reads; never fetch Secret objects or node config."""
from __future__ import annotations

import re

from cyberthunder.adapters.kubernetes.adapter import KubernetesAdapter
from cyberthunder.adapters.kubernetes.kubectl import OBJ_TAG, RE_K8S_LABEL, RE_K8S_NAME

from .dependencies_io import ReadFailure, read_json

MAX_OBJECTS = 32
MAX_REFERENCES = 16
PATHS = {"deployment": ("/apis/apps/v1", "deployments"),
         "pod": ("/api/v1", "pods"), "cronjob": ("/apis/batch/v1", "cronjobs")}
LABEL_PART = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?")


def _name(value):
    return isinstance(value, str) and RE_K8S_NAME.fullmatch(value) is not None


def _count(value):
    return value if type(value) is int and 0 <= value <= 1000000 else None


def _labels(value):
    if not isinstance(value, dict) or len(value) > 32:
        raise ReadFailure("invalid_labels")
    if any(not isinstance(k, str) or not isinstance(v, str) or len(k) > 253 or len(v) > 63
           for k, v in value.items()):
        raise ReadFailure("invalid_labels")
    for key, val in value.items():
        parts = key.split("/")
        if (len(parts) > 2 or not LABEL_PART.fullmatch(parts[-1])
                or (len(parts) == 2 and not _name(parts[0]))
                or (val and not LABEL_PART.fullmatch(val))):
            raise ReadFailure("invalid_labels")
    return value


def _matches(selector, labels):
    """Evaluate all Kubernetes label selector operators, refusing unknown semantics."""
    if not isinstance(selector, dict) or set(selector) - {"matchLabels", "matchExpressions"}:
        raise ReadFailure("invalid_selector")
    match = _labels(selector.get("matchLabels", {}))
    expressions = selector.get("matchExpressions", [])
    if not isinstance(expressions, list) or len(expressions) > 16:
        raise ReadFailure("invalid_selector")
    result = all(labels.get(k) == v for k, v in match.items())
    for expr in expressions:
        if not isinstance(expr, dict):
            raise ReadFailure("invalid_selector")
        key, op, values = expr.get("key"), expr.get("operator"), expr.get("values", [])
        if (not isinstance(key, str) or len(key) > 253 or not isinstance(values, list)
                or len(values) > 32 or any(not isinstance(v, str) or len(v) > 63 for v in values)):
            raise ReadFailure("invalid_selector")
        for value in values or [""]:
            _labels({key: value})
        if op == "In" and values:
            result &= key in labels and labels[key] in values
        elif op == "NotIn" and values:
            result &= key not in labels or labels[key] not in values
        elif op == "Exists" and not values:
            result &= key in labels
        elif op == "DoesNotExist" and not values:
            result &= key not in labels
        else:
            raise ReadFailure("invalid_selector")
    return result


def _command(prefix, ns, resource, name=None):
    if not RE_K8S_LABEL.fullmatch(ns) or (name is not None and not _name(name)):
        raise ValueError("invalid object reference")
    path = f"{prefix}/namespaces/{ns}/{resource}"
    path += f"/{name}" if name is not None else f"?limit={MAX_OBJECTS + 1}"
    # --raw avoids kubectl's automatic pagination. No continuation is ever followed.
    return "kubectl --request-timeout=8s get --raw " + path


def _object(data, ns, *, name=None):
    if not isinstance(data, dict) or not isinstance(data.get("metadata"), dict):
        raise ReadFailure("invalid_object")
    md = data["metadata"]
    if md.get("namespace") != ns or not _name(md.get("name")) or (name is not None and md["name"] != name):
        raise ReadFailure("object_scope_mismatch")
    if not isinstance(data.get("spec", {}), dict) or not isinstance(data.get("status", {}), dict):
        raise ReadFailure("invalid_object")
    return data


def _list(packet, read, prefix, ns, resource, kind):
    text = read(_command(prefix, ns, resource))
    if text is None:
        return [], False
    try:
        data = read_json(text)
        items, md = data.get("items"), data.get("metadata")
        if not isinstance(items, list) or not isinstance(md, dict):
            raise ReadFailure("invalid_list")
        complete = not md.get("continue") and len(items) <= MAX_OBJECTS
        rows = []
        seen = set()
        for item in items[:MAX_OBJECTS]:
            try:
                item = _object(item, ns)
                if item.get("kind") != kind or item["metadata"]["name"] in seen:
                    raise ReadFailure("invalid_object")
                seen.add(item["metadata"]["name"])
                rows.append(item)
            except ReadFailure:
                complete = False
        if not complete:
            packet.unknown("A namespace object list was partial, oversized or invalid; absent dependencies cannot be inferred.")
        return rows, complete
    except (ReadFailure, TypeError):
        packet.unknown("A namespace dependency response was invalid; its dependencies remain unknown.")
        return [], False


def _references(packet, subject, pod_spec):
    refs = []
    account = pod_spec.get("serviceAccountName") or "default"
    if _name(account):
        refs.append({"kind": "serviceaccount", "name": account})
    else:
        packet.unknown("The workload service-account reference is invalid or unavailable.")
    volumes = pod_spec.get("volumes", [])
    if not isinstance(volumes, list):
        volumes = []
        packet.unknown("Workload volume references are unavailable.")
    if len(volumes) > MAX_REFERENCES:
        packet.unknown("Workload volume references exceeded the collection bound.")
    host_path = False
    for volume in volumes[:MAX_REFERENCES]:
        if not isinstance(volume, dict):
            packet.unknown("A workload volume reference is invalid.")
            continue
        if "hostPath" in volume:
            host_path = True
        for key, field, kind in (("persistentVolumeClaim", "claimName", "persistentvolumeclaim"),
                                 ("configMap", "name", "configmap"), ("secret", "secretName", "secret-reference")):
            if key in volume:
                value = volume[key]
                name = value.get(field) if isinstance(value, dict) else None
                if _name(name):
                    refs.append({"kind": kind, "name": name})
                else:
                    packet.unknown("A workload volume reference is invalid.")
        if "projected" in volume or "csi" in volume:
            packet.unknown("Projected/CSI volume dependencies require owner preflight; their configuration was not collected.")
    eid = packet.evidence("kubernetes-references", packet.source("kubernetes-api"), subject,
                          {"references": refs, "host_path_present": host_path})
    ns = subject.split("/", 1)[0]
    for ref in refs:
        packet.edge(subject, f"{ns}/{ref['kind']}/{ref['name']}", "references", eid)
    if host_path:
        packet.risk("host-volume", "high", "The workload references host storage; rescheduling and manifest rollback do not restore host data.", [eid])
    if any(ref["kind"] == "persistentvolumeclaim" for ref in refs):
        packet.risk("persistent-volume", "medium", "The workload references persistent storage; attachment, failover and data recovery remain unverified.", [eid])


def collect_kubernetes(packet, fix, finding, read):
    if finding is None or finding.host != packet.target.id:
        packet.unknown("A matching current Kubernetes finding is required to bind the affected object.")
        return
    try:
        if fix.kind != "manifest" or len([t for t in finding.tags if t.startswith(OBJ_TAG)]) != 1:
            raise ValueError("ambiguous object")
        ref, restore = KubernetesAdapter()._object_ref(fix, finding)
        if (ref.kind not in PATHS or ref.namespace is None or not RE_K8S_LABEL.fullmatch(ref.namespace)
                or not _name(ref.name) or ref.key() != restore.key()):
            raise ValueError("unsupported workload")
    except (ValueError, TypeError, AttributeError):
        packet.unknown("This manifest/runbook has no supported exact workload binding; cluster-wide dependencies remain unknown.")
        packet.check("Review affected objects, namespaces, RBAC and network-policy dependencies with the cluster owner.")
        return
    ns, subject = ref.namespace, ref.key()
    prefix, resource = PATHS[ref.kind]
    text = read(_command(prefix, ns, resource, ref.name))
    if text is None:
        return
    try:
        obj = _object(read_json(text), ns, name=ref.name)
        if obj.get("kind") != {"pod": "Pod", "deployment": "Deployment", "cronjob": "CronJob"}[ref.kind]:
            raise ReadFailure("object_kind_mismatch")
        spec, status = obj.get("spec", {}), obj.get("status", {})
        if ref.kind == "deployment":
            template = spec.get("template", {})
            selector = spec.get("selector")
            if not selector:
                raise ReadFailure("missing_selector")
        elif ref.kind == "cronjob":
            template = spec.get("jobTemplate", {}).get("spec", {}).get("template", {})
            selector = {"matchLabels": template.get("metadata", {}).get("labels", {})}
        else:
            template = obj
            selector = None
        labels = _labels(template.get("metadata", {}).get("labels", {}))
        pod_spec = template.get("spec")
        if not isinstance(pod_spec, dict):
            raise ReadFailure("invalid_pod_spec")
        if selector is not None:
            _matches(selector, labels)  # validate all selector operators before using them
    except (ReadFailure, TypeError, AttributeError):
        packet.unknown("The bound workload response was incomplete, invalid or outside its namespace/name; no topology was inferred.")
        return
    facts = {"kind": ref.kind, "namespace": ns, "name": ref.name,
             "desired_replicas": _count(spec.get("replicas")) if ref.kind == "deployment" else None,
             "ready_replicas": _count(status.get("readyReplicas")),
             "available_replicas": _count(status.get("availableReplicas"))}
    eid = packet.evidence("kubernetes-workload", packet.source("kubernetes-api"), subject, facts)
    if ref.kind == "deployment":
        counts = [facts[key] for key in ("desired_replicas", "ready_replicas", "available_replicas")]
        if any(value is None for value in counts):
            packet.unknown("Replica availability was not fully reported; missing counts were not treated as zero.")
        if any(value is not None and value < 2 for value in counts):
            packet.risk("limited-redundancy", "high", "The workload reports fewer than two desired, ready or available replicas; continuity during disruption is unproven.", [eid])
    if ns == "kube-system":
        packet.risk("system-workload", "high", "The affected workload is in kube-system and may support cluster operation.", [eid])
    _references(packet, subject, pod_spec)
    pods, pods_complete = _list(packet, read, "/api/v1", ns, "pods", "Pod")
    matched_pods = []
    for pod in pods:
        try:
            matches = pod["metadata"]["name"] == ref.name if ref.kind == "pod" else (
                (ref.kind == "deployment" or bool(labels))
                and _matches(selector, _labels(pod["metadata"].get("labels", {}))))
            if not matches:
                continue
            matched_pods.append(pod)
            conditions = pod.get("status", {}).get("conditions", [])
            if not isinstance(conditions, list) or len(conditions) > 32:
                raise ReadFailure("invalid_conditions")
            ready = next((c.get("status") for c in conditions if isinstance(c, dict) and c.get("type") == "Ready"), None)
            ready = ready if ready in {"True", "False", "Unknown"} else None
            name = pod["metadata"]["name"]
            peid = packet.evidence("kubernetes-pod", packet.source("kubernetes-api"), f"{ns}/pod/{name}",
                                   {"name": name, "ready": ready, "match_basis": "exact-name" if ref.kind == "pod" else "workload-label-selector"})
            packet.edge(subject, f"{ns}/pod/{name}", "selector-matches" if ref.kind != "pod" else "observed", peid)
        except (ReadFailure, TypeError, AttributeError):
            pods_complete = False
    services, services_complete = _list(packet, read, "/api/v1", ns, "services", "Service")
    service_count = 0
    for service in services:
        try:
            selector = _labels(service.get("spec", {}).get("selector", {}))
            if not selector or not all(labels.get(k) == v for k, v in selector.items()):
                continue
            service_count += 1
            name = service["metadata"]["name"]
            seid = packet.evidence("kubernetes-service-selector", packet.source("kubernetes-api"), f"{ns}/service/{name}",
                                   {"name": name, "selector_matches_template": True, "selector_key_count": len(selector)})
            packet.edge(f"{ns}/service/{name}", subject, "selector-matches", seid)
        except (ReadFailure, TypeError):
            services_complete = False
    pdbs, pdbs_complete = _list(packet, read, "/apis/policy/v1", ns, "poddisruptionbudgets", "PodDisruptionBudget")
    pdb_count = 0
    for pdb in pdbs:
        try:
            selector = pdb.get("spec", {}).get("selector")
            if selector is None:
                continue
            if pdb.get("apiVersion") != "policy/v1":
                raise ReadFailure("unknown_pdb_semantics")
            if not _matches(selector, labels):
                continue
            pdb_count += 1
            name = pdb["metadata"]["name"]
            allowed = _count(pdb.get("status", {}).get("disruptionsAllowed"))
            peid = packet.evidence("kubernetes-pdb", packet.source("kubernetes-api"), f"{ns}/poddisruptionbudget/{name}",
                                   {"name": name, "selector_matches_template": True, "disruptions_allowed": allowed})
            packet.edge(subject, f"{ns}/poddisruptionbudget/{name}", "matched-by-budget", peid)
            if allowed == 0:
                packet.risk("pdb-no-disruptions", "high", "A matching PDB reports zero allowed voluntary disruptions; some update mechanisms may bypass this budget.", [peid])
            elif allowed is None:
                packet.unknown("A matching disruption budget has no usable status; allowed disruptions remain unknown.")
        except (ReadFailure, TypeError):
            pdbs_complete = False
    coverage = packet.evidence("kubernetes-namespace-coverage", packet.source("kubernetes-api"), subject,
                               {"pod_list_complete": pods_complete, "service_list_complete": services_complete,
                                "pdb_list_complete": pdbs_complete, "matching_pods": len(matched_pods),
                                "matching_services": service_count, "matching_pdbs": pdb_count})
    if pdbs_complete and pdb_count == 0:
        packet.risk("no-matching-pdb", "medium", "No matching PDB was observed in the bounded, complete namespace response; disruption protection is unverified.", [coverage])
    if not all((pods_complete, services_complete, pdbs_complete)):
        packet.unknown("Some namespace dependencies could not be resolved completely; zero matches do not prove absence.")
    packet.unknown("Selectors indicate routing/selection relationships, not verified ownership, endpoint health or client traffic.")
    packet.unknown("Cross-namespace/external clients, RBAC permissions, storage health and network paths remain unknown.")
    packet.unknown("Independent API reads are not a transactional snapshot; relationships and readiness can change during collection.")
    packet.check("Validate service routing, pod readiness, disruption budgets, storage and service-account access with the workload owner.")
