"""Kubernetes as a discovery source: the node list of a cluster already in the inventory.

`kubectl get nodes -o json` is read-only. Each node becomes an asset at its InternalIP with the OS
image, kernel, kubelet and container runtime versions as facts, so the applicability lookup can match
Kubernetes and Linux STIGs against it.
"""
from __future__ import annotations

import ipaddress
import json

from ..models import DiscoveredAsset

KUBE_COMMAND = "kubectl get nodes -o json"


def _ip(value: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        return None


def parse_nodes(text: str) -> list[DiscoveredAsset]:
    data = json.loads(text or "{}")
    items = data.get("items", []) if isinstance(data, dict) else []
    out = []
    for n in items:
        meta, status = n.get("metadata", {}), n.get("status", {})
        addrs = {a.get("type"): a.get("address") for a in status.get("addresses", [])}
        address = _ip(addrs.get("InternalIP")) or _ip(addrs.get("ExternalIP"))
        if not address:
            continue
        info = status.get("nodeInfo", {})
        labels = meta.get("labels", {}) or {}
        roles = sorted(k.split("/", 1)[1] for k in labels if k.startswith("node-role.kubernetes.io/"))
        ready = next((c.get("status") == "True" for c in status.get("conditions", []) if c.get("type") == "Ready"), None)
        a = DiscoveredAsset(address=address, hostname=addrs.get("Hostname") or meta.get("name"), sources=["kubernetes"])
        a.os_guess = info.get("osImage") or None
        a.facts.update({k: v for k, v in {
            "kube_node": meta.get("name"), "os_image": info.get("osImage"), "kernel": info.get("kernelVersion"),
            "kubelet_version": info.get("kubeletVersion"), "container_runtime": info.get("containerRuntimeVersion"),
            "operating_system": info.get("operatingSystem"), "architecture": info.get("architecture"),
            "roles": roles, "ready": ready,
        }.items() if v is not None and v != []})
        a.evidence.append(f"kubernetes: node {meta.get('name')} kubelet {info.get('kubeletVersion') or '?'} "
                          f"roles {','.join(roles) or 'worker'}")
        out.append(a)
    return out
