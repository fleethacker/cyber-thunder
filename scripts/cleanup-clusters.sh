#!/usr/bin/env bash
set -euo pipefail
umask 077

repository_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_dir"
mkdir -p .build

k3d cluster list --output json > .build/k3d-before-cleanup.json
other_clusters=$(python3 -c '
import json

with open(".build/k3d-before-cleanup.json") as cluster_file:
    clusters = json.load(cluster_file)
for cluster in clusters:
    if cluster["name"] != "cyber-thunder":
        print(cluster["name"])
')

if [ -n "$other_clusters" ]; then
  while IFS= read -r cluster_name; do
    echo "Removing k3d cluster: $cluster_name"
    k3d cluster delete "$cluster_name"
  done <<< "$other_clusters"
fi

# k3d can return success after logging a container removal error from Podman.
k3d cluster list --output json | python3 -c '
import json
import sys

remaining = [cluster["name"] for cluster in json.load(sys.stdin)
             if cluster["name"] != "cyber-thunder"]
if remaining:
    sys.exit("Cluster cleanup incomplete: " + ", ".join(remaining))
'
