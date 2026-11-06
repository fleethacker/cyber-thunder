#!/usr/bin/env bash
# One bounded image evaluation. Run from WSL; no cluster access or host installs.
set -euo pipefail
repo=$(realpath "$1")
receipts=$(realpath "$2")
test -d "$receipts"
test ! -e "$receipts/run-id.txt"
task=$(mktemp -d /tmp/ct-container-scap-XXXXXXXX)
run_id=$(basename "$task" | tr '[:upper:]' '[:lower:]')
printf '%s\n' "$run_id" > "$receipts/run-id.txt"
printf '%s\n' "$task" > "$receipts/linux-directory.txt"
d() { docker --host unix:///var/run/docker.sock "$@"; }
container=""
scanner=""
cleanup() {
    if test -n "$scanner"; then d rm -f "$scanner" > "$receipts/scanner-remove.txt" 2>&1 || true; fi
    if test -n "$container"; then d rm "$container" > "$receipts/export-remove.txt" 2>&1 || true; fi
    if d image inspect "$run_id:scanner" >/dev/null 2>&1; then
        d image rm "$run_id:scanner" > "$receipts/scanner-image-remove.txt" 2>&1 || true
    fi
    d ps -a --format '{{.ID}} {{.Names}} {{.Image}} {{.Status}}' > "$receipts/containers-after.txt"
}
trap cleanup EXIT
d ps -a --format '{{.ID}} {{.Names}} {{.Image}} {{.Status}}' > "$receipts/containers-before.txt"
d version --format '{{json .}}' > "$receipts/docker-version.json"
uname -srmo > "$receipts/kernel.txt"
cp /etc/os-release "$receipts/host-os-release.txt"
mkdir "$task/rootfs" "$task/output" "$task/content" "$task/build"
# Only the task directory's owner can reach these directories on the host.
# UID 0 with only SYS_CHROOT cannot bypass DAC, so allow its isolated output writes.
chmod 1777 "$task/output"
printf '%s\n' '{"attempt_number":2,"scanner_uid":0,"capabilities":["SYS_CHROOT"],"target_metadata_original":false,"temp":"private 128 MiB tmpfs"}' > "$receipts/harness-config.json"
benchmark=U_RHEL_9_V2R10_STIG_SCAP_1-3_Benchmark.xml
cp "$repo/STIG/$benchmark" "$task/content/benchmark.xml"
sha256sum "$task/content/benchmark.xml" > "$receipts/benchmark-sha256.txt"
image=registry.access.redhat.com/ubi9/nginx-124@sha256:49c71b7a13b151b282d52c13323021235529d44d82f9b875699bc4e9f6139a91
timeout 300 docker --host unix:///var/run/docker.sock pull "$image" > "$receipts/target-pull.txt" 2>&1
d image inspect "$image" --format '{{.Id}} {{json .RepoDigests}} {{.Os}}/{{.Architecture}}' > "$receipts/target-image.txt"
immutable=$(d image inspect "$image" --format '{{index .RepoDigests 0}}')
# Created but NEVER started. Overridden entrypoint is an additional safeguard.
container=$(d create --name "$run_id-export" --network none --entrypoint /bin/false "$immutable")
d inspect "$container" --format '{{.Id}} {{.State.Status}} {{.State.StartedAt}} {{.Image}}' > "$receipts/export-container.txt"
d export --output "$task/image.tar" "$container"
python3 "$repo/scripts/container-scap-live/extract_rootfs.py" "$task/image.tar" "$task/rootfs" "$receipts/extraction.json" --scan-readable
base=debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
timeout 300 docker --host unix:///var/run/docker.sock pull "$base" > "$receipts/scanner-base-pull.txt" 2>&1
d image inspect "$base" --format '{{.Id}} {{json .RepoDigests}} {{.Os}}/{{.Architecture}}' > "$receipts/scanner-base.txt"
cat > "$task/build/Dockerfile" <<EOF
FROM $base
RUN apt-get update && apt-get install -y --no-install-recommends openscap-scanner openscap-utils && rm -rf /var/lib/apt/lists/*
EOF
cp "$task/build/Dockerfile" "$receipts/Dockerfile"
timeout 600 docker --host unix:///var/run/docker.sock build --label "local.ct-scap-run=$run_id" -t "$run_id:scanner" "$task/build" > "$receipts/scanner-build.txt" 2>&1
scanner_image=$(d image inspect "$run_id:scanner" --format '{{.Id}}')
printf '%s\n' "$scanner_image" > "$receipts/scanner-image-id.txt"
protection=(--network none --cap-drop ALL --cap-add SYS_CHROOT --security-opt no-new-privileges --read-only --pids-limit 128 --memory 1536m --cpus 2 --user 0:0 --ipc none --hostname ct-scap-offline --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777)
d run --rm "${protection[@]}" --entrypoint /bin/sh "$scanner_image" -c 'oscap --version; dpkg-query -W openscap-scanner openscap-utils libopenscap25 librpm9; cat /usr/bin/oscap-chroot' > "$receipts/scanner-version.txt" 2>&1
# /output is the sole writable bind; temporary data uses a private bounded tmpfs.
mounts=(--mount "type=bind,src=$task/rootfs,dst=/target,readonly" --mount "type=bind,src=$task/content,dst=/content,readonly" --mount "type=bind,src=$task/output,dst=/output")
d run --rm "${protection[@]}" "${mounts[@]}" --workdir /output -e TMPDIR=/tmp --entrypoint /usr/bin/oscap "$scanner_image" info /content/benchmark.xml > "$receipts/benchmark-info.txt" 2>&1
profile=xccdf_mil.disa.stig_profile_MAC-1_Public
scanner=$(d create --name "$run_id-eval" "${protection[@]}" "${mounts[@]}" --workdir /output -e TMPDIR=/tmp --entrypoint /usr/bin/oscap-chroot "$scanner_image" /target xccdf eval --profile "$profile" --results /output/image-xccdf.xml --report /output/image-report.html /content/benchmark.xml)
d inspect "$scanner" --format '{{json .HostConfig}}' > "$receipts/scanner-protection.json"
printf '%q ' docker --host unix:///var/run/docker.sock create --name "$run_id-eval" "${protection[@]}" "${mounts[@]}" --workdir /output -e TMPDIR=/tmp --entrypoint /usr/bin/oscap-chroot "$scanner_image" /target xccdf eval --profile "$profile" --results /output/image-xccdf.xml --report /output/image-report.html /content/benchmark.xml > "$receipts/evaluation-command.txt"
printf '\n' >> "$receipts/evaluation-command.txt"
set +e
timeout 300 docker --host unix:///var/run/docker.sock start --attach "$scanner" > "$receipts/engine-stdout.txt" 2> "$receipts/engine-stderr.txt"
wrapper_status=$?
set -e
printf '%s\n' "$wrapper_status" > "$receipts/docker-attach-exit.txt"
if test "$wrapper_status" -eq 124; then d stop --time 5 "$scanner" > "$receipts/timeout-stop.txt"; fi
d inspect "$scanner" --format '{{json .State}}' > "$receipts/engine-state.json"
find "$task/output" -maxdepth 1 -type f -name 'image-*' -exec sha256sum {} + > "$receipts/raw-output-sha256.txt"
# Keep original scanner exports locally, outside Git. Do not normalize the XML.
for file in image-xccdf.xml image-report.html; do
    if test -f "$task/output/$file"; then cp "$task/output/$file" "$receipts/$file"; fi
done
python3 "$repo/scripts/container-scap-live/record_result.py" "$repo" "$receipts" >/dev/null
printf 'Evaluation attempt finished; inspect the original engine state and result summary.\n'
exit "$wrapper_status"
