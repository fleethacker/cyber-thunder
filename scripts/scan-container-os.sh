#!/usr/bin/env bash
set -uo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scan-container-os --profile PROFILE [options]

Required:
  --profile PROFILE          XCCDF profile id to evaluate.

Target options:
  --target-rootfs PATH       Mounted container root filesystem to scan.
                             Defaults to /target.
  --podman-image IMAGE       Scan an image available in mounted Podman storage.
                             Requires oscap-podman in the scanner image.
  --podman-container NAME    Scan a container available in mounted Podman storage.
                             Requires oscap-podman in the scanner image.

Scan options:
  --datastream PATH          SCAP datastream file. Defaults to
                             /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml.
  --out-dir PATH             Output directory. Defaults to /results.
  --name NAME                Output filename prefix. Defaults to openscap.
  --no-fail-on-findings      Return 0 when OpenSCAP reports non-compliance.

Outputs:
  NAME-xccdf.xml             Raw XCCDF results.
  NAME-report.html           OpenSCAP HTML report.
  NAME-xccdf.json            JSON representation of the XCCDF results.
USAGE
}

profile=""
datastream="/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"
out_dir="/results"
name="openscap"
target_rootfs="/target"
target_mode="rootfs"
target_ref=""
no_fail_on_findings="false"

require_value() {
  if [[ $# -lt 2 || "$2" == --* ]]; then
    echo "Missing value for $1." >&2
    usage >&2
    exit 64
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      require_value "$@"
      profile="$2"
      shift 2
      ;;
    --datastream)
      require_value "$@"
      datastream="$2"
      shift 2
      ;;
    --out-dir)
      require_value "$@"
      out_dir="$2"
      shift 2
      ;;
    --name)
      require_value "$@"
      name="$2"
      shift 2
      ;;
    --target-rootfs)
      require_value "$@"
      target_rootfs="$2"
      target_mode="rootfs"
      shift 2
      ;;
    --podman-image)
      require_value "$@"
      target_ref="$2"
      target_mode="podman-image"
      shift 2
      ;;
    --podman-container)
      require_value "$@"
      target_ref="$2"
      target_mode="podman-container"
      shift 2
      ;;
    --no-fail-on-findings)
      no_fail_on_findings="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if [[ -z "$profile" ]]; then
  echo "Missing required --profile." >&2
  usage >&2
  exit 64
fi

if [[ ! -f "$datastream" ]]; then
  echo "Datastream not found: $datastream" >&2
  exit 66
fi

mkdir -p "$out_dir"

xccdf_xml="${out_dir}/${name}-xccdf.xml"
html_report="${out_dir}/${name}-report.html"
json_report="${out_dir}/${name}-xccdf.json"

case "$target_mode" in
  rootfs)
    if [[ ! -d "$target_rootfs" ]]; then
      echo "Target root filesystem not found: $target_rootfs" >&2
      exit 66
    fi

    set +e
    oscap-chroot "$target_rootfs" xccdf eval \
      --profile "$profile" \
      --results "$xccdf_xml" \
      --report "$html_report" \
      "$datastream"
    scan_status=$?
    set -e
    ;;
  podman-image)
    if [[ -z "$target_ref" ]]; then
      echo "Missing image reference for --podman-image." >&2
      exit 64
    fi
    if ! command -v oscap-podman >/dev/null 2>&1; then
      echo "oscap-podman is not installed in this scanner image." >&2
      exit 69
    fi

    set +e
    oscap-podman "$target_ref" xccdf eval \
      --profile "$profile" \
      --results "$xccdf_xml" \
      --report "$html_report" \
      "$datastream"
    scan_status=$?
    set -e
    ;;
  podman-container)
    if [[ -z "$target_ref" ]]; then
      echo "Missing container reference for --podman-container." >&2
      exit 64
    fi
    if ! command -v oscap-podman >/dev/null 2>&1; then
      echo "oscap-podman is not installed in this scanner image." >&2
      exit 69
    fi

    set +e
    oscap-podman "$target_ref" xccdf eval \
      --profile "$profile" \
      --results "$xccdf_xml" \
      --report "$html_report" \
      "$datastream"
    scan_status=$?
    set -e
    ;;
  *)
    echo "Unsupported target mode: $target_mode" >&2
    exit 70
    ;;
esac

if [[ -f "$xccdf_xml" ]]; then
  xccdf-to-json "$xccdf_xml" "$json_report"
else
  echo "OpenSCAP did not produce an XCCDF results file: $xccdf_xml" >&2
  exit "$scan_status"
fi

echo "XCCDF XML: $xccdf_xml"
echo "HTML report: $html_report"
echo "JSON report: $json_report"

if [[ "$no_fail_on_findings" == "true" && "$scan_status" -eq 2 ]]; then
  exit 0
fi

exit "$scan_status"
