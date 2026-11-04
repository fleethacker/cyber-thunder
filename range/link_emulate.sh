#!/usr/bin/env bash
# Throttle a network interface to look like a constrained shipboard link.
#
# Usage (as root, on the range VM only):
#   link_emulate.sh on [kbps] [latency_ms] [iface]   defaults: 56 kbps, 500 ms, first non-loopback interface
#   link_emulate.sh off [iface]                      remove the shaping
#   link_emulate.sh status [iface]                   show what is applied
#
# How it works: a netem qdisc at the root adds delay, with a token bucket filter (tbf) under it that caps the
# rate. Only egress traffic from this machine is shaped, so the transfer you pull *from* the VM is slowed.
# Never run this on a machine you need for anything else; "off" removes it again.
set -euo pipefail

cmd="${1:-status}"

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
command -v tc >/dev/null || { echo "tc not found (install iproute-tc)"; exit 1; }

default_iface() {
  # first interface that is not loopback
  ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}' | cut -d@ -f1
}

case "$cmd" in
  on)
    kbps="${2:-56}"
    latency="${3:-500}"
    iface="${4:-$(default_iface)}"
    [[ "$kbps" =~ ^[0-9]+$ && "$latency" =~ ^[0-9]+$ ]] || { echo "kbps and latency must be whole numbers"; exit 1; }
    [[ -n "$iface" ]] || { echo "no interface found"; exit 1; }
    tc qdisc del dev "$iface" root 2>/dev/null || true
    tc qdisc add dev "$iface" root handle 1: netem delay "${latency}ms"
    # burst and latency on tbf must be large enough to pass full-size packets at low rates.
    tc qdisc add dev "$iface" parent 1: handle 2: tbf rate "${kbps}kbit" burst 4kb latency 400ms
    echo "link emulation ON: $iface ${kbps} kbit/s, +${latency} ms"
    ;;
  off)
    iface="${2:-$(default_iface)}"
    tc qdisc del dev "$iface" root 2>/dev/null || true
    echo "link emulation OFF: $iface"
    ;;
  status)
    iface="${2:-$(default_iface)}"
    echo "interface: $iface"
    tc qdisc show dev "$iface"
    ;;
  *)
    echo "usage: $0 on [kbps] [latency_ms] [iface] | off [iface] | status [iface]"
    exit 1
    ;;
esac
