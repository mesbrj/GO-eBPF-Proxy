#!/usr/bin/env bash
# Tears down the app+sidecar pod. Ephemeral by default: removing the pod
# also removes the sidecar's tmpfs keylog mount and, unless RETAIN=1, the
# named log volume holding /var/log/sidecar (feature-03: "pod teardown wipes
# /var/log/sidecar"). Set RETAIN=1 (or pass --retain) to keep the volume.
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "pod-down: must run as root (rootful podman)" >&2
  exit 1
fi

POD_NAME="${POD_NAME:-go-ebpf-proxy}"
LOG_VOLUME="${LOG_VOLUME:-${POD_NAME}-sidecar-logs}"
RETAIN="${RETAIN:-0}"

for arg in "$@"; do
  case "$arg" in
    --retain) RETAIN=1 ;;
  esac
done

podman pod rm -f "$POD_NAME" >/dev/null 2>&1 || true

if [[ "$RETAIN" == "1" ]]; then
  echo "pod-down: --retain set, keeping volume $LOG_VOLUME"
else
  podman volume rm -f "$LOG_VOLUME" >/dev/null 2>&1 || true
  echo "pod-down: pod $POD_NAME removed, $LOG_VOLUME wiped"
fi
