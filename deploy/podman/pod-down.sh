#!/usr/bin/env bash
# Tears down the app+sidecar pod. Ephemeral by default: removing the pod
# also removes the sidecar's tmpfs keylog mount and, unless RETAIN=1, the
# named log volume holding /var/log/sidecar (feature-03: "pod teardown wipes
# /var/log/sidecar"). Set RETAIN=1 (or pass --retain) to keep the volume.
# The keylog socket volume pod-up.sh shares between the two containers is
# always removed: it holds only the socket, never an artifact.
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "pod-down: must run as root (rootful podman)" >&2
  exit 1
fi

POD_NAME="${POD_NAME:-go-ebpf-proxy}"
LOG_VOLUME="${LOG_VOLUME:-${POD_NAME}-sidecar-logs}"
KEYLOG_VOLUME="${KEYLOG_VOLUME:-${POD_NAME}-keylog-sock}"
RETAIN="${RETAIN:-0}"

for arg in "$@"; do
  case "$arg" in
    --retain) RETAIN=1 ;;
  esac
done

podman pod rm -f "$POD_NAME" >/dev/null 2>&1 || true

# The keylog socket volume carries only the socket the interposer connects to
# (the keylog itself is on the sidecar's tmpfs), so --retain does not keep it;
# the sidecar binds a fresh socket on its next start.
podman volume rm -f "$KEYLOG_VOLUME" >/dev/null 2>&1 || true

# A crashed/killed sidecar may not have run its own graceful pin cleanup;
# these bpffs pin dirs are pod-up.sh's compiled-in defaults, safe to remove.
rm -rf /sys/fs/bpf/go-ebpf-proxy /sys/fs/bpf/go-ebpf-proxy-keylog 2>/dev/null || true

if [[ "$RETAIN" == "1" ]]; then
  echo "pod-down: --retain set, keeping volume $LOG_VOLUME ($KEYLOG_VOLUME removed)"
else
  podman volume rm -f "$LOG_VOLUME" >/dev/null 2>&1 || true
  echo "pod-down: pod $POD_NAME removed, $LOG_VOLUME and $KEYLOG_VOLUME wiped"
fi
