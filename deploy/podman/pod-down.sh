#!/usr/bin/env bash
# Tears down the app+sidecar pod. Ephemeral by default: removing the pod
# also removes the sidecar's tmpfs keylog mount and, unless the artifacts are
# retained, the named log volume holding /var/log/sidecar (feature-03: "pod
# teardown wipes /var/log/sidecar"). Whether they are retained is decided
# once, at pod-up.sh time: RETAIN=1 there makes the sidecar keep its capture
# and labels the pod go-ebpf-proxy.retain=1, which this script follows when
# given no choice of its own (AD-019). RETAIN=0 here still wipes a retained
# pod. --retain or RETAIN=1 here is refused, before anything is touched, for
# a pod started without RETAIN=1: its sidecar wipes its own capture when it
# stops, so keeping the volume would keep nothing. A pod with no label, or
# no pod at all, keeps the volume only on --retain or RETAIN=1.
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
# Empty means this invocation made no choice; RETAIN=0 is a choice to wipe.
REQUEST="${RETAIN-}"

for arg in "$@"; do
  case "$arg" in
    --retain) REQUEST=1 ;;
  esac
done

# The label pod-up.sh recorded: 1, 0, or empty for a pod with no label or no
# pod at all.
LABEL="$(podman pod inspect "$POD_NAME" --format '{{index .Labels "go-ebpf-proxy.retain"}}' 2>/dev/null || true)"

if [[ -z "$REQUEST" ]]; then
  RETAIN="${LABEL:-0}"
elif [[ "$REQUEST" == "1" && "$LABEL" == "0" ]]; then
  echo "pod-down: pod $POD_NAME was started without RETAIN=1, so its sidecar wipes its capture when it stops and --retain/RETAIN=1 cannot keep it. Bring the pod up with RETAIN=1 deploy/podman/pod-up.sh to keep artifacts, or run pod-down.sh without --retain. Nothing was removed." >&2
  exit 1
else
  RETAIN="$REQUEST"
fi

podman pod rm -f "$POD_NAME" >/dev/null 2>&1 || true

# The keylog socket volume carries only the socket the interposer connects to
# (the keylog itself is on the sidecar's tmpfs), so --retain does not keep it;
# the sidecar binds a fresh socket on its next start.
podman volume rm -f "$KEYLOG_VOLUME" >/dev/null 2>&1 || true

# A crashed/killed sidecar may not have run its own graceful pin cleanup;
# these bpffs pin dirs are pod-up.sh's compiled-in defaults, safe to remove.
rm -rf /sys/fs/bpf/go-ebpf-proxy /sys/fs/bpf/go-ebpf-proxy-keylog 2>/dev/null || true

if [[ "$RETAIN" == "1" ]]; then
  echo "pod-down: retaining, keeping volume $LOG_VOLUME ($KEYLOG_VOLUME removed)"
else
  podman volume rm -f "$LOG_VOLUME" >/dev/null 2>&1 || true
  echo "pod-down: pod $POD_NAME removed, $LOG_VOLUME and $KEYLOG_VOLUME wiped"
fi
