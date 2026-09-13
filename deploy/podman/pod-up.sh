#!/usr/bin/env bash
# Brings up the rootful app+sidecar pod (deploy/podman): shared PID/net/ipc/uts
# namespaces, host cgroup namespace (--cgroupns=host) so the eBPF programs
# attach at the pod's common parent cgroup, CAP_BPF+CAP_NET_ADMIN+CAP_PERFMON
# on the sidecar only, and /sys/fs/bpf + /sys/fs/cgroup mounts. The sidecar
# runs entirely as UID 1337 (AD-002 loop avoidance: connect4 skips UID 1337).
# No CA injection: the app container validates the real server certificate
# end-to-end. Must be run as root (rootful podman; MVP has no rootless path).
# CAP_SYS_RESOURCE is also required: cilium/ebpf's loader raises RLIMIT_MEMLOCK
# on load, which needs it even though the spec's cap list only names the three
# above (found empirically running this script rootful). This host's default
# podman AppArmor profile and seccomp profile each independently block one step
# of BPF map create/pin (confirmed empirically: each alone still fails, only
# lifting both together succeeds), so the sidecar also disables both -- the
# capability set above is what actually authorises the operations; these two
# flags only remove this host's default profiles, which pre-date CAP_BPF.
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "pod-up: must run as root (rootful podman; see feature-03 functional requirements)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

POD_NAME="${POD_NAME:-go-ebpf-proxy}"
# nginx:alpine (not plain alpine): it keeps libssl.so mapped for its whole
# lifetime as PID 1, so uprobe discovery via /proc/<pid>/maps succeeds, and it
# ships curl linked against the same libssl.so the uprobe attaches to (uprobes
# are per-inode, so a later `curl` exec into the same file also fires it).
APP_IMAGE="${APP_IMAGE:-docker.io/library/nginx:alpine}"
SIDECAR_IMAGE="${SIDECAR_IMAGE:-docker.io/library/alpine:3}"
SIDECAR_BIN="${SIDECAR_BIN:-$REPO_ROOT/bin/app}"
LOG_VOLUME="${LOG_VOLUME:-${POD_NAME}-sidecar-logs}"
CAPTURE_IFACE="${CAPTURE_IFACE:-eth0}"
OPENSSL_VERSION="${OPENSSL_VERSION:-3.x}"

if [[ ! -x "$SIDECAR_BIN" ]]; then
  echo "pod-up: sidecar binary not found at $SIDECAR_BIN (run: go build -o bin/app ./cmd/app)" >&2
  exit 1
fi

# /sys/fs/bpf is root-owned 0700; the sidecar (UID 1337) needs its pin dirs
# pre-created and chowned before it can bpf_obj_pin under them.
mkdir -p /sys/fs/bpf/go-ebpf-proxy /sys/fs/bpf/go-ebpf-proxy-keylog
chown -R 1337:1337 /sys/fs/bpf/go-ebpf-proxy /sys/fs/bpf/go-ebpf-proxy-keylog

podman pod create \
  --name "$POD_NAME" \
  --share pid,net,ipc,uts \
  --replace

podman volume create "$LOG_VOLUME" >/dev/null 2>&1 || true

podman run -d \
  --pod "$POD_NAME" \
  --name "${POD_NAME}-app" \
  --replace \
  --cgroupns=host \
  "$APP_IMAGE"

# nginx's PID as seen from *inside* the pod's shared PID namespace -- not the
# host-relative PID `podman inspect` reports, which is a different numbering
# and would resolve to the wrong (or no) /proc/<pid>/maps from the sidecar.
APP_PID="$(podman exec "${POD_NAME}-app" pgrep -o nginx)"
# The pod's common parent cgroup under a host-shared cgroup namespace; verify
# against your podman cgroup manager (cgroupfs vs systemd) if attach fails.
POD_CGROUP="/sys/fs/cgroup/$(podman pod inspect "$POD_NAME" --format '{{.CgroupPath}}' 2>/dev/null || true)"

podman run -d \
  --pod "$POD_NAME" \
  --name "${POD_NAME}-sidecar" \
  --replace \
  --cgroupns=host \
  --security-opt apparmor=unconfined \
  --security-opt seccomp=unconfined \
  --user 1337:1337 \
  --cap-drop ALL \
  --cap-add CAP_BPF \
  --cap-add CAP_NET_ADMIN \
  --cap-add CAP_PERFMON \
  --cap-add CAP_SYS_RESOURCE \
  --volume /sys/fs/bpf:/sys/fs/bpf \
  --volume /sys/fs/cgroup:/sys/fs/cgroup \
  --volume "$SIDECAR_BIN:/usr/local/bin/app:ro,z" \
  --volume "${LOG_VOLUME}:/var/log/sidecar" \
  --tmpfs /var/log/sidecar-keylog-tmpfs \
  "$SIDECAR_IMAGE" \
  /usr/local/bin/app \
    --cgroup-path="$POD_CGROUP" \
    --pid="$APP_PID" \
    --capture-iface="$CAPTURE_IFACE" \
    --openssl-version="$OPENSSL_VERSION" \
    --keylog-path=/var/log/sidecar-keylog-tmpfs/keylog/sslkeylog.log \
    --capture-path=/var/log/sidecar/dump.pcapng

echo "pod-up: pod $POD_NAME is up (app pid $APP_PID, cgroup $POD_CGROUP)"
