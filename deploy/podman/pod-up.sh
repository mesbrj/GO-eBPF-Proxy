#!/usr/bin/env bash
# Brings up the rootful app+sidecar pod (deploy/podman): shared net/ipc/uts
# namespaces (no shared PID namespace -- AD-010 replaced the eBPF-uprobe TLS
# key extraction with an LD_PRELOAD interposer, so the sidecar no longer needs
# to resolve or attach to the app's PID/libssl inode), host cgroup namespace
# (--cgroupns=host) so the eBPF connect4/sockops programs attach at the pod's
# common parent cgroup, CAP_BPF+CAP_NET_ADMIN+CAP_SYS_RESOURCE on the sidecar
# only, and /sys/fs/bpf + /sys/fs/cgroup mounts. The sidecar runs entirely as
# UID 1337 (AD-002 loop avoidance: connect4 skips UID 1337). No CA injection:
# the app container validates the real server certificate end-to-end. Must be
# run as root (rootful podman; MVP has no rootless path).
# CAP_SYS_RESOURCE is also required: cilium/ebpf's loader raises RLIMIT_MEMLOCK
# on load, which needs it even though the spec's cap list only names the two
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
# nginx:alpine: a normal, long-lived process dynamically linked against
# libssl -- still a convenient real target for the LD_PRELOAD interposer
# (unrelated to uprobes/inode resolution, which no longer apply here).
APP_IMAGE="${APP_IMAGE:-docker.io/library/nginx:alpine}"
SIDECAR_IMAGE="${SIDECAR_IMAGE:-docker.io/library/alpine:3}"
SIDECAR_BIN="${SIDECAR_BIN:-$REPO_ROOT/bin/app}"
LOG_VOLUME="${LOG_VOLUME:-${POD_NAME}-sidecar-logs}"
KEYLOG_VOLUME="${KEYLOG_VOLUME:-${POD_NAME}-keylog-sock}"
CAPTURE_IFACE="${CAPTURE_IFACE:-eth0}"
PRELOAD_SO="${PRELOAD_SO:-$REPO_ROOT/preload/libkeylogpreload.so}"
KEYLOG_DIR="/run/keylog"
KEYLOG_SOCKET="$KEYLOG_DIR/keylog.sock"

if [[ ! -x "$SIDECAR_BIN" ]]; then
  echo "pod-up: sidecar binary not found at $SIDECAR_BIN (run: go build -o bin/app ./cmd/app)" >&2
  exit 1
fi

# Build the LD_PRELOAD interposer fresh so the pod always tests the current
# tree, not a stale .so (mirrors the sidecar binary precondition above).
make -C "$REPO_ROOT" build-preload

if [[ ! -f "$PRELOAD_SO" ]]; then
  echo "pod-up: interposer not found at $PRELOAD_SO (build-preload failed?)" >&2
  exit 1
fi

# /sys/fs/bpf is root-owned 0700; the sidecar (UID 1337) needs its pin dir
# pre-created and chowned before it can bpf_obj_pin under it.
mkdir -p /sys/fs/bpf/go-ebpf-proxy
chown -R 1337:1337 /sys/fs/bpf/go-ebpf-proxy

podman pod create \
  --name "$POD_NAME" \
  --share net,ipc,uts \
  --replace

podman volume create "$LOG_VOLUME" >/dev/null 2>&1 || true
# Shared keylog socket directory: mounted into both containers below so the
# interposer (app container, arbitrary UID) and the socket server (sidecar,
# UID 1337) can rendezvous on the same socket file despite the UID mismatch
# (see feature-02 design.md's socket-directory Tech Decision: 0711 dir,
# chmod 0666 on the bound socket file -- NewSocketServer does both itself).
podman volume create "$KEYLOG_VOLUME" >/dev/null 2>&1 || true

# The pod's common parent cgroup under a host-shared cgroup namespace; verify
# against your podman cgroup manager (cgroupfs vs systemd) if attach fails.
# Resolved before either container starts -- podman pod inspect only needs
# the pod itself to exist.
POD_CGROUP="/sys/fs/cgroup/$(podman pod inspect "$POD_NAME" --format '{{.CgroupPath}}' 2>/dev/null || true)"

# Sidecar starts BEFORE the app container (spec.md: "sidecar listens on the
# keylog socket before the app container starts" -- the interposer only
# retries briefly then silently drops a line if the socket isn't reachable
# yet, so starting the app first would race an early handshake against the
# sidecar's own listener).
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
  --cap-add CAP_SYS_RESOURCE \
  --volume /sys/fs/bpf:/sys/fs/bpf \
  --volume /sys/fs/cgroup:/sys/fs/cgroup \
  --volume "$SIDECAR_BIN:/usr/local/bin/app:ro,z" \
  --volume "${LOG_VOLUME}:/var/log/sidecar" \
  --volume "${KEYLOG_VOLUME}:${KEYLOG_DIR}" \
  --tmpfs /var/log/sidecar-keylog-tmpfs \
  "$SIDECAR_IMAGE" \
  /usr/local/bin/app \
    --cgroup-path="$POD_CGROUP" \
    --capture-iface="$CAPTURE_IFACE" \
    --keylog-socket="$KEYLOG_SOCKET" \
    --keylog-path=/var/log/sidecar-keylog-tmpfs/keylog/sslkeylog.log \
    --capture-path=/var/log/sidecar/dump.pcapng

# Wait for the sidecar to actually bind the keylog socket before starting the
# app container -- the volume's host-visible mountpoint lets us poll for the
# socket file without needing a shared PID/mount namespace (mirrors how
# smoke_e2e_test.go's volumeCapturePath already resolves the log volume).
KEYLOG_VOLUME_MOUNT="$(podman volume inspect "$KEYLOG_VOLUME" --format '{{.Mountpoint}}')"
for _ in $(seq 1 100); do
  [[ -S "$KEYLOG_VOLUME_MOUNT/keylog.sock" ]] && break
  sleep 0.1
done
if [[ ! -S "$KEYLOG_VOLUME_MOUNT/keylog.sock" ]]; then
  echo "pod-up: keylog socket did not appear at $KEYLOG_VOLUME_MOUNT/keylog.sock within 10s" >&2
  exit 1
fi

podman run -d \
  --pod "$POD_NAME" \
  --name "${POD_NAME}-app" \
  --replace \
  --cgroupns=host \
  --volume "$PRELOAD_SO:/usr/local/lib/libkeylogpreload.so:ro,z" \
  --volume "${KEYLOG_VOLUME}:${KEYLOG_DIR}" \
  --env "LD_PRELOAD=/usr/local/lib/libkeylogpreload.so" \
  --env "GOEBPF_PRELOAD_SOCKET=${KEYLOG_SOCKET}" \
  "$APP_IMAGE"

echo "pod-up: pod $POD_NAME is up (cgroup $POD_CGROUP)"
