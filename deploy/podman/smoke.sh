#!/usr/bin/env bash
# Smoke test: curl https://example.com (no -k) from the app container,
# end-to-end through the sidecar's transparent redirect. No CA injection: a
# successful request without -k proves the real server certificate was
# validated (no MITM).
set -euo pipefail

POD_NAME="${POD_NAME:-go-ebpf-proxy}"
URL="${URL:-https://example.com}"

status="$(podman exec "${POD_NAME}-app" curl -s -o /dev/null -w '%{http_code}' "$URL")"
if [[ "$status" != "200" ]]; then
  echo "smoke: expected HTTP 200 from $URL, got $status" >&2
  exit 1
fi
echo "smoke: $URL -> HTTP $status"
