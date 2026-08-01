#!/bin/sh
set -eu

IMAGE="${1:?usage: scripts/container-smoke.sh IMAGE}"
CONTAINER_ID=""

cleanup() {
  if [ -n "$CONTAINER_ID" ]; then
    docker logs "$CONTAINER_ID" 2>&1 || true
    docker stop "$CONTAINER_ID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

configured_user="$(docker image inspect --format '{{.Config.User}}' "$IMAGE")"
case "$configured_user" in
  ""|root|0|0:0)
    echo "ERROR: container image must configure a non-root user" >&2
    exit 1
    ;;
esac

docker run --rm --entrypoint python "$IMAGE" convert.py --help >/dev/null

CONTAINER_ID="$(docker run --rm -d \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -p 127.0.0.1::8080 \
  "$IMAGE")"

host_port="$(docker port "$CONTAINER_ID" 8080/tcp | sed -n '1s/.*://p')"
if [ -z "$host_port" ]; then
  echo "ERROR: could not resolve the container's published port" >&2
  exit 1
fi

attempt=0
until curl --fail --silent --show-error \
  "http://127.0.0.1:${host_port}/healthz" | grep -q '"status":"ok"'; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "ERROR: container health endpoint did not become ready" >&2
    exit 1
  fi
  sleep 1
done

curl --fail --silent --show-error \
  --form-string 'config_text=set service "TCP/8080" protocol tcp src-port 0-65535 dst-port 8080-8080' \
  --form-string 'action=preview' \
  "http://127.0.0.1:${host_port}/convert" | grep -q 'tcp_8080'

echo "Container CLI, health, and conversion smoke checks passed for $IMAGE."
