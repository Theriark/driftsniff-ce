#!/usr/bin/env bash
# Container smoke test. Builds the image (unless SKIP_BUILD=1), runs it with the hardening
# flags of compose.yaml and asserts the runtime contract: non-root uid 10001, read-only root
# file system, writable /data and /keys, no compiler, image under 250 MB, healthy within 30
# seconds and /healthz answering. The container and its volumes are always removed.
#
# Usage: bash scripts/container-smoke.sh
# Environment: IMAGE (default driftsniff:smoke), SKIP_BUILD (1 = use the existing IMAGE),
#              SOURCE_SHA (revision label when building), MAX_IMAGE_BYTES (default 250000000).
set -euo pipefail

IMAGE="${IMAGE:-driftsniff:smoke}"
SOURCE_SHA="${SOURCE_SHA:-smoke}"
MAX_IMAGE_BYTES="${MAX_IMAGE_BYTES:-250000000}"
HEALTH_WAIT_SECONDS=30
EXPECTED_UID=10001

container="driftsniff-smoke-$$"
data_volume="driftsniff-smoke-data-$$"
keys_volume="driftsniff-smoke-keys-$$"

fail() {
  echo "::error::container smoke: $*" >&2
  exit 1
}

pass() {
  echo "ok: $*"
}

cleanup() {
  local status=$?
  if [[ ${status} -ne 0 ]]; then
    docker logs "${container}" 2>&1 | tail -n 50 || true
  fi
  docker rm --force "${container}" >/dev/null 2>&1 || true
  docker volume rm --force "${data_volume}" "${keys_volume}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  docker build --build-arg SOURCE_SHA="${SOURCE_SHA}" --tag "${IMAGE}" .
fi
docker image inspect "${IMAGE}" >/dev/null 2>&1 || fail "image ${IMAGE} does not exist"

# Image properties.
config_user="$(docker image inspect --format '{{.Config.User}}' "${IMAGE}")"
case "${config_user}" in
  "" | 0 | root | 0:* | root:*) fail "image must run as a non-root user (User='${config_user}')" ;;
  *) pass "image user is ${config_user}" ;;
esac

size_bytes="$(docker image inspect --format '{{.Size}}' "${IMAGE}")"
if (( size_bytes >= MAX_IMAGE_BYTES )); then
  fail "image is ${size_bytes} bytes, limit is ${MAX_IMAGE_BYTES}"
fi
pass "image size ${size_bytes} bytes is under ${MAX_IMAGE_BYTES}"

licenses="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.licenses"}}' "${IMAGE}")"
[[ "${licenses}" == "MIT" ]] || fail "licenses label is '${licenses}', expected MIT"
revision="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "${IMAGE}")"
[[ -n "${revision}" ]] || fail "revision label is empty"
pass "labels licenses=${licenses} revision=${revision}"

# Run with the production hardening flags.
docker volume create "${data_volume}" >/dev/null
docker volume create "${keys_volume}" >/dev/null
docker run --detach --name "${container}" \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --memory 512m \
  --publish 127.0.0.1::8080 \
  --volume "${data_volume}:/data" --volume "${keys_volume}:/keys" \
  --env DRIFTSNIFF_BASE_URL=http://127.0.0.1:8080 \
  "${IMAGE}" >/dev/null

status=""
for ((second = 0; second < HEALTH_WAIT_SECONDS; second++)); do
  running="$(docker inspect --format '{{.State.Running}}' "${container}")"
  if [[ "${running}" != "true" ]]; then
    fail "container stopped before it became healthy"
  fi
  status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "${container}")"
  if [[ "${status}" == "healthy" ]]; then
    break
  fi
  sleep 1
done
[[ "${status}" == "healthy" ]] || fail "container not healthy after ${HEALTH_WAIT_SECONDS} s (status '${status}')"
pass "container healthy within ${HEALTH_WAIT_SECONDS} s"

# Runtime contract.
readonly_root="$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "${container}")"
[[ "${readonly_root}" == "true" ]] || fail "root file system is not read-only"

uid="$(docker exec "${container}" id -u)"
[[ "${uid}" == "${EXPECTED_UID}" ]] || fail "process runs as uid ${uid}, expected ${EXPECTED_UID}"
pass "process runs as uid ${uid}"

write_output="$(docker exec "${container}" touch /etc/driftsniff-smoke 2>&1 || true)"
[[ "${write_output}" == *"Read-only file system"* ]] \
  || fail "write to /etc was not refused as read-only (output: ${write_output})"
pass "write to /etc is refused (read-only root file system)"

for directory in /data /keys; do
  docker exec "${container}" sh -c "touch '${directory}/.smoke' && rm '${directory}/.smoke'" \
    || fail "${directory} is not writable by uid ${uid}"
  pass "${directory} is writable"
done

for tool in gcc cc make; do
  if docker exec "${container}" sh -c "command -v ${tool}" >/dev/null 2>&1; then
    fail "${tool} is present in the final image"
  fi
done
pass "gcc, cc and make are absent"

host_port="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}' "${container}")"
[[ -n "${host_port}" ]] || fail "no published port for 8080/tcp"
body="$(curl --fail --silent --show-error --max-time 5 "http://127.0.0.1:${host_port}/healthz")"
python3 -c 'import json, sys; data = json.loads(sys.argv[1]); assert data["status"] == "ok" and data["version"] and data["commit"] == sys.argv[2]' "${body}" "${revision}" \
  || fail "/healthz body is not ok with a version and commit ${revision}: ${body}"
pass "/healthz answered ${body}"

echo "container smoke test passed for ${IMAGE}"
