#!/usr/bin/env bash
# Deploy the Kia API container on the Oracle box.
#
# Same shape and reasoning as benchbot-deploy.sh: the flags live in a script on
# the host so they cannot be forgotten when a person or a model retypes a
# docker run. Build with the old container still serving, health check the new
# one, and roll back if it never comes up.
#
# Version-controlled at deploy/kia-deploy.sh in the Kia-Android-Widget repo.
# The host copy must match. This script cannot deploy itself - git pull updates
# the checkout, not /home/opc/bin - so scp it after editing.
set -euo pipefail

REPO=/home/opc/kia-android-widget
ENV_FILE=/home/opc/kia.env
NAME=kia-api
IMAGE=kia-api
PORT=5000
LOG=/home/opc/kia-deploy.log

exec > >(tee -a "$LOG") 2>&1
echo "=== $(date -Is) deploy starting ==="

# Refuse rather than come up misconfigured: without the env file the app starts
# happily and then 503s on every request with no credentials.
[ -f "$ENV_FILE" ] || { echo "FATAL: $ENV_FILE missing"; exit 1; }
[ -d "$REPO" ]     || { echo "FATAL: $REPO missing"; exit 1; }

cd "$REPO"
git pull --ff-only

# Keep the current image so a bad build has something to fall back to.
if docker image inspect "$IMAGE:latest" >/dev/null 2>&1; then
  docker tag "$IMAGE:latest" "$IMAGE:previous"
  echo "tagged current image as :previous"
fi

# Build while the old container is still serving - a failed build costs nothing.
docker build -f deploy/Dockerfile -t "$IMAGE:latest" .

start_container() {
  local tag="$1"
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d \
    --name "$NAME" \
    --restart unless-stopped \
    --env-file "$ENV_FILE" \
    -p 127.0.0.1:${PORT}:5000 \
    "$IMAGE:$tag"
}

echo "starting $IMAGE:latest"
start_container latest

# /health needs no credentials and no Kia call, so it answers immediately once
# the app is up. Anything slower would be testing the car, not the deploy.
for i in $(seq 1 30); do
  if curl -fsS -m 5 "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
    echo "healthy after ${i}s"
    docker image prune -f >/dev/null 2>&1 || true
    echo "=== $(date -Is) deploy OK ==="
    exit 0
  fi
  sleep 1
done

echo "FATAL: never became healthy - rolling back"
docker logs --tail 40 "$NAME" || true
if docker image inspect "$IMAGE:previous" >/dev/null 2>&1; then
  start_container previous
  echo "rolled back to :previous"
else
  echo "no :previous image to roll back to - container left stopped"
  docker rm -f "$NAME" >/dev/null 2>&1 || true
fi
exit 1
