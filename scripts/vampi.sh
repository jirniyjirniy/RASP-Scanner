#!/usr/bin/env bash
# Управление локальным стендом VAmPI в Docker.
#   ./scripts/vampi.sh up      — поднять и засеять
#   ./scripts/vampi.sh reset   — пересоздать с нуля (чистый сид)
#   ./scripts/vampi.sh down     — остановить и удалить
set -euo pipefail

NAME=vampi
HOST_PORT="${VAMPI_PORT:-5001}"
IMAGE=erev0s/vampi:latest
BASE="http://localhost:${HOST_PORT}"

wait_ready() {
  for _ in $(seq 1 40); do curl -sf -o /dev/null "${BASE}/" && return 0; sleep 0.5; done
  echo "VAmPI не поднялся на ${BASE}" >&2; return 1
}

case "${1:-up}" in
  up)
    docker ps --format '{{.Names}}' | grep -qx "$NAME" && echo "уже запущен" && exit 0
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" -p "${HOST_PORT}:5000" "$IMAGE" >/dev/null
    wait_ready && curl -s "${BASE}/createdb" && echo && echo "VAmPI готов: ${BASE}"
    ;;
  reset)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" -p "${HOST_PORT}:5000" "$IMAGE" >/dev/null
    wait_ready && curl -s "${BASE}/createdb" && echo && echo "VAmPI пересоздан: ${BASE}"
    ;;
  down)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    echo "VAmPI остановлен"
    ;;
  *)
    echo "usage: $0 {up|reset|down}" >&2; exit 1 ;;
esac
