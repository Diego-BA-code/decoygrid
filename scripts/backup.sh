#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] && set -a && . ./.env && set +a

REPO_DIR="${RESTIC_REPO_DIR:-$HOME/restic-repo}"
PASSWORD="${RESTIC_PASSWORD:?Falta RESTIC_PASSWORD en .env}"
IMAGE="restic/restic:0.20.0"
RU="$(id -u):$(id -g)"

mkdir -p "$REPO_DIR"

echo "==> snapshot SQLite consistente"
docker compose exec -T app python -c "import sqlite3,time; c=sqlite3.connect('/data/decoygrid.db'); b=sqlite3.connect('/data/backup-'+time.strftime('%Y%m%d-%H%M%S')+'.db'); c.backup(b); b.close(); c.close(); print('snapshot ok')"

if ! docker run --rm -u "$RU" -e HOME=/tmp -v "$REPO_DIR:/repo" -e RESTIC_REPOSITORY=/repo -e RESTIC_PASSWORD="$PASSWORD" "$IMAGE" snapshots >/dev/null 2>&1; then
  echo "==> inicializando repositorio restic"
  docker run --rm -u "$RU" -e HOME=/tmp -v "$REPO_DIR:/repo" -e RESTIC_REPOSITORY=/repo -e RESTIC_PASSWORD="$PASSWORD" "$IMAGE" init
fi

echo "==> backup cifrado con restic"
docker run --rm -u "$RU" -e HOME=/tmp \
  -v decoygrid_app-data:/data:ro \
  -v "$REPO_DIR:/repo" \
  -e RESTIC_REPOSITORY=/repo -e RESTIC_PASSWORD="$PASSWORD" \
  "$IMAGE" backup /data

echo "==> retencion (7 diarios, 4 semanales, 6 mensuales)"
docker run --rm -u "$RU" -e HOME=/tmp \
  -v "$REPO_DIR:/repo" \
  -e RESTIC_REPOSITORY=/repo -e RESTIC_PASSWORD="$PASSWORD" \
  "$IMAGE" forget --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune

echo "backup completado"
