#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] && set -a && . ./.env && set +a

REPO_DIR="${RESTIC_REPO_DIR:-$HOME/restic-repo}"
PASSWORD="${RESTIC_PASSWORD:?Falta RESTIC_PASSWORD en .env}"
IMAGE="restic/restic:0.20.0"
RU="$(id -u):$(id -g)"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "==> restaurando ultimo snapshot a directorio temporal"
docker run --rm -u "$RU" -e HOME=/tmp \
  -v "$REPO_DIR:/repo" \
  -v "$TMP:/restore" \
  -e RESTIC_REPOSITORY=/repo -e RESTIC_PASSWORD="$PASSWORD" \
  "$IMAGE" restore latest --target /restore

python3 - "$TMP" <<'PY'
import glob, sqlite3, sys
files = sorted(glob.glob(sys.argv[1] + '/data/backup-*.db'))
if not files:
    print("FAIL: no hay snapshot SQLite en el backup")
    sys.exit(1)
c = sqlite3.connect(files[-1])
n = c.execute("select count(*) from events").fetchone()[0]
print(f"OK: snapshot restaurado con {n} eventos ({files[-1]})")
PY

echo "restore-test ok"
