#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Exporta los breadcrumbs activos (credenciales no usadas) al userdb de Cowrie
# y reinicia el senuelo para que los acepte como logins validos.

TMP=$(mktemp)
docker compose exec -T app python - > "$TMP" <<'PY'
import sqlite3
c = sqlite3.connect('/data/decoygrid.db')
for u, p in c.execute(
    "select username, password from breadcrumbs where kind='credential' and burned_at is null"
):
    print(f"{u}:x:{p}")
PY

cat "$TMP" >> cowrie/userdb.txt
sort -u cowrie/userdb.txt -o cowrie/userdb.txt
rm -f "$TMP"

docker compose restart cowrie
echo "Breadcrumbs sincronizados con Cowrie. Senuelo reiniciado."
