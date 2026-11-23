#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Ejecutar con: sudo bash $0"
  exit 1
fi

# IPs permitidas para SSH real (puerto 2200). Edita esta lista si cambian.
ALLOW_IPS="10.1.0.0/24 170.80.30.1"

echo "==> agregando reglas restringidas (primero, para no cortar acceso)"
for ip in $ALLOW_IPS; do
  ufw allow from "$ip" to any port 2200 proto tcp comment "SSH real desde $ip"
done

echo "==> quitando la regla amplia de 2200"
ufw delete allow 2200/tcp || true

echo "==> estado de ufw"
ufw status verbose
