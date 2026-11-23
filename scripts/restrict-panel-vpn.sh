#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Ejecutar con: sudo bash $0"
  exit 1
fi

echo "==> permitiendo el panel solo desde la VPN (10.66.0.0/24)"
ufw allow from 10.66.0.0/24 to any port 8443 proto tcp comment "Panel via VPN"

echo "==> quitando el acceso amplio al panel"
ufw delete allow 8443/tcp || true

echo "==> estado de ufw"
ufw status verbose
