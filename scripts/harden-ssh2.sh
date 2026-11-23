#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Ejecutar con: sudo bash $0"
  exit 1
fi

echo "==> desactivando activacion por socket (ssh.socket)"
systemctl disable --now ssh.socket

echo "==> activando ssh.service (escuchara segun sshd_config)"
systemctl enable --now ssh.service
systemctl restart ssh.service

echo "==> puertos sshd activos (deberia mostrar 22 y 2200):"
ss -tlnp 2>/dev/null | grep -i sshd | awk '{print $4}' || true
echo "Etapa 2 completada."
