#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Ejecutar con: sudo bash $0"
  exit 1
fi

echo "==> respaldo de sshd_config"
cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%F-%H%M%S)"

echo "==> escribiendo config de endurecimiento (puertos 22 + 2200, solo llave, sin root)"
cat > /etc/ssh/sshd_config.d/00-decoygrid.conf <<'EOF'
# Hardening DecoyGrid - etapa 1 (22 se mantiene como respaldo)
Port 22
Port 2200
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
EOF

echo "==> validando config"
sshd -t

echo "==> recargando sshd (no corta sesiones existentes)"
systemctl reload ssh

echo "==> abriendo puerto 2200 en ufw"
ufw allow 2200/tcp comment "SSH real (nuevo puerto)"

echo "==> puertos sshd activos:"
ss -tlnp 2>/dev/null | grep -i sshd | awk '{print $4}' || true
echo "Etapa 1 completada. El puerto 22 sigue activo como respaldo."
