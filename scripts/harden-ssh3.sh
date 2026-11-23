#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Ejecutar con: sudo bash $0"
  exit 1
fi

cat > /etc/ssh/sshd_config.d/00-decoygrid.conf <<'EOF'
# Hardening DecoyGrid - etapa final: SSH real solo en 2200
Port 2200
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
EOF

sshd -t
systemctl restart ssh.service

echo "SSH real movido a 2200. El puerto 22 queda libre para el senuelo Cowrie."
echo "Puertos sshd activos:"
ss -tlnp 2>/dev/null | grep -i sshd | awk '{print $4}' || true
