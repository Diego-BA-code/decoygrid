#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Ejecutar con: sudo bash $0"
  exit 1
fi

if ! command -v wg >/dev/null 2>&1; then
  echo "==> instalando wireguard-tools"
  apt-get update
  apt-get install -y wireguard-tools
fi

mkdir -p /etc/wireguard
if [ ! -f /etc/wireguard/server_private ]; then
  wg genkey | tee /etc/wireguard/server_private | wg pubkey > /etc/wireguard/server_public
  wg genkey | tee /etc/wireguard/client_private | wg pubkey > /etc/wireguard/client_public
fi
chmod 600 /etc/wireguard/*_private 2>/dev/null || true

SERVER_PRIV=$(cat /etc/wireguard/server_private)
SERVER_PUB=$(cat /etc/wireguard/server_public)
CLIENT_PRIV=$(cat /etc/wireguard/client_private)
CLIENT_PUB=$(cat /etc/wireguard/client_public)

# Endpoint: usa la IP local por ahora; cambia a tu IP publica/dominio al exponer.
ENDPOINT="${WG_ENDPOINT:-10.1.0.20}"

cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.66.0.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIV

[Peer]
PublicKey = $CLIENT_PUB
AllowedIPs = 10.66.0.2/32
EOF
chmod 600 /etc/wireguard/wg0.conf

echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-decoygrid-wireguard.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null

systemctl enable --now wg-quick@wg0

ufw allow 51820/udp comment "WireGuard VPN"

cat > /home/datacenter/wg0-client.conf <<EOF
[Interface]
PrivateKey = $CLIENT_PRIV
Address = 10.66.0.2/32

[Peer]
PublicKey = $SERVER_PUB
Endpoint = $ENDPOINT:51820
AllowedIPs = 10.66.0.0/24
EOF
chmod 600 /home/datacenter/wg0-client.conf

echo ""
echo "=== CONFIG DEL CLIENTE (tambien en ~/wg0-client.conf) ==="
cat /home/datacenter/wg0-client.conf
echo ""
echo "=== estado de la VPN ==="
wg show
