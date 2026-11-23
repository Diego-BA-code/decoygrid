# DecoyGrid

Plataforma de cyber deception defensiva para un solo servidor Ubuntu:
senuelos de alta fidelidad, breadcrumbs, honeytokens, mapeo MITRE ATT&CK,
consola web y alertas por Telegram/webhook.

## Requisitos

- Ubuntu 24.04+ (probado en 26.04 LTS)
- Docker Engine + Compose v2
- `net.ipv4.ip_unprivileged_port_start=0` (para que Cowrie ligue el puerto 22 sin root)

## Puesta en marcha

```bash
cp .env.example .env        # y edita las claves
make up                     # construye y levanta todo
make ps                     # estado de los contenedores
make logs                   # logs en vivo
```

## Acceso a la consola

Abre `http://10.1.0.20:8443` (usuario `admin` + contraseña de `.env` + código 2FA).
El primer login te pide activar TOTP con Google Authenticator/Authy.

## Puertos

- SSH real del host: **2200** (solo llave, sin root, sin contraseña).
- Señuelos:
  - Cowrie: SSH en **22**, Telnet en 2223.
  - OpenCanary: HTTP 80, FTP 21, SMB 445, MySQL 3306, MSSQL 1433, RDP 3389,
    SIP 5060/UDP, VNC 5900.
  - Canary tokens: 9000.
- Panel: 8443.

## Breadcrumbs y honeytokens

Tipos: `credential`, `api_key`, `canary_url`, `document`, `database`.
Los de tipo `document` generan `.docx`/`.xlsx`/`.pdf` descargables con el token
incrustado. Sincroniza credenciales con Cowrie con `make breadcrumbs-sync`.

## Cobertura MITRE ATT&CK

En la consola, `cobertura MITRE` muestra las técnicas detectadas y permite
descargar la capa para ATT&CK Navigator (`/api/coverage/layer`).

## Backup / restauracion

```bash
make backup       # snapshot SQLite + backup cifrado con restic
make restore-test # restaura el ultimo snapshot y verifica integridad
```

Backups cifrados a `RESTIC_REPO_DIR` con `RESTIC_PASSWORD` (en `.env`).
Para copia fuera del servidor, apunta `RESTIC_REPOSITORY` a S3/SFTP.

### Backup diario automatico (cron de usuario)

```bash
crontab -e
# agregar:
0 3 * * * cd /home/datacenter/decoygrid && ./scripts/backup.sh >> /home/datacenter/backup.log 2>&1
```

## Endurecimiento

- `scripts/harden-ssh.sh` (etapas 1-3): mueve el SSH real a 2200, activa
  solo-llave y sin root. Corre cada etapa con `sudo bash scripts/harden-sshN.sh`.
- `scripts/restrict-ssh-ip.sh`: restringe el SSH (2200) a la red local y a
  la IP remota autorizada.
- `ufw` con default deny entrante; solo se abren los puertos de señuelos, el
  panel y el SSH real.

## Notas de seguridad

- Los señuelos usan red `host` para ver la IP real del atacante; el plano de
  control vive en una red bridge privada. El bloqueo de egress de los señuelos
  y la separacion completa por interfaz (ipvlan/macvlan) quedan para la Fase 2.
- Pendiente: acceso por VPN (WireGuard) antes de exponer IPs publicas.
