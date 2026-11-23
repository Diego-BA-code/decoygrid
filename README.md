# DecoyGrid

Plataforma de cyber deception defensiva para un solo servidor Ubuntu.
Fase 1 (MVP): Cowrie (SSH/Telnet), OpenCanary (HTTP/SMB), colector con
normalizacion ECS + deduplicacion + mapeo MITRE ATT&CK, alertas por
webhook/Telegram y consola minima.

## Requisitos

- Ubuntu 24.04+ (probado en 26.04 LTS)
- Docker Engine + Compose v2

## Puesta en marcha

```bash
cp .env.example .env        # y edita las claves
make up                     # construye y levanta todo
make ps                     # estado de los contenedores
make logs                   # logs en vivo
```

## Acceso a la consola (temporal, por tunel SSH)

El panel corre en HTTP detras de Caddy, publicado solo en localhost.
Desde tu maquina:

```bash
ssh -L 8443:127.0.0.1:8443 datacenter@10.1.0.20
```

y abre http://localhost:8443 en tu navegador. Usuario/contraseña segun `.env`.

## Puertos de los señuelos

- Cowrie: SSH en 2222, Telnet en 2223 (el SSH real del host sigue en 22).
- OpenCanary: HTTP en 80, SMB en 445.

## Backup / restauracion

```bash
make backup       # snapshot SQLite + backup cifrado con restic
make restore-test # restaura el ultimo snapshot y verifica integridad
```

Los backups van cifrados (AES) a `RESTIC_REPO_DIR` con la clave `RESTIC_PASSWORD`
(ambas en `.env`). Para copia fuera del servidor, apunta el repositorio a S3/SFTP
con `RESTIC_REPOSITORY`.

### Backup diario automatico (cron de usuario)

```bash
crontab -e
# agregar:
0 3 * * * cd /home/datacenter/decoygrid && ./scripts/backup.sh >> /home/datacenter/backup.log 2>&1
```

## Notas de seguridad (conocidas en esta fase)

- Los señuelos usan red `host` para ver la IP real del atacante; el plano de
  control vive en una red bridge privada. El bloqueo de egress de los señuelos
  y la separacion completa por interfaz (ipvlan/macvlan) se implementan en la
  Fase 2.
- TOTP para el panel se agrega en la siguiente iteracion (hoy: Argon2 + sesion
  firmada + log de auditoria).
