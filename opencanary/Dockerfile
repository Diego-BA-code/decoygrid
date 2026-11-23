FROM thinkst/opencanary@sha256:12ea9447a9acd1517a2c0c48819d741c6ce0a0e532fa039ae13835691847f677

# El modulo SMB de OpenCanary requiere Samba (smbd) y rsyslog, que no vienen
# en la imagen oficial. Los instalamos y dejamos un smb.conf con full_audit.
RUN apt-get update \
    && apt-get install -y --no-install-recommends samba samba-vfs-modules smbclient rsyslog \
    && rm -rf /var/lib/apt/lists/*

COPY smb.conf /etc/samba/smb.conf
COPY rsyslog-samba.conf /etc/rsyslog.d/samba.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && mkdir -p /samba/IT /samba/backup \
    && printf 'Informe de respaldo - DecoyGrid\n' > /samba/IT/informe.txt \
    && printf 'backup-2026.tar.gz\n' > /samba/backup/lista.txt

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--dev"]
