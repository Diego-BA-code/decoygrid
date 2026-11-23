#!/bin/sh
set -e

mkdir -p /var/lib/samba/private /var/cache/samba /run/samba /var/tmp/samba

rsyslogd
smbd -F -s /etc/samba/smb.conf &
sleep 2

exec opencanaryd "$@"
