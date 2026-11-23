#!/usr/bin/env python3
"""Prueba E2E de DecoyGrid: nmap + login SSH fallido -> alerta en < 2s."""

import http.cookiejar
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

BASE = os.environ.get("DECOYGRID_BASE", "http://127.0.0.1:8443")
ADMIN = os.environ.get("DECOYGRID_ADMIN_USER", "admin")
PASSWORD = os.environ.get("DECOYGRID_ADMIN_PASSWORD", "test-admin-password")
SSH_HOST = os.environ.get("DECOYGRID_SSH_HOST", "127.0.0.1")
SSH_PORT = os.environ.get("DECOYGRID_SSH_PORT", "2222")
MAX_SECONDS = float(os.environ.get("DECOYGRID_E2E_MAX_SECONDS", "2.0"))


def wait_healthy(timeout: int = 180) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(f"{BASE}/health", timeout=3) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(2)
    return False


def login():
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    data = urllib.parse.urlencode({"username": ADMIN, "password": PASSWORD}).encode()
    opener.open(
        urllib.request.Request(f"{BASE}/login", data=data, method="POST"),
        timeout=10,
    )
    return opener


def count_failed(opener) -> int:
    with opener.open(f"{BASE}/api/events", timeout=10) as r:
        evs = json.loads(r.read()).get("events", [])
    return sum(1 for e in evs if e.get("event_type") == "cowrie.login.failed")


def nmap_like() -> None:
    if shutil.which("nmap"):
        subprocess.run(["nmap", "-Pn", "-p", SSH_PORT, SSH_HOST], capture_output=True)
        return
    s = socket.create_connection((SSH_HOST, int(SSH_PORT)), timeout=5)
    s.recv(128)
    s.close()


def failed_ssh() -> None:
    cmd = [
        "ssh", "-p", SSH_PORT,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password",
        "-o", "PubkeyAuthentication=no",
        "-o", "NumberOfPasswordPrompts=1",
        f"root@{SSH_HOST}", "id",
    ]
    if shutil.which("sshpass"):
        subprocess.run(["sshpass", "-p", "WrongPasswordE2E"] + cmd, capture_output=True)
        return
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/sh\necho 'WrongPasswordE2E'\n")
        askpass = f.name
    os.chmod(askpass, 0o700)
    env = dict(
        os.environ,
        SSH_ASKPASS=askpass,
        SSH_ASKPASS_REQUIRE="force",
        DISPLAY=":0",
    )
    subprocess.run(cmd, capture_output=True, env=env)
    os.unlink(askpass)


def main() -> None:
    if not wait_healthy():
        print("FAIL: el stack no quedo saludable")
        sys.exit(1)

    opener = login()
    before = count_failed(opener)
    nmap_like()

    start = time.time()
    failed_ssh()
    found = False
    while time.time() - start < MAX_SECONDS + 1.0:
        if count_failed(opener) > before:
            found = True
            break
        time.sleep(0.1)
    elapsed = time.time() - start

    if found and elapsed <= MAX_SECONDS:
        print(f"PASS: alerta cowrie.login.failed detectada en {elapsed:.2f}s")
        sys.exit(0)
    print(f"FAIL: no se detecto a tiempo (elapsed={elapsed:.2f}s, max={MAX_SECONDS}s)")
    sys.exit(1)


if __name__ == "__main__":
    main()
