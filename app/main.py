import hashlib
import json
import os
import secrets
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import docgen
import httpx
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import Boolean, DateTime, Integer, String, Text, create_engine, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from starlette.middleware.sessions import SessionMiddleware
from watchfiles import watch


# ----------------------------------------------------------------------------
# Configuracion
# ----------------------------------------------------------------------------
BASE_DIR = Path(os.getenv("DECOYGRID_DATA_DIR", "/data"))
DB_PATH = BASE_DIR / "decoygrid.db"
LOG_DIRS = [Path("/logs/cowrie"), Path("/logs/opencanary"), Path("/logs/canary")]

ADMIN_USER = os.getenv("DECOYGRID_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("DECOYGRID_ADMIN_PASSWORD", "decoygrid-admin")
SESSION_SECRET = os.getenv("DECOYGRID_SESSION_SECRET", "insecure-change-me")
WEBHOOK_URL = os.getenv("DECOYGRID_WEBHOOK_URL", "")
TG_TOKEN = os.getenv("DECOYGRID_TELEGRAM_BOT_TOKEN", "")
TG_CHAT_ID = os.getenv("DECOYGRID_TELEGRAM_CHAT_ID", "")
ALERT_MIN_SEVERITY = int(os.getenv("DECOYGRID_ALERT_MIN_SEVERITY", "3"))
CANARY_BASE = os.getenv("DECOYGRID_CANARY_BASE", "http://10.1.0.20:9000")
RETENTION_DAYS = int(os.getenv("DECOYGRID_RETENTION_DAYS", "30"))


# ----------------------------------------------------------------------------
# Base de datos (SQLite en modo WAL)
# ----------------------------------------------------------------------------
engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},
)


class Base(DeclarativeBase):
    pass


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    dedup_key: Mapped[str] = mapped_column(String(64), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    engine: Mapped[str] = mapped_column(String(32), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    src_ip: Mapped[str] = mapped_column(String(64), index=True)
    src_port: Mapped[int] = mapped_column(Integer, default=0)
    dst_port: Mapped[int] = mapped_column(Integer, default=0)
    protocol: Mapped[str] = mapped_column(String(16), default="")
    username: Mapped[str] = mapped_column(String(128), default="")
    password: Mapped[str] = mapped_column(String(256), default="")
    technique_id: Mapped[str] = mapped_column(String(16), default="")
    technique_name: Mapped[str] = mapped_column(String(128), default="")
    severity: Mapped[int] = mapped_column(Integer, default=3)
    count: Mapped[int] = mapped_column(Integer, default=1)
    breadcrumb_id: Mapped[str] = mapped_column(String(64), default="")
    raw: Mapped[str] = mapped_column(Text, default="{}")


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[str] = mapped_column(String(64), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    severity: Mapped[int] = mapped_column(Integer, index=True)
    title: Mapped[str] = mapped_column(String(256))
    detail: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="new")
    notified: Mapped[bool] = mapped_column(Boolean, default=False)


class Breadcrumb(Base):
    __tablename__ = "breadcrumbs"
    id: Mapped[int] = mapped_column(primary_key=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(16), default="credential")
    username: Mapped[str] = mapped_column(String(128), default="")
    password: Mapped[str] = mapped_column(String(256), default="")
    secret: Mapped[str] = mapped_column(String(512), default="")
    location: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    burned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    burned_event_id: Mapped[str] = mapped_column(String(64), default="")


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(16), default="admin")
    totp_secret: Mapped[str] = mapped_column(String(64), default="")


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    username: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(128))
    ip: Mapped[str] = mapped_column(String(64), default="")


SessionLocal = sessionmaker(engine, expire_on_commit=False)
ph = PasswordHasher()
templates = Jinja2Templates(directory="/app/templates")


# ----------------------------------------------------------------------------
# Mapeos a MITRE ATT&CK y severidad
# ----------------------------------------------------------------------------
COWRIE_MAP = {
    "cowrie.login.failed": ("T1110", "Brute Force", 3),
    "cowrie.login.success": ("T1078", "Valid Accounts", 4),
    "cowrie.command.input": ("T1059", "Command and Scripting Interpreter", 4),
    "cowrie.session.connect": ("T1595", "Active Scanning", 2),
    "cowrie.session.closed": ("T1595", "Active Scanning", 1),
    "cowrie.client.version": ("T1595", "Active Scanning", 1),
    "cowrie.direct-tcpip.request": ("T1021", "Remote Services", 4),
}

OPEN_MAP = {
    3000: ("T1190", "Exploit Public-Facing Application", 3),  # HTTP GET
    3001: ("T1190", "Exploit Public-Facing Application", 4),  # HTTP POST login
    3002: ("T1190", "Exploit Public-Facing Application", 2),  # HTTP metodo no implementado
    3003: ("T1190", "Exploit Public-Facing Application", 2),  # HTTP redirect
    2000: ("T1110", "Brute Force", 3),                        # FTP login
    4000: ("T1595", "Active Scanning", 2),                    # SSH nueva conexion
    4002: ("T1110", "Brute Force", 3),                        # SSH login attempt
    5000: ("T1021.002", "SMB/Windows Admin Shares", 4),       # SMB file open
    5001: ("T1595", "Active Scanning", 2),                    # portscan SYN
    3100: ("T1204", "User Execution", 3),                     # canary token activado
    2000: ("T1110", "Brute Force", 3),                        # FTP login
    6001: ("T1110", "Brute Force", 3),                        # Telnet login
    8001: ("T1110", "Brute Force", 3),                        # MySQL login
    9001: ("T1110", "Brute Force", 3),                        # MSSQL SQL auth
    9002: ("T1110", "Brute Force", 3),                        # MSSQL Windows auth
    10001: ("T1190", "Exploit Public-Facing Application", 3), # TFTP
    12001: ("T1021.005", "VNC", 4),                           # VNC
    14001: ("T1021.001", "Remote Desktop Protocol", 4),       # RDP
    15001: ("T1190", "Exploit Public-Facing Application", 3), # SIP request
}

DEFAULT_TECH = ("T1595", "Active Scanning", 2)


def _load_mitre() -> dict:
    try:
        p = Path("/app/mitre_techniques.json")
        if p.is_file():
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {"techniques": [], "version": "20.1"}


MITRE_DATA = _load_mitre()
MITRE_TECHNIQUES = MITRE_DATA.get("techniques", [])
MITRE_VERSION = MITRE_DATA.get("version", "20.1")
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


def covered_techniques() -> dict[str, str]:
    ids: dict[str, str] = {}
    for tid, name, _sev in list(COWRIE_MAP.values()) + list(OPEN_MAP.values()):
        ids[tid] = name
    return ids


def parse_ts(value) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def dedup_key(engine: str, event_type: str, src_ip: str, dst_port: int, ts: datetime) -> str:
    bucket = ts.strftime("%Y%m%d%H%M")
    raw = f"{engine}|{event_type}|{src_ip}|{dst_port}|{bucket}"
    return hashlib.md5(raw.encode()).hexdigest()


def normalize_cowrie(d: dict) -> dict | None:
    event_type = d.get("eventid", "unknown")
    tech_id, tech_name, severity = COWRIE_MAP.get(event_type, DEFAULT_TECH)
    ts = parse_ts(d.get("timestamp"))
    src_ip = str(d.get("src_ip", ""))
    dst_port = int(d.get("dst_port", 2222))
    return {
        "event_id": str(uuid.uuid4()),
        "dedup_key": dedup_key("cowrie", event_type, src_ip, dst_port, ts),
        "ts": ts,
        "engine": "cowrie",
        "event_type": event_type,
        "src_ip": src_ip,
        "src_port": int(d.get("src_port", 0)),
        "dst_port": dst_port,
        "protocol": str(d.get("protocol", "ssh")),
        "username": str(d.get("username", "")),
        "password": str(d.get("password", "")),
        "technique_id": tech_id,
        "technique_name": tech_name,
        "severity": severity,
        "raw": json.dumps(d),
    }


def normalize_opencanary(d: dict, engine: str = "opencanary") -> dict | None:
    logtype = int(d.get("logtype", 0))
    tech_id, tech_name, severity = OPEN_MAP.get(logtype, DEFAULT_TECH)
    ts = parse_ts(d.get("utc_time"))
    src_ip = str(d.get("src_host", ""))
    dst_port = int(d.get("dst_port", 0))
    event_type = str(d.get("logtype", logtype))
    return {
        "event_id": str(uuid.uuid4()),
        "dedup_key": dedup_key(engine, event_type, src_ip, dst_port, ts),
        "ts": ts,
        "engine": engine,
        "event_type": f"{engine}.{logtype}",
        "src_ip": src_ip,
        "src_port": int(d.get("src_port", 0)),
        "dst_port": dst_port,
        "protocol": "tcp",
        "username": str(d.get("username", "")),
        "password": str(d.get("password", "")),
        "technique_id": tech_id,
        "technique_name": tech_name,
        "severity": severity,
        "raw": json.dumps(d),
    }


def process_event(raw: dict, engine: str) -> None:
    if engine == "cowrie":
        ev = normalize_cowrie(raw)
    else:
        ev = normalize_opencanary(raw, engine=engine)
    if not ev or not ev["src_ip"]:
        return
    with SessionLocal() as s:
        bc = match_breadcrumb(s, ev)
        if bc is None:
            bc = match_honeytoken(s, ev["raw"])
        if bc:
            ev["breadcrumb_id"] = bc.token
            ev["severity"] = 5
        existing = s.scalar(select(Event).where(Event.dedup_key == ev["dedup_key"]))
        if existing:
            existing.count += 1
            existing.ts = max(existing.ts, ev["ts"])
            existing.raw = ev["raw"]
            s.commit()
            return
        e = Event(**ev)
        s.add(e)
        s.commit()
        if bc:
            bc.burned_at = datetime.now(timezone.utc)
            bc.burned_event_id = e.event_id
            s.commit()
        if e.severity >= ALERT_MIN_SEVERITY:
            extra = f" | breadcrumb {bc.kind} plantado en {bc.location}" if bc else ""
            a = Alert(
                event_id=e.event_id,
                ts=e.ts,
                severity=e.severity,
                title=f"{e.engine} | {e.event_type} | {e.src_ip}{extra}",
                detail=ev["raw"][:2000],
            )
            s.add(a)
            s.commit()
            dispatch_alert(a, e)


def match_breadcrumb(s: Session, ev: dict):
    if ev["engine"] != "cowrie" or ev["event_type"] != "cowrie.login.success":
        return None
    if not ev["username"]:
        return None
    return s.scalar(
        select(Breadcrumb).where(
            Breadcrumb.kind == "credential",
            Breadcrumb.username == ev["username"],
            Breadcrumb.password == ev["password"],
            Breadcrumb.burned_at.is_(None),
        )
    )


HONEYTOKEN_KINDS = ("api_key", "canary_url", "document", "database")


def match_honeytoken(s: Session, raw_str: str):
    rows = s.scalars(
        select(Breadcrumb).where(
            Breadcrumb.kind.in_(HONEYTOKEN_KINDS),
            Breadcrumb.burned_at.is_(None),
        )
    ).all()
    for b in rows:
        if b.token and b.token in raw_str:
            return b
    return None


def generate_breadcrumb(kind: str = "credential", location: str = "") -> dict:
    if kind == "credential":
        return {
            "token": secrets.token_urlsafe(16),
            "kind": kind,
            "username": f"svc_{secrets.token_hex(4)}",
            "password": secrets.token_urlsafe(12),
            "secret": "",
            "location": location,
        }
    if kind == "api_key":
        t = f"dg_{secrets.token_hex(16)}"
        return {"token": t, "kind": kind, "username": "", "password": "", "secret": t, "location": location}
    if kind in ("canary_url", "document"):
        t = secrets.token_urlsafe(12)
        return {"token": t, "kind": kind, "username": "", "password": "", "secret": f"{CANARY_BASE}/{t}", "location": location}
    if kind == "database":
        t = secrets.token_urlsafe(12)
        return {
            "token": t,
            "kind": kind,
            "username": f"db_{secrets.token_hex(4)}",
            "password": t,
            "secret": "",
            "location": location,
        }
    return {
        "token": secrets.token_urlsafe(16),
        "kind": kind,
        "username": "",
        "password": "",
        "secret": "",
        "location": location,
    }


def dispatch_alert(a: Alert, e: Event) -> None:
    threading.Thread(target=_dispatch_sync, args=(a, e), daemon=True).start()


def _dispatch_sync(a: Alert, e: Event) -> None:
    payload = {
        "event_id": a.event_id,
        "timestamp": a.ts.isoformat(),
        "severity": a.severity,
        "title": a.title,
        "src_ip": e.src_ip,
        "src_port": e.src_port,
        "dst_port": e.dst_port,
        "engine": e.engine,
        "event_type": e.event_type,
        "technique": {"id": e.technique_id, "name": e.technique_name},
        "count": e.count,
    }
    if WEBHOOK_URL:
        try:
            httpx.post(WEBHOOK_URL, json=payload, timeout=10)
            print("[alerta] webhook enviado", flush=True)
        except Exception as exc:
            print(f"[alerta] webhook error: {exc}", flush=True)
    if TG_TOKEN and TG_CHAT_ID:
        text = (
            f"[DecoyGrid] {a.title} (sev {a.severity})\n"
            f"origen={e.src_ip}:{e.src_port} tecnica={e.technique_id} {e.technique_name}"
        )
        try:
            r = httpx.post(
                f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                json={"chat_id": TG_CHAT_ID, "text": text},
                timeout=10,
            )
            if r.status_code == 200:
                print("[alerta] telegram OK", flush=True)
            else:
                print(
                    f"[alerta] telegram status={r.status_code} body={r.text[:200]}",
                    flush=True,
                )
        except Exception as exc:
            print(f"[alerta] telegram error: {exc}", flush=True)


def engine_of(path: str) -> str:
    if "cowrie" in path:
        return "cowrie"
    if "opencanary" in path:
        return "opencanary"
    if "canary" in path:
        return "canary"
    return "opencanary"


def seed_offsets() -> dict[str, int]:
    offsets: dict[str, int] = {}
    for d in LOG_DIRS:
        if not d.exists():
            continue
        for p in d.rglob("*"):
            if p.is_file() and p.suffix in (".json", ".log"):
                offsets[str(p)] = p.stat().st_size
    return offsets


def collector_loop() -> None:
    offsets = seed_offsets()
    print("[collector] iniciado", flush=True)
    while True:
        try:
            for changes in watch(*LOG_DIRS, debounce=300, ignore_permission_denied=True):
                for _change, path in changes:
                    p = Path(path)
                    if not p.is_file() or p.suffix not in (".json", ".log"):
                        continue
                    off = offsets.get(str(p), 0)
                    try:
                        with p.open("r", errors="replace") as f:
                            f.seek(off)
                            for line in f:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    raw = json.loads(line)
                                except json.JSONDecodeError:
                                    continue
                                try:
                                    process_event(raw, engine_of(str(p)))
                                except Exception as exc:
                                    print(
                                        f"[collector] error procesando {p}: {exc}",
                                        flush=True,
                                    )
                            offsets[str(p)] = f.tell()
                    except OSError:
                        continue
        except Exception as exc:
            print(f"[collector] error en watch: {exc}", flush=True)
            time.sleep(5)


# ----------------------------------------------------------------------------
# Autenticacion (Argon2 + sesion firmada). TOTP se agrega en la siguiente
# iteracion.
# ----------------------------------------------------------------------------
def current_user(request: Request) -> str | None:
    return request.session.get("user")


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    _migrate()
    with SessionLocal() as s:
        if not s.scalar(select(User).where(User.username == ADMIN_USER)):
            s.add(
                User(
                    username=ADMIN_USER,
                    password_hash=ph.hash(ADMIN_PASSWORD),
                    role="admin",
                )
            )
            s.commit()
    threading.Thread(target=collector_loop, daemon=True).start()
    threading.Thread(target=cleanup_loop, daemon=True).start()
    yield


def _migrate() -> None:
    with engine.begin() as conn:
        try:
            conn.execute(text("ALTER TABLE events ADD COLUMN breadcrumb_id VARCHAR(64) DEFAULT ''"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE users ADD COLUMN totp_secret VARCHAR(64) DEFAULT ''"))
        except Exception:
            pass


app = FastAPI(title="DecoyGrid", lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=False,
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "decoygrid"}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html")


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    totp: str = Form(""),
):
    ip = request.client.host if request.client else ""
    with SessionLocal() as s:
        u = s.scalar(select(User).where(User.username == username))
        if not u:
            s.add(AuditLog(username=username, action="login_failed", ip=ip))
            s.commit()
            raise HTTPException(400, "Credenciales invalidas")
        try:
            ph.verify(u.password_hash, password)
        except VerifyMismatchError:
            s.add(AuditLog(username=username, action="login_failed", ip=ip))
            s.commit()
            raise HTTPException(400, "Credenciales invalidas")
        if u.totp_secret:
            if not totp or not pyotp.TOTP(u.totp_secret).verify(totp, valid_window=1):
                s.add(AuditLog(username=u.username, action="login_2fa_failed", ip=ip))
                s.commit()
                raise HTTPException(400, "Codigo 2FA invalido")
        else:
            secret = pyotp.random_base32()
            request.session["pending_user"] = u.username
            request.session["pending_secret"] = secret
            s.add(AuditLog(username=u.username, action="login_ok_2fa_pending", ip=ip))
            s.commit()
            return RedirectResponse("/setup-2fa", status_code=303)
        request.session["user"] = u.username
        request.session["role"] = u.role
        s.add(AuditLog(username=u.username, action="login_ok", ip=ip))
        s.commit()
    return RedirectResponse("/", status_code=303)


@app.get("/setup-2fa", response_class=HTMLResponse)
def setup_2fa_page(request: Request):
    pending = request.session.get("pending_user")
    if not pending:
        return RedirectResponse("/login", status_code=303)
    secret = request.session.get("pending_secret", "")
    uri = pyotp.TOTP(secret).provisioning_uri(name=pending, issuer_name="DecoyGrid")
    qr = _qr_svg(uri)
    return templates.TemplateResponse(
        request,
        "setup_2fa.html",
        {"user": pending, "secret": secret, "uri": uri, "qr": qr},
    )


@app.post("/setup-2fa")
def setup_2fa_submit(request: Request, code: str = Form(...)):
    pending = request.session.get("pending_user")
    secret = request.session.get("pending_secret", "")
    if not pending or not secret:
        raise HTTPException(400, "Sesion de configuracion invalida")
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        raise HTTPException(400, "Codigo invalido")
    role = "admin"
    with SessionLocal() as s:
        u = s.scalar(select(User).where(User.username == pending))
        if not u:
            raise HTTPException(400, "Usuario no encontrado")
        u.totp_secret = secret
        role = u.role
        s.commit()
    request.session["user"] = pending
    request.session["role"] = role
    request.session.pop("pending_user", None)
    request.session.pop("pending_secret", None)
    return RedirectResponse("/", status_code=303)


def _qr_svg(uri: str) -> str:
    import qrcode
    import qrcode.image.svg

    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=6)
    svg = img.to_string()
    return svg.decode("utf-8") if isinstance(svg, bytes) else svg


def cleanup_loop() -> None:
    while True:
        time.sleep(3600)
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
            with SessionLocal() as s:
                s.execute(text("DELETE FROM alerts WHERE ts < :c"), {"c": cutoff})
                s.execute(text("DELETE FROM events WHERE ts < :c"), {"c": cutoff})
                s.commit()
            print(f"[cleanup] datos anteriores a {cutoff.isoformat()} borrados", flush=True)
        except Exception as exc:
            print(f"[cleanup] error: {exc}", flush=True)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with SessionLocal() as s:
        total_events = s.query(Event).count()
        total_alerts = s.query(Alert).count()
        total_breadcrumbs = s.query(Breadcrumb).count()
        events = s.query(Event).order_by(Event.ts.desc()).limit(50).all()
        alerts = s.query(Alert).order_by(Alert.ts.desc()).limit(50).all()
        breadcrumbs = (
            s.query(Breadcrumb).order_by(Breadcrumb.created_at.desc()).limit(20).all()
        )
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "user": user,
            "total_events": total_events,
            "total_alerts": total_alerts,
            "total_breadcrumbs": total_breadcrumbs,
            "events": events,
            "alerts": alerts,
            "breadcrumbs": breadcrumbs,
        },
    )


@app.get("/api/events")
def api_events(request: Request, limit: int = 200):
    if not current_user(request):
        raise HTTPException(401, "no autenticado")
    with SessionLocal() as s:
        rows = s.query(Event).order_by(Event.ts.desc()).limit(min(limit, 500)).all()
    return {
        "events": [
            {
                "id": e.event_id,
                "ts": e.ts.isoformat(),
                "engine": e.engine,
                "event_type": e.event_type,
                "src_ip": e.src_ip,
                "src_port": e.src_port,
                "dst_port": e.dst_port,
                "technique": {"id": e.technique_id, "name": e.technique_name},
                "severity": e.severity,
                "count": e.count,
            }
            for e in rows
        ]
    }


@app.get("/api/alerts")
def api_alerts(request: Request, limit: int = 100):
    if not current_user(request):
        raise HTTPException(401, "no autenticado")
    with SessionLocal() as s:
        rows = s.query(Alert).order_by(Alert.ts.desc()).limit(min(limit, 200)).all()
    return {
        "alerts": [
            {
                "id": a.id,
                "ts": a.ts.isoformat(),
                "severity": a.severity,
                "title": a.title,
                "status": a.status,
            }
            for a in rows
        ]
    }


@app.post("/api/breadcrumbs")
def create_breadcrumbs(
    request: Request,
    count: int = Form(1),
    location: str = Form(""),
    kind: str = Form("credential"),
):
    if not current_user(request):
        raise HTTPException(401, "no autenticado")
    out = []
    with SessionLocal() as s:
        for _ in range(max(1, min(count, 50))):
            b = Breadcrumb(**generate_breadcrumb(kind, location))
            s.add(b)
            out.append(
                {
                    "token": b.token,
                    "kind": b.kind,
                    "username": b.username,
                    "password": b.password,
                    "location": b.location,
                }
            )
        s.commit()
    return {"breadcrumbs": out}


@app.get("/api/breadcrumbs")
def list_breadcrumbs(request: Request):
    if not current_user(request):
        raise HTTPException(401, "no autenticado")
    with SessionLocal() as s:
        rows = (
            s.query(Breadcrumb)
            .order_by(Breadcrumb.created_at.desc())
            .limit(200)
            .all()
        )
    return {
        "breadcrumbs": [
            {
                "token": b.token,
                "kind": b.kind,
                "username": b.username,
                "password": b.password,
                "location": b.location,
                "burned": b.burned_at is not None,
            }
            for b in rows
        ]
    }


@app.get("/api/breadcrumbs/{token}/document")
def download_document(request: Request, token: str, fmt: str = "docx"):
    if not current_user(request):
        raise HTTPException(401, "no autenticado")
    with SessionLocal() as s:
        b = s.scalar(select(Breadcrumb).where(Breadcrumb.token == token))
        if not b or b.kind != "document":
            raise HTTPException(404, "breadcrumb de documento no encontrado")
        canary = f"{CANARY_BASE}/{b.token}"
    if fmt == "xlsx":
        body = docgen.make_xlsx(canary)
        media = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        fname = "inventario.xlsx"
    elif fmt == "pdf":
        body = docgen.make_pdf(canary)
        media = "application/pdf"
        fname = "informe.pdf"
    else:
        body = docgen.make_docx(canary)
        media = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        fname = "informe.docx"
    return Response(
        content=body,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.get("/coverage", response_class=HTMLResponse)
def coverage_page(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    covered = covered_techniques()
    by_tactic: dict[str, list[dict]] = {}
    for t in MITRE_TECHNIQUES:
        if t["id"] in covered:
            for tactic in t["tactics"] or ["unknown"]:
                by_tactic.setdefault(tactic, []).append(t)
    order = {name: i for i, name in enumerate(TACTIC_ORDER)}
    by_tactic = dict(
        sorted(
            by_tactic.items(),
            key=lambda kv: order.get(kv[0], 999),
        )
    )
    return templates.TemplateResponse(
        request,
        "coverage.html",
        {
            "user": user,
            "total_covered": len(covered),
            "total_all": len(MITRE_TECHNIQUES),
            "by_tactic": by_tactic,
        },
    )


@app.get("/api/coverage")
def api_coverage(request: Request):
    if not current_user(request):
        raise HTTPException(401, "no autenticado")
    covered = covered_techniques()
    return {
        "domain": "enterprise-attack",
        "version": MITRE_VERSION,
        "total_techniques": len(MITRE_TECHNIQUES),
        "total_covered": len(covered),
        "covered": covered,
    }


@app.get("/api/coverage/layer")
def api_coverage_layer(request: Request):
    if not current_user(request):
        raise HTTPException(401, "no autenticado")
    covered = covered_techniques()
    layer = {
        "name": "DecoyGrid coverage",
        "versions": {
            "attack": MITRE_VERSION,
            "navigator": "5.0.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": "Cobertura de deteccion de DecoyGrid (decoys + breadcrumbs)",
        "techniques": [
            {
                "techniqueID": tid,
                "comment": name,
                "enabled": True,
                "score": 100,
            }
            for tid, name in sorted(covered.items())
        ],
        "gradient": {
            "colors": ["#ffffff", "#2f6fed"],
            "minValue": 0,
            "maxValue": 100,
        },
    }
    return JSONResponse(layer)
