#!/usr/bin/env python3
"""Servidor mínimo de licencias compatible con la API observada en BelgaCheats.

Requiere Python 3.10+. En producción, colóquese detrás de HTTPS (reverse proxy).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import string
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("LICENSE_DATA_DIR", str(ROOT / "data")))
DB_PATH = DATA_DIR / "licenses.sqlite3"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))
PUBLIC_HTTPS = os.environ.get("PUBLIC_HTTPS", "0") == "1"
SESSION_TTL = 8 * 60 * 60
PBKDF2_ROUNDS = 310_000

_sessions: dict[str, float] = {}
_session_lock = threading.Lock()
_login_attempts: dict[str, list[float]] = {}
_attempt_lock = threading.Lock()


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat(timespec="seconds") if dt else None


def connect() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, timeout=20)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS licenses (
            license_key TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            note TEXT NOT NULL DEFAULT '',
            used_by TEXT UNIQUE
        );
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_salt BLOB NOT NULL,
            password_hash BLOB NOT NULL,
            license_key TEXT NOT NULL UNIQUE REFERENCES licenses(license_key),
            hwid TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_licenses_created ON licenses(created_at DESC);
        """)


def password_hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)


def make_license() -> str:
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "BELGA-" + "-".join("".join(secrets.choice(chars) for _ in range(4)) for _ in range(3))


def json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "BelgaLicense/1.0"

    def log_message(self, fmt, *args):
        # No imprimir contraseñas ni formularios en logs.
        print(f"[{self.log_date_time_string()}] {self.client_address[0]} {fmt % args}")

    def send_bytes(self, status: int, body: bytes, content_type: str = "application/json; charset=utf-8", extra: list[tuple[str, str]] | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        if extra:
            for key, value in extra:
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: int, payload: dict, extra=None):
        self.send_bytes(status, json_bytes(payload), extra=extra)

    def read_form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 32_768:
            raise ValueError("Solicitud demasiado grande")
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        parsed = parse_qs(raw, keep_blank_values=True, max_num_fields=100)
        return {k: (v[-1] if v else "") for k, v in parsed.items()}

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 32_768:
            raise ValueError("Solicitud demasiado grande")
        raw = self.rfile.read(length).decode("utf-8")
        value = json.loads(raw or "{}")
        if not isinstance(value, dict):
            raise ValueError("JSON inválido")
        return value

    def get_session(self) -> str | None:
        cookie = self.headers.get("Cookie", "")
        token = None
        for part in cookie.split(";"):
            key, _, value = part.strip().partition("=")
            if key == "belga_admin_session":
                token = value
                break
        if not token:
            return None
        with _session_lock:
            expires = _sessions.get(token)
            if not expires or expires < time.time():
                _sessions.pop(token, None)
                return None
            _sessions[token] = time.time() + SESSION_TTL
        return token

    def require_admin(self) -> bool:
        if self.get_session():
            return True
        self.send_json(401, {"ok": False, "error": "Inicia sesión como administrador."})
        return False

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/admin", "/admin/"):
            try:
                body = (ROOT / "admin.html").read_bytes()
            except OSError:
                self.send_bytes(500, b"Falta admin.html", "text/plain; charset=utf-8")
                return
            self.send_bytes(200, body, "text/html; charset=utf-8", [("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")])
            return
        if path == "/api/admin/me":
            self.send_json(200, {"ok": bool(self.get_session())})
            return
        if path == "/api/admin/licenses":
            if not self.require_admin():
                return
            with connect() as con:
                rows = con.execute("""
                    SELECT l.license_key, l.created_at, l.expires_at, l.active, l.note, l.used_by,
                           u.username
                    FROM licenses l LEFT JOIN users u ON u.license_key=l.license_key
                    ORDER BY l.created_at DESC LIMIT 500
                """).fetchall()
            self.send_json(200, {"ok": True, "licenses": [dict(r) for r in rows]})
            return
        self.send_json(404, {"ok": False, "error": "No encontrado."})

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/admin/login":
            self.admin_login()
            return
        if path == "/api/admin/logout":
            token = self.get_session()
            if token:
                with _session_lock:
                    _sessions.pop(token, None)
            self.send_json(200, {"ok": True}, [("Set-Cookie", "belga_admin_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict" + ("; Secure" if PUBLIC_HTTPS else ""))])
            return
        if path == "/api/admin/licenses":
            if not self.require_admin():
                return
            self.create_licenses()
            return
        match = re.fullmatch(r"/api/admin/licenses/([A-Z0-9-]+)/revoke", path)
        if match:
            if not self.require_admin():
                return
            self.revoke_license(match.group(1))
            return
        # API que usa el APK: POST application/x-www-form-urlencoded a la raíz.
        if path == "/":
            self.app_auth()
            return
        self.send_json(404, {"ok": False, "error": "No encontrado."})

    def admin_login(self):
        if not ADMIN_PASSWORD:
            self.send_json(503, {"ok": False, "error": "Configura ADMIN_PASSWORD en el servidor antes de usar el panel."})
            return
        ip = self.client_address[0]
        now = time.time()
        with _attempt_lock:
            attempts = [t for t in _login_attempts.get(ip, []) if now - t < 600]
            if len(attempts) >= 10:
                self.send_json(429, {"ok": False, "error": "Demasiados intentos. Espera 10 minutos."})
                return
        try:
            data = self.read_json()
            supplied = str(data.get("password", ""))
        except Exception:
            self.send_json(400, {"ok": False, "error": "Solicitud inválida."})
            return
        if not hmac.compare_digest(supplied.encode(), ADMIN_PASSWORD.encode()):
            with _attempt_lock:
                _login_attempts[ip] = attempts + [now]
            self.send_json(401, {"ok": False, "error": "Contraseña incorrecta."})
            return
        with _attempt_lock:
            _login_attempts.pop(ip, None)
        token = secrets.token_urlsafe(32)
        with _session_lock:
            _sessions[token] = now + SESSION_TTL
        cookie = f"belga_admin_session={token}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Strict" + ("; Secure" if PUBLIC_HTTPS else "")
        self.send_json(200, {"ok": True}, [("Set-Cookie", cookie)])

    def create_licenses(self):
        try:
            data = self.read_json()
            count = int(data.get("count", 1))
            days = int(data.get("days", 30))
            note = str(data.get("note", ""))[:120].strip()
            if not 1 <= count <= 100 or not 0 <= days <= 3650:
                raise ValueError
        except Exception:
            self.send_json(400, {"ok": False, "error": "Cantidad: 1–100. Duración: 0–3650 días (0 = sin vencimiento)."})
            return
        created = now_utc()
        expiry = iso(created + timedelta(days=days)) if days else None
        keys = []
        try:
            with connect() as con:
                for _ in range(count):
                    key = make_license()
                    con.execute("INSERT INTO licenses(license_key,created_at,expires_at,note) VALUES(?,?,?,?)", (key, iso(created), expiry, note))
                    keys.append(key)
        except sqlite3.Error:
            self.send_json(500, {"ok": False, "error": "No se pudieron guardar las licencias."})
            return
        self.send_json(201, {"ok": True, "licenses": keys, "expires_at": expiry})

    def revoke_license(self, key: str):
        with connect() as con:
            cur = con.execute("UPDATE licenses SET active=0 WHERE license_key=? AND active=1", (key,))
        if cur.rowcount:
            self.send_json(200, {"ok": True})
        else:
            self.send_json(404, {"ok": False, "error": "Licencia no encontrada o ya revocada."})

    def app_auth(self):
        try:
            data = self.read_form()
        except Exception:
            self.send_json(400, {"success": False, "message": "Solicitud inválida."})
            return
        action = data.get("type", "").lower()
        if action == "register":
            self.app_register(data)
        elif action == "login":
            self.app_login(data)
        else:
            self.send_json(400, {"success": False, "message": "Tipo de solicitud no válido."})

    def app_register(self, data: dict[str, str]):
        username = data.get("username", "").strip()
        password = data.get("pass") or data.get("password", "")
        key = (data.get("key") or data.get("license", "")).strip().upper()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username) or len(password) < 6 or not key:
            self.send_json(200, {"success": False, "message": "Usuario, contraseña o licencia no válidos."})
            return
        now = now_utc()
        salt = secrets.token_bytes(16)
        hashed = password_hash(password, salt)
        try:
            with connect() as con:
                row = con.execute("SELECT * FROM licenses WHERE license_key=?", (key,)).fetchone()
                if not row or not row["active"]:
                    self.send_json(200, {"success": False, "message": "Licencia inválida o revocada."})
                    return
                if row["used_by"]:
                    self.send_json(200, {"success": False, "message": "La licencia ya fue utilizada."})
                    return
                if row["expires_at"] and datetime.fromisoformat(row["expires_at"]) <= now:
                    self.send_json(200, {"success": False, "message": "La licencia ha vencido."})
                    return
                if con.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                    self.send_json(200, {"success": False, "message": "Ese usuario ya existe."})
                    return
                con.execute("INSERT INTO users(username,password_salt,password_hash,license_key,created_at) VALUES(?,?,?,?,?)", (username, salt, hashed, key, iso(now)))
                con.execute("UPDATE licenses SET used_by=? WHERE license_key=?", (username, key))
        except sqlite3.IntegrityError:
            self.send_json(200, {"success": False, "message": "No se pudo activar la licencia."})
            return
        self.send_json(200, {"success": True, "message": "Registro completado."})

    def app_login(self, data: dict[str, str]):
        username = data.get("username", "").strip()
        password = data.get("pass", "")
        hwid = data.get("hwid", "")[:256]
        if not hwid:
            self.send_json(200, {"success": False, "message": "No se recibió el identificador del dispositivo."})
            return
        with connect() as con:
            user = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if not user or not hmac.compare_digest(password_hash(password, user["password_salt"]), user["password_hash"]):
                self.send_json(200, {"success": False, "message": "Usuario o contraseña incorrectos."})
                return
            license_row = con.execute("SELECT * FROM licenses WHERE license_key=?", (user["license_key"],)).fetchone()
            if not license_row or not license_row["active"]:
                self.send_json(200, {"success": False, "message": "Licencia revocada."})
                return
            if license_row["expires_at"] and datetime.fromisoformat(license_row["expires_at"]) <= now_utc():
                self.send_json(200, {"success": False, "message": "La licencia ha vencido."})
                return
            saved_hwid = user["hwid"]
            if saved_hwid and hwid and not hmac.compare_digest(saved_hwid, hwid):
                self.send_json(200, {"success": False, "message": "La licencia está vinculada a otro dispositivo."})
                return
            if not saved_hwid and hwid:
                con.execute("UPDATE users SET hwid=? WHERE username=?", (hwid, username))
        self.send_json(200, {"success": True, "keyInfo": {"authenticated": True}, "message": "Autenticado."})


def main():
    if not ADMIN_PASSWORD:
        raise SystemExit("Error: define ADMIN_PASSWORD antes de iniciar el servidor.")
    init_db()
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Panel/API escuchando en http://{HOST}:{PORT} (HTTPS debe terminar en un proxy en producción).")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nCerrando servidor…")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
