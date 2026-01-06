# -*- coding: utf-8 -*-
"""
Almacen_RBYRD - Online (Opción 2: API + Postgres Cloud)

Objetivo:
- Cliente NO usa SMB ni abre SQLite remota.
- Cliente opera contra API HTTPS con autenticación por token (JWT).
- Estado canónico (EPP/EPV) se guarda en Postgres como JSONB con control de concurrencia (optimistic locking).

Endpoints:
- GET  /health
- GET  /version
- POST /auth/login
- GET  /auth/me
- GET  /state/{warehouse_type}
- PUT  /state/{warehouse_type}

Variables de entorno:
- DATABASE_URL: connection string (postgresql://user:pass@host:port/dbname)
- JWT_SECRET: secreto para firmar tokens (mínimo 32 chars)
- JWT_ISSUER: opcional (default: "almacen_rbryd")
- JWT_EXPIRES_MIN: opcional (default: 720 = 12 horas)
- BOOTSTRAP_ADMIN_USER / BOOTSTRAP_ADMIN_PASS: crea admin si no hay usuarios
- CORS_ORIGINS: lista separada por comas para CORS (opcional)
"""

from __future__ import annotations

import os
import time
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# --- Dependencias externas recomendadas ---
# pip install psycopg2-binary PyJWT passlib[bcrypt]
import jwt
from passlib.context import CryptContext

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor, Json
except Exception as ex:  # pragma: no cover
    psycopg2 = None
    RealDictCursor = None
    Json = None


APP_VERSION = "2.0.0-online"
CLIENT_LATEST_VERSION = "2.0.0-online"
CLIENT_MIN_VERSION = "2.0.0-online"

JWT_SECRET = os.environ.get("JWT_SECRET", "").strip()
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET no está configurado. Debes definir un secreto largo (>=32 chars) en el entorno.")

JWT_ISSUER = os.environ.get("JWT_ISSUER", "almacen_rbryd").strip()
JWT_EXPIRES_MIN = int(os.environ.get("JWT_EXPIRES_MIN", "720"))

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
if not DATABASE_URL:
    # No permitimos operar "online real" sin DB.
    # En dev puedes setear DATABASE_URL apuntando a Postgres local.
    raise RuntimeError("DATABASE_URL no está configurada. Debes apuntar a un Postgres (Supabase/Neon/Render/etc.).")

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="Almacen_RBYRD Online API", version=APP_VERSION)

# --- CORS (si el cliente es un EXE, normalmente no aplica; si luego tienes web admin, sí) ---
cors_env = os.environ.get("CORS_ORIGINS", "").strip()
origins = [o.strip() for o in cors_env.split(",") if o.strip()] if cors_env else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _db_conn():
    if psycopg2 is None:
        raise RuntimeError("psycopg2 no está disponible. Instala requirements_server.txt en el servidor.")
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor, connect_timeout=5)




@contextmanager
def db_conn():
    """Context manager que SI CIERRA la conexión al salir.

    Nota: psycopg2.Connection como context manager no cierra por sí mismo, solo maneja transacción.
    Aquí garantizamos close() para evitar fugas y mantener consumo bajo en Neon.
    """
    conn = _db_conn()
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass

def _init_schema():
    """Crea tablas si no existen."""
    ddl = """
    CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        is_admin BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS warehouse_state (
        warehouse_type TEXT PRIMARY KEY,
        version BIGINT NOT NULL DEFAULT 1,
        state JSONB NOT NULL DEFAULT '{}'::jsonb,
        updated_by TEXT,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id BIGSERIAL PRIMARY KEY,
        ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        username TEXT,
        action TEXT NOT NULL,
        warehouse_type TEXT,
        detail JSONB
    );
    """
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(ddl)
        conn.commit()


def _bootstrap_admin_if_needed():
    user = os.environ.get("BOOTSTRAP_ADMIN_USER", "").strip()
    pw = os.environ.get("BOOTSTRAP_ADMIN_PASS", "").strip()
    if not user or not pw:
        return

    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM users;")
            c = int(cur.fetchone()["c"])
            if c > 0:
                return
            ph = pwd_ctx.hash(pw)
            cur.execute(
                "INSERT INTO users(username, password_hash, is_admin) VALUES (%s, %s, TRUE);",
                (user, ph),
            )
        conn.commit()


@app.on_event("startup")
def on_startup():
    _init_schema()
    _bootstrap_admin_if_needed()


# -------------------- Models --------------------

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: str  # ISO8601


class MeResponse(BaseModel):
    username: str
    is_admin: bool


class StateResponse(BaseModel):
    warehouse_type: str
    version: int
    state: Dict[str, Any]
    updated_at: Optional[str] = None
    updated_by: Optional[str] = None


class StateUpdateRequest(BaseModel):
    base_version: int = Field(..., ge=0)
    state: Dict[str, Any]


# -------------------- Auth helpers --------------------

def _issue_token(username: str, is_admin: bool) -> TokenResponse:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=JWT_EXPIRES_MIN)
    payload = {
        "iss": JWT_ISSUER,
        "sub": username,
        "adm": bool(is_admin),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    tok = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return TokenResponse(access_token=tok, expires_at=exp.isoformat())


def _decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"], issuer=JWT_ISSUER)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except Exception:
        raise HTTPException(status_code=401, detail="Token inválido")


def require_user(authorization: Optional[str] = Header(default=None)) -> dict:
    if not authorization:
        raise HTTPException(status_code=401, detail="Falta Authorization")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authorization inválido")
    token = parts[1].strip()
    return _decode_token(token)


def _audit(username: Optional[str], action: str, warehouse_type: Optional[str] = None, detail: Any = None):
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO audit_log(username, action, warehouse_type, detail) VALUES (%s, %s, %s, %s);",
                (username, action, warehouse_type, Json(detail) if Json else json.dumps(detail) if detail is not None else None),
            )
        conn.commit()


# -------------------- Routes --------------------

@app.get("/health")
def health():
    return {"ok": True, "ts": datetime.now(timezone.utc).isofo
@app.get("/warmup")
def warmup(request: Request):
    """Optional: used to keep DB warm during business hours.
    Requires header X-Warm-Key matching env WARMUP_KEY.
    Does a cheap SELECT 1 against Postgres.
    """
    warm_key = os.environ.get("WARMUP_KEY", "").strip()
    if not warm_key:
        # If not configured, behave as disabled.
        raise HTTPException(status_code=404, detail="warmup disabled")
    provided = request.headers.get("X-Warm-Key", "")
    if provided != warm_key:
        raise HTTPException(status_code=401, detail="unauthorized")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
            _ = cur.fetchone()
    return {"ok": True, "ts": datetime.now(timezone.utc).isoformat()}

rmat()}


@app.get("/version")
def version():
    return {"latest": CLIENT_LATEST_VERSION, "min_supported": CLIENT_MIN_VERSION, "server": APP_VERSION}


@app.post("/auth/login", response_model=TokenResponse)
def auth_login(req: LoginRequest):
    u = req.username.strip()
    if not u:
        raise HTTPException(status_code=400, detail="Usuario requerido")

    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT username, password_hash, is_admin FROM users WHERE lower(username)=lower(%s);", (u,))
            row = cur.fetchone()

    if not row or not pwd_ctx.verify(req.password, row["password_hash"]):
        _audit(u, "login_failed")
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    _audit(row["username"], "login_ok")
    return _issue_token(row["username"], bool(row["is_admin"]))


@app.get("/auth/me", response_model=MeResponse)
def auth_me(claims: dict = Depends(require_user)):
    return MeResponse(username=claims["sub"], is_admin=bool(claims.get("adm", False)))


@app.get("/state/{warehouse_type}", response_model=StateResponse)
def get_state(warehouse_type: str, claims: dict = Depends(require_user)):
    wt = warehouse_type.strip().lower()
    if wt not in ("epp", "epv"):
        raise HTTPException(status_code=400, detail="warehouse_type inválido (epp/epv)")

    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT warehouse_type, version, state, updated_at, updated_by FROM warehouse_state WHERE warehouse_type=%s;", (wt,))
            row = cur.fetchone()

    if not row:
        # Estado vacío inicial
        return StateResponse(warehouse_type=wt, version=0, state={"epps": [], "workers": [], "deliveries": [], "vehicles": []})

    return StateResponse(
        warehouse_type=row["warehouse_type"],
        version=int(row["version"]),
        state=row["state"] or {},
        updated_at=row["updated_at"].isoformat() if row.get("updated_at") else None,
        updated_by=row.get("updated_by"),
    )


@app.put("/state/{warehouse_type}", response_model=StateResponse)
def put_state(warehouse_type: str, req: StateUpdateRequest, claims: dict = Depends(require_user)):
    wt = warehouse_type.strip().lower()
    if wt not in ("epp", "epv"):
        raise HTTPException(status_code=400, detail="warehouse_type inválido (epp/epv)")

    username = claims["sub"]
    now = datetime.now(timezone.utc)

    # Optimistic locking:
    # - si no existe fila: base_version debe ser 0
    # - si existe: version debe coincidir con base_version
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT version FROM warehouse_state WHERE warehouse_type=%s FOR UPDATE;", (wt,))
            row = cur.fetchone()

            if not row:
                if req.base_version != 0:
                    raise HTTPException(status_code=409, detail="Conflicto de versión (estado no existe). Recarga.")
                new_version = 1
                cur.execute(
                    "INSERT INTO warehouse_state(warehouse_type, version, state, updated_by, updated_at) VALUES (%s, %s, %s, %s, %s);",
                    (wt, new_version, Json(req.state) if Json else json.dumps(req.state), username, now),
                )
            else:
                current_version = int(row["version"])
                if req.base_version != current_version:
                    raise HTTPException(status_code=409, detail=f"Conflicto de versión. Tu base_version={req.base_version}, actual={current_version}. Recarga.")
                new_version = current_version + 1
                cur.execute(
                    "UPDATE warehouse_state SET version=%s, state=%s, updated_by=%s, updated_at=%s WHERE warehouse_type=%s;",
                    (new_version, Json(req.state) if Json else json.dumps(req.state), username, now, wt),
                )

        conn.commit()

    _audit(username, "state_saved", wt, {"new_version": new_version})
    return StateResponse(warehouse_type=wt, version=new_version, state=req.state, updated_at=now.isoformat(), updated_by=username)
