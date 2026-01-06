from __future__ import annotations

import os
import json
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt
import psycopg2
from psycopg2.extras import Json
from passlib.context import CryptContext
from fastapi import FastAPI, HTTPException, Depends, Request
from pydantic import BaseModel, Field


APP_VERSION = "2.0.0"
JWT_ALG = "HS256"

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
JWT_SECRET = os.environ.get("JWT_SECRET", "").strip()
JWT_ISSUER = os.environ.get("JWT_ISSUER", "almacen_rbyrd").strip()
JWT_EXPIRES_MIN = int(os.environ.get("JWT_EXPIRES_MIN", "720"))

BOOTSTRAP_ADMIN_USER = os.environ.get("BOOTSTRAP_ADMIN_USER", "").strip()
BOOTSTRAP_ADMIN_PASS = os.environ.get("BOOTSTRAP_ADMIN_PASS", "").strip()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="Almacen_RBYRD Online API", version=APP_VERSION)


@contextmanager
def get_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set")
    conn = psycopg2.connect(DATABASE_URL, connect_timeout=10)
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(username: str) -> str:
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET is not set")
    exp = now_utc() + timedelta(minutes=JWT_EXPIRES_MIN)
    payload = {"sub": username, "iss": JWT_ISSUER, "iat": int(now_utc().timestamp()), "exp": int(exp.timestamp())}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def verify_token(token: str) -> str:
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET is not set")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG], issuer=JWT_ISSUER)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="invalid token")
    sub = payload.get("sub")
    if not sub:
        raise HTTPException(status_code=401, detail="invalid token")
    return str(sub)


def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS warehouse_state (
                    warehouse_type TEXT PRIMARY KEY,
                    payload JSONB NOT NULL,
                    version BIGINT NOT NULL DEFAULT 0,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_by TEXT
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id BIGSERIAL PRIMARY KEY,
                    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    username TEXT,
                    action TEXT NOT NULL,
                    warehouse_type TEXT,
                    detail JSONB
                );
                """
            )
        conn.commit()


def bootstrap_admin():
    if not BOOTSTRAP_ADMIN_USER or not BOOTSTRAP_ADMIN_PASS:
        return
    username = BOOTSTRAP_ADMIN_USER
    pw_hash = pwd_context.hash(BOOTSTRAP_ADMIN_PASS)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT username FROM users WHERE username=%s;", (username,))
            row = cur.fetchone()
            if row:
                return
            cur.execute(
                "INSERT INTO users(username, password_hash, is_active) VALUES (%s, %s, TRUE);",
                (username, pw_hash),
            )
        conn.commit()


def write_audit(username: Optional[str], action: str, warehouse_type: Optional[str], detail: Optional[dict]):
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO audit_log(username, action, warehouse_type, detail) VALUES (%s, %s, %s, %s);",
                    (username, action, warehouse_type, Json(detail) if detail is not None else None),
                )
            conn.commit()
    except Exception:
        # audit must never break the main flow
        pass


@app.on_event("startup")
def on_startup():
    init_db()
    bootstrap_admin()


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_minutes: int


def get_bearer_token(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    return auth.split(" ", 1)[1].strip()


def current_username(request: Request) -> str:
    token = get_bearer_token(request)
    return verify_token(token)


class StateResponse(BaseModel):
    warehouse: str
    version: int
    payload: Dict[str, Any]


class StateUpdateRequest(BaseModel):
    payload: Dict[str, Any]
    base_version: Optional[int] = None


@app.get("/health")
def health():
    # IMPORTANT: does NOT touch the DB (keeps Render warm without consuming Neon CU-hours)
    return {"ok": True, "ts": now_utc().isoformat(), "version": APP_VERSION}


@app.get("/version")
def version():
    return {"ok": True, "version": APP_VERSION, "issuer": JWT_ISSUER}


@app.post("/auth/login", response_model=LoginResponse)
def login(body: LoginRequest):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash, is_active FROM users WHERE username=%s;", (body.username,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=401, detail="invalid credentials")
            pw_hash, is_active = row
            if not is_active:
                raise HTTPException(status_code=403, detail="user disabled")
            if not pwd_context.verify(body.password, pw_hash):
                raise HTTPException(status_code=401, detail="invalid credentials")

    token = create_access_token(body.username)
    write_audit(body.username, "login", None, None)
    return LoginResponse(access_token=token, expires_minutes=JWT_EXPIRES_MIN)


@app.get("/auth/me")
def me(username: str = Depends(current_username)):
    return {"ok": True, "username": username}


@app.get("/state/{warehouse}", response_model=StateResponse)
def get_state(warehouse: str, username: str = Depends(current_username)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT payload, version FROM warehouse_state WHERE warehouse_type=%s;", (warehouse,))
            row = cur.fetchone()
            if not row:
                return StateResponse(warehouse=warehouse, version=0, payload={})
            payload, version = row
            # psycopg2 returns jsonb as dict already (if available) else string; normalize
            if isinstance(payload, str):
                payload = json.loads(payload)
            return StateResponse(warehouse=warehouse, version=int(version), payload=payload)


@app.put("/state/{warehouse}", response_model=StateResponse)
def put_state(warehouse: str, body: StateUpdateRequest, username: str = Depends(current_username)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT payload, version FROM warehouse_state WHERE warehouse_type=%s FOR UPDATE;", (warehouse,))
            row = cur.fetchone()

            if not row:
                server_version = 0
                if body.base_version not in (None, 0):
                    raise HTTPException(status_code=409, detail={"message": "version conflict", "server_version": server_version})
                new_version = 1
                cur.execute(
                    """
                    INSERT INTO warehouse_state(warehouse_type, payload, version, updated_at, updated_by)
                    VALUES (%s, %s, %s, NOW(), %s);
                    """,
                    (warehouse, Json(body.payload), new_version, username),
                )
            else:
                _payload, server_version = row
                server_version = int(server_version)
                if body.base_version is not None and int(body.base_version) != server_version:
                    raise HTTPException(status_code=409, detail={"message": "version conflict", "server_version": server_version})
                new_version = server_version + 1
                cur.execute(
                    """
                    UPDATE warehouse_state
                    SET payload=%s, version=%s, updated_at=NOW(), updated_by=%s
                    WHERE warehouse_type=%s;
                    """,
                    (Json(body.payload), new_version, username, warehouse),
                )

        conn.commit()

    write_audit(username, "put_state", warehouse, {"new_version": new_version})
    return StateResponse(warehouse=warehouse, version=new_version, payload=body.payload)


@app.get("/warmup")
def warmup(request: Request):
    """
    Optional: keeps DB warm during business hours.
    If WARMUP_KEY is not set, returns 404 (disabled).
    """
    warm_key = os.environ.get("WARMUP_KEY", "").strip()
    if not warm_key:
        raise HTTPException(status_code=404, detail="warmup disabled")
    provided = request.headers.get("X-Warm-Key", "")
    if provided != warm_key:
        raise HTTPException(status_code=401, detail="unauthorized")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
            _ = cur.fetchone()

    return {"ok": True, "ts": now_utc().isoformat()}
