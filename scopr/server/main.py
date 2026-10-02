from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
import sqlite3
import jwt
import datetime
import os
import hmac
import uuid
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Scopr API", description="OAuth for AI Agents", version="0.2.0")
security = HTTPBearer()

JWT_SECRET = os.getenv("SCOPR_JWT_SECRET")
ADMIN_KEY = os.getenv("SCOPR_ADMIN_KEY")

if not JWT_SECRET or not ADMIN_KEY:
    raise RuntimeError("FATAL: Both SCOPR_JWT_SECRET and SCOPR_ADMIN_KEY must be set.")

admin_key_header = APIKeyHeader(name="X-Admin-Key", auto_error=True)

def verify_admin(api_key: str = Security(admin_key_header)):
    if not hmac.compare_digest(api_key, ADMIN_KEY):
        raise HTTPException(status_code=403, detail="Unauthorized: Invalid Admin Key")
    return api_key

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "scopr.db")

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
                token_version INTEGER NOT NULL DEFAULT 1
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_scopes (
                agent_id TEXT NOT NULL,
                scope TEXT NOT NULL,
                PRIMARY KEY (agent_id, scope),
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                description TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

init_db()

def log_audit_event(agent_id: str, event_type: str, description: str):
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO audit_logs (agent_id, event_type, description) VALUES (?, ?, ?)",
                (agent_id, event_type, description),
            )
            conn.commit()
    except Exception:
        # Avoid crashing primary auth flows if audit logging experiences disk lock
        pass

@app.post("/oauth/token")
def generate_agent_token(
    agent_id: str,
    requested_scope: str,
    expires_in_minutes: int = 15,
    admin_key: str = Depends(verify_admin),
):
    if expires_in_minutes > 60 or expires_in_minutes < 1:
        raise HTTPException(status_code=400, detail="Token lifetime must be between 1 and 60 minutes.")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT owner_id, status, token_version FROM agents WHERE agent_id = ?", (agent_id,))
        agent = cursor.fetchone()

        if not agent or agent["status"] != "active":
            raise HTTPException(status_code=403, detail="Agent invalid or revoked.")

        cursor.execute("SELECT scope FROM agent_scopes WHERE agent_id = ? AND scope = ?", (agent_id, requested_scope))
        if not cursor.fetchone():
            raise HTTPException(status_code=403, detail=f"Scope '{requested_scope}' not authorized.")

    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": agent_id,
        "owner": agent["owner_id"],
        "scope": requested_scope,
        "iat": now,
        "exp": now + datetime.timedelta(minutes=expires_in_minutes),
        "iss": "scopr",
        "aud": "scopr-resource",
        "jti": str(uuid.uuid4()),
        "token_version": agent["token_version"],
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    log_audit_event(agent_id, "token_issued", f"Minted token for scope: {requested_scope}")

    return {"access_token": token, "token_type": "bearer", "expires_in": expires_in_minutes * 60}

@app.post("/agents/{agent_id}/revoke")
def revoke_agent(agent_id: str, admin_key: str = Depends(verify_admin)):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM agents WHERE agent_id = ?", (agent_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Agent not found.")

        cursor.execute(
            "UPDATE agents SET status = 'revoked', token_version = token_version + 1 WHERE agent_id = ?",
            (agent_id,),
        )
        conn.commit()

    log_audit_event(agent_id, "agent_revoked", "Agent revoked. Token version incremented.")
    return {"status": "success", "agent_id": agent_id, "message": "Agent permissions revoked immediately."}

def verify_active_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            issuer="scopr",
            audience="scopr-resource",
            options={"require": ["exp", "iat", "iss", "aud", "sub", "token_version", "jti"]},
        )

        agent_id = payload["sub"]
        token_version = payload["token_version"]

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT status, token_version FROM agents WHERE agent_id = ?", (agent_id,))
            agent = cursor.fetchone()

            if not agent or agent["status"] != "active":
                raise HTTPException(status_code=401, detail="Scopr Guard: Agent access revoked.")

            if agent["token_version"] != token_version:
                raise HTTPException(status_code=401, detail="Scopr Guard: Token version obsolete.")

        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

@app.post("/oauth/verify")
def verify_agent_token(payload: dict = Depends(verify_active_token)):
    return {
        "status": "valid",
        "agent_id": payload["sub"],
        "granted_scope": payload["scope"],
        "token_version": payload["token_version"],
    }

@app.post("/resource/github/commit")
def simulate_github_commit(payload: dict = Depends(verify_active_token)):
    if payload["scope"] != "github:repo:write":
        raise HTTPException(status_code=403, detail="Insufficient scope for this action.")

    log_audit_event(payload["sub"], "resource_accessed", "Successfully executed git commit via scoped token.")
    return {"status": "success", "message": "Action executed.", "executed_by_agent": payload["sub"]}
