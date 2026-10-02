from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
import sqlite3
import jwt
import datetime
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = FastAPI(title="Scopr API", description="OAuth for AI Agents")
security = HTTPBearer()

# Pull the secret key from the environment, fail hard if it's missing
SECRET_KEY = os.getenv("SCOPR_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("FATAL: SCOPR_SECRET_KEY environment variable is not set.")

# --- Admin Security ---
admin_key_header = APIKeyHeader(name="X-Admin-Key", auto_error=True)

def verify_admin(api_key: str = Security(admin_key_header)):
    if api_key != SECRET_KEY:
        raise HTTPException(status_code=403, detail="Unauthorized: Invalid Admin Key")
    return api_key

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "scopr.db")

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def log_audit_event(agent_id: str, event_type: str, description: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO audit_logs (agent_id, event_type, description) VALUES (?, ?, ?)",
        (agent_id, event_type, description)
    )
    conn.commit()
    conn.close()

@app.post("/oauth/token")
def generate_agent_token(agent_id: str, requested_scope: str, expires_in_minutes: int = 15, admin_key: str = Depends(verify_admin)):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT owner_id, status FROM agents WHERE agent_id = ?", (agent_id,))
    agent = cursor.fetchone()
    
    if not agent or agent["status"] != "active":
        conn.close()
        raise HTTPException(status_code=403, detail="Agent invalid or revoked.")
        
    cursor.execute("SELECT scope FROM agent_scopes WHERE agent_id = ? AND scope = ?", (agent_id, requested_scope))
    scope_check = cursor.fetchone()
    conn.close()
    
    if not scope_check:
        raise HTTPException(status_code=403, detail=f"Scope '{requested_scope}' not authorized.")

    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": agent_id,
        "owner": agent["owner_id"],
        "scope": requested_scope,
        "iat": now,
        "exp": now + datetime.timedelta(minutes=expires_in_minutes)
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    log_audit_event(agent_id, "token_issued", f"Minted {expires_in_minutes}-minute access token for scope: {requested_scope}")
    
    return {"access_token": token, "token_type": "bearer", "expires_in": expires_in_minutes * 60}

@app.post("/agents/{agent_id}/revoke")
def revoke_agent(agent_id: str, admin_key: str = Depends(verify_admin)):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT status FROM agents WHERE agent_id = ?", (agent_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Agent not found.")
        
    cursor.execute("UPDATE agents SET status = 'revoked' WHERE agent_id = ?", (agent_id,))
    conn.commit()
    conn.close()
    
    log_audit_event(agent_id, "agent_revoked", "Owner manually revoked all agent permissions.")
    return {"status": "success", "agent_id": agent_id, "message": "Agent permissions revoked immediately."}

# --- 1. NEW CENTRALIZED DEPENDENCY ---
def verify_active_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        agent_id = payload["sub"]
        
        # INSTANT REVOCATION CHECK: Ping the DB to ensure the agent wasn't killed
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM agents WHERE agent_id = ?", (agent_id,))
        agent = cursor.fetchone()
        conn.close()
        
        if not agent or agent["status"] != "active":
            raise HTTPException(status_code=401, detail="Scopr Guard: Agent access revoked.")
        
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token signature.")

# --- 2. UPDATE ENDPOINTS TO USE IT ---
@app.post("/oauth/verify")
def verify_agent_token(payload: dict = Depends(verify_active_token)):
    return {"status": "valid", "agent_id": payload["sub"], "granted_scope": payload["scope"]}

@app.post("/resource/github/commit")
def simulate_github_commit(payload: dict = Depends(verify_active_token)):
    if payload["scope"] != "github:repo:write":
        raise HTTPException(status_code=403, detail="Insufficient scope for this action.")
        
    log_audit_event(payload["sub"], "resource_accessed", "Successfully executed git commit via scoped token.")
    return {"status": "success", "message": "Action executed.", "executed_by_agent": payload["sub"], "verified_scope": payload["scope"]}
   