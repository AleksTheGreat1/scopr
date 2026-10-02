import os
import tempfile
import sqlite3
import pytest
import jwt
import datetime
from fastapi.testclient import TestClient

# 1. Force a secure environment key for testing BEFORE importing the app (Must be 32+ chars for pyjwt)
os.environ["SCOPR_SECRET_KEY"] = "super_secret_test_key_999_make_it_long_enough"

# 2. Intercept the server and reroute the database to an isolated temporary file
import scopr.server.main as main
temp_db_fd, temp_db_path = tempfile.mkstemp(suffix=".db")
main.DB_FILE = temp_db_path

from scopr.server.main import app, SECRET_KEY

client = TestClient(app)
ADMIN_HEADERS = {"X-Admin-Key": SECRET_KEY}

@pytest.fixture(autouse=True)
def setup_isolated_db():
    """Wipes and rebuilds the test database before EVERY test to guarantee absolute isolation."""
    conn = sqlite3.connect(main.DB_FILE)
    cursor = conn.cursor()
    
    # Drop existing tables to ensure a clean slate
    cursor.execute("DROP TABLE IF EXISTS agents")
    cursor.execute("DROP TABLE IF EXISTS agent_scopes")
    cursor.execute("DROP TABLE IF EXISTS audit_logs")
    
    # Rebuild Schema
    cursor.execute("CREATE TABLE agents (agent_id TEXT PRIMARY KEY, owner_id TEXT, status TEXT)")
    cursor.execute("CREATE TABLE agent_scopes (agent_id TEXT, scope TEXT)")
    cursor.execute("CREATE TABLE audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, event_type TEXT, description TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
    
    # Seed Test Data: Agent A (GitHub Writer) and Agent B (Database Reader)
    cursor.execute("INSERT INTO agents (agent_id, owner_id, status) VALUES ('agent_A', 'owner_1', 'active')")
    cursor.execute("INSERT INTO agent_scopes (agent_id, scope) VALUES ('agent_A', 'github:repo:write')")
    
    cursor.execute("INSERT INTO agents (agent_id, owner_id, status) VALUES ('agent_B', 'owner_1', 'active')")
    cursor.execute("INSERT INTO agent_scopes (agent_id, scope) VALUES ('agent_B', 'db:read')")
    
    conn.commit()
    conn.close()

# --- HAPPY PATHS ---

def test_token_issuance_success():
    """Test standard token minting."""
    response = client.post("/oauth/token", params={"agent_id": "agent_A", "requested_scope": "github:repo:write"}, headers=ADMIN_HEADERS)
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_resource_access_success():
    """Test using a valid token to access a protected resource."""
    token_response = client.post("/oauth/token", params={"agent_id": "agent_A", "requested_scope": "github:repo:write"}, headers=ADMIN_HEADERS)
    valid_token = token_response.json()["access_token"]
    
    resource_response = client.post("/resource/github/commit", headers={"Authorization": f"Bearer {valid_token}"})
    assert resource_response.status_code == 200
    assert resource_response.json()["status"] == "success"

# --- ADVERSARIAL & AUTHORIZATION TESTS ---

def test_admin_auth_required():
    """Ensure requests with invalid admin keys are rejected."""
    # FIX: Send a deliberately incorrect key to trigger our custom logic
    response = client.post("/oauth/token", params={"agent_id": "agent_A", "requested_scope": "github:repo:write"}, headers={"X-Admin-Key": "completely_wrong_key"})
    assert response.status_code == 403
    assert "Invalid Admin Key" in response.json()["detail"]

def test_scope_escalation_blocked():
    """Ensure an agent cannot request scopes they were not granted in the database."""
    response = client.post("/oauth/token", params={"agent_id": "agent_A", "requested_scope": "system:admin:all"}, headers=ADMIN_HEADERS)
    assert response.status_code == 403
    assert "not authorized" in response.json()["detail"]

def test_cross_agent_scope_blocked():
    """Ensure Agent B cannot request Agent A's scopes."""
    response = client.post("/oauth/token", params={"agent_id": "agent_B", "requested_scope": "github:repo:write"}, headers=ADMIN_HEADERS)
    assert response.status_code == 403
    assert "not authorized" in response.json()["detail"]

def test_invalid_jwt_signature():
    """Ensure tampered tokens are instantly rejected."""
    token_response = client.post("/oauth/token", params={"agent_id": "agent_A", "requested_scope": "github:repo:write"}, headers=ADMIN_HEADERS)
    tampered_token = token_response.json()["access_token"][:-5] + "XXXXX"
    
    resource_response = client.post("/resource/github/commit", headers={"Authorization": f"Bearer {tampered_token}"})
    assert resource_response.status_code == 401
    assert "Invalid token signature" in resource_response.json()["detail"]

def test_expired_token_rejected():
    """Manually forge an expired token to ensure the server rejects it."""
    now = datetime.datetime.now(datetime.timezone.utc)
    expired_payload = {
        "sub": "agent_A",
        "owner": "owner_1",
        "scope": "github:repo:write",
        "iat": now - datetime.timedelta(hours=2),
        "exp": now - datetime.timedelta(hours=1) # Expired 1 hour ago
    }
    expired_token = jwt.encode(expired_payload, SECRET_KEY, algorithm="HS256")
    
    resource_response = client.post("/resource/github/commit", headers={"Authorization": f"Bearer {expired_token}"})
    assert resource_response.status_code == 401
    assert "expired" in resource_response.json()["detail"]

# --- INSTANT REVOCATION KILL-SWITCH ---

def test_revoked_agent_cannot_mint():
    """Ensure an agent cannot get a new token after being revoked."""
    client.post("/agents/agent_A/revoke", headers=ADMIN_HEADERS)
    response = client.post("/oauth/token", params={"agent_id": "agent_A", "requested_scope": "github:repo:write"}, headers=ADMIN_HEADERS)
    assert response.status_code == 403
    assert "invalid or revoked" in response.json()["detail"]

def test_instant_revocation_existing_token():
    """Ensure an unexpired token becomes instantly useless if the agent is killed mid-flight."""
    token_response = client.post("/oauth/token", params={"agent_id": "agent_A", "requested_scope": "github:repo:write"}, headers=ADMIN_HEADERS)
    valid_token = token_response.json()["access_token"]
    
    client.post("/agents/agent_A/revoke", headers=ADMIN_HEADERS)
    
    resource_response = client.post("/resource/github/commit", headers={"Authorization": f"Bearer {valid_token}"})
    assert resource_response.status_code == 401
    assert "access revoked" in resource_response.json()["detail"]

# Cleanup temp files when tests finish
def teardown_module(module):
    os.close(temp_db_fd)
    os.remove(temp_db_path)
