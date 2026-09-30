import pytest
from fastapi.testclient import TestClient
from scopr.server.main import app
import sqlite3
import os

client = TestClient(app)

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scopr", "server", "scopr.db")

def reset_agent():
    """Helper to ensure the test agent is active before each test."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE agents SET status = 'active' WHERE agent_id = 'agent_123'")
    conn.commit()
    conn.close()

def test_token_issuance_success():
    reset_agent()
    response = client.post("/oauth/token", params={"agent_id": "agent_123", "requested_scope": "github:repo:write"})
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["expires_in"] == 900  # Default 15 mins (900 seconds)

def test_scope_mismatch_rejection():
    reset_agent()
    response = client.post("/oauth/token", params={"agent_id": "agent_123", "requested_scope": "invalid:evil:scope"})
    assert response.status_code == 403
    assert "not authorized" in response.json()["detail"]

def test_revocation_kill_switch():
    reset_agent()
    # 1. Revoke the agent via the API
    revoke_response = client.post("/agents/agent_123/revoke")
    assert revoke_response.status_code == 200
    assert revoke_response.json()["status"] == "success"
    
    # 2. Attempt to get a token as a revoked agent
    token_response = client.post("/oauth/token", params={"agent_id": "agent_123", "requested_scope": "github:repo:write"})
    assert token_response.status_code == 403
    assert "invalid or revoked" in token_response.json()["detail"]
    
    # Reset for local dev environment
    reset_agent()
