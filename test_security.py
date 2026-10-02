import os
import tempfile
import sqlite3
import pytest
import jwt
import datetime
from fastapi.testclient import TestClient

os.environ["SCOPR_JWT_SECRET"] = "super_secret_test_key_999_make_it_long_enough_for_hs256"
os.environ["SCOPR_ADMIN_KEY"] = "super_secure_admin_key_for_testing_purposes"

import scopr.server.main as main
temp_db_fd, temp_db_path = tempfile.mkstemp(suffix=".db")
main.DB_FILE = temp_db_path

from scopr.server.main import app, JWT_SECRET, ADMIN_KEY
from scopr.sdk.scopr_sdk import ScoprClient

client = TestClient(app)
ADMIN_HEADERS = {"X-Admin-Key": ADMIN_KEY}

@pytest.fixture(autouse=True)
def setup_isolated_db():
    with sqlite3.connect(main.DB_FILE) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS audit_logs")
        cursor.execute("DROP TABLE IF EXISTS agent_scopes")
        cursor.execute("DROP TABLE IF EXISTS agents")

        cursor.execute("""
            CREATE TABLE agents (
                agent_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                status TEXT NOT NULL,
                token_version INTEGER NOT NULL DEFAULT 1
            )
        """)
        cursor.execute("""
            CREATE TABLE agent_scopes (
                agent_id TEXT NOT NULL,
                scope TEXT NOT NULL,
                PRIMARY KEY (agent_id, scope),
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE TABLE audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                description TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("INSERT INTO agents (agent_id, owner_id, status, token_version) VALUES ('agent_A', 'owner_1', 'active', 1)")
        cursor.execute("INSERT INTO agent_scopes (agent_id, scope) VALUES ('agent_A', 'github:repo:write')")

        cursor.execute("INSERT INTO agents (agent_id, owner_id, status, token_version) VALUES ('agent_B', 'owner_1', 'active', 1)")
        cursor.execute("INSERT INTO agent_scopes (agent_id, scope) VALUES ('agent_B', 'db:read')")

        conn.commit()

# --- HAPPY PATHS ---

def test_token_issuance_success():
    response = client.post("/oauth/token", params={"agent_id": "agent_A", "requested_scope": "github:repo:write"}, headers=ADMIN_HEADERS)
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_resource_access_success():
    token_response = client.post("/oauth/token", params={"agent_id": "agent_A", "requested_scope": "github:repo:write"}, headers=ADMIN_HEADERS)
    valid_token = token_response.json()["access_token"]

    resource_response = client.post("/resource/github/commit", headers={"Authorization": f"Bearer {valid_token}"})
    assert resource_response.status_code == 200
    assert resource_response.json()["status"] == "success"

# --- ADVERSARIAL & AUTHORIZATION BOUNDARY ---

def test_admin_auth_required():
    response = client.post("/oauth/token", params={"agent_id": "agent_A", "requested_scope": "github:repo:write"}, headers={"X-Admin-Key": "wrong_key"})
    assert response.status_code == 403
    assert "Invalid Admin Key" in response.json()["detail"]

def test_scope_escalation_blocked():
    response = client.post("/oauth/token", params={"agent_id": "agent_A", "requested_scope": "system:admin:all"}, headers=ADMIN_HEADERS)
    assert response.status_code == 403
    assert "not authorized" in response.json()["detail"]

def test_cross_agent_scope_blocked():
    response = client.post("/oauth/token", params={"agent_id": "agent_B", "requested_scope": "github:repo:write"}, headers=ADMIN_HEADERS)
    assert response.status_code == 403
    assert "not authorized" in response.json()["detail"]

def test_invalid_jwt_signature():
    token_response = client.post("/oauth/token", params={"agent_id": "agent_A", "requested_scope": "github:repo:write"}, headers=ADMIN_HEADERS)
    tampered_token = token_response.json()["access_token"][:-5] + "XXXXX"

    response = client.post("/resource/github/commit", headers={"Authorization": f"Bearer {tampered_token}"})
    assert response.status_code == 401
    assert "Invalid token" in response.json()["detail"]

def test_expired_token_rejected():
    now = datetime.datetime.now(datetime.timezone.utc)
    expired_payload = {
        "sub": "agent_A",
        "owner": "owner_1",
        "scope": "github:repo:write",
        "iss": "scopr",
        "aud": "scopr-resource",
        "jti": "dummy-expired-jti",
        "token_version": 1,
        "iat": now - datetime.timedelta(hours=2),
        "exp": now - datetime.timedelta(hours=1),
    }
    expired_token = jwt.encode(expired_payload, JWT_SECRET, algorithm="HS256")

    response = client.post("/resource/github/commit", headers={"Authorization": f"Bearer {expired_token}"})
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()

def test_max_lifetime_enforced():
    response = client.post("/oauth/token", params={"agent_id": "agent_A", "requested_scope": "github:repo:write", "expires_in_minutes": 999}, headers=ADMIN_HEADERS)
    assert response.status_code == 400
    assert "lifetime" in response.json()["detail"].lower()

def test_missing_jwt_claims_rejected():
    now = datetime.datetime.now(datetime.timezone.utc)
    bad_payload = {
        "sub": "agent_A",
        "scope": "github:repo:write",
        "iat": now,
        "exp": now + datetime.timedelta(minutes=15),
        "token_version": 1,
    }
    bad_token = jwt.encode(bad_payload, JWT_SECRET, algorithm="HS256")

    response = client.post("/resource/github/commit", headers={"Authorization": f"Bearer {bad_token}"})
    assert response.status_code == 401

# --- REVOCATION & TOKEN RESURRECTION ---

def test_revoked_agent_cannot_mint():
    client.post("/agents/agent_A/revoke", headers=ADMIN_HEADERS)
    response = client.post("/oauth/token", params={"agent_id": "agent_A", "requested_scope": "github:repo:write"}, headers=ADMIN_HEADERS)
    assert response.status_code == 403
    assert "invalid or revoked" in response.json()["detail"]

def test_instant_revocation_existing_token():
    token_response = client.post("/oauth/token", params={"agent_id": "agent_A", "requested_scope": "github:repo:write"}, headers=ADMIN_HEADERS)
    valid_token = token_response.json()["access_token"]

    client.post("/agents/agent_A/revoke", headers=ADMIN_HEADERS)

    response = client.post("/resource/github/commit", headers={"Authorization": f"Bearer {valid_token}"})
    assert response.status_code == 401
    assert "access revoked" in response.json()["detail"].lower()

def test_token_resurrection_blocked():
    token_response = client.post("/oauth/token", params={"agent_id": "agent_A", "requested_scope": "github:repo:write"}, headers=ADMIN_HEADERS)
    v1_token = token_response.json()["access_token"]

    client.post("/agents/agent_A/revoke", headers=ADMIN_HEADERS)

    with sqlite3.connect(main.DB_FILE) as conn:
        conn.cursor().execute("UPDATE agents SET status = 'active' WHERE agent_id = 'agent_A'")
        conn.commit()

    response = client.post("/resource/github/commit", headers={"Authorization": f"Bearer {v1_token}"})
    assert response.status_code == 401
    assert "obsolete" in response.json()["detail"].lower()

# --- SDK RUNTIME GUARD DECORATOR ---

def test_sdk_runtime_guard_injection(monkeypatch):
    sdk = ScoprClient(admin_key=ADMIN_KEY)
    # Reroute SDK HTTP calls through TestClient
    monkeypatch.setattr(sdk.session, "post", lambda url, **kwargs: client.post(url.replace("http://127.0.0.1:8000", ""), **{k: v for k, v in kwargs.items() if k != 'timeout'}))
    
    called = {}

    @sdk.protect(agent_id="agent_A", scope="github:repo:write")
    def tool_action(arg1, scopr_auth=None):
        called["arg1"] = arg1
        called["scopr_auth"] = scopr_auth
        return "success"

    res = tool_action("commit_files")
    assert res == "success"
    assert called["arg1"] == "commit_files"
    assert called["scopr_auth"]["agent_id"] == "agent_A"
    assert called["scopr_auth"]["granted_scope"] == "github:repo:write"

def teardown_module(module):
    os.close(temp_db_fd)
    os.remove(temp_db_path)
