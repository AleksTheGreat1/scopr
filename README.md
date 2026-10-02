# Scopr 🎯

> **Scoped authorization and runtime permission guard for autonomous AI agents.**

When you give an AI agent access to your system tools — GitHub, a database, a server — handing it a permanent API key is a serious security risk. Scopr acts as an intermediary authorization layer: it issues time-boxed, scope-limited JWTs to agents and forces them to re-authenticate before executing sensitive actions, giving you an instant kill-switch if an agent goes rogue.

> **Status: v0.2.0 — Active development.** Core authorization, token versioning, revocation, and audit logging are implemented and covered by tests, but Scopr has not yet had independent security review. See "Security Limitations & Known Assumptions" below before using this with anything sensitive.

---

## Key Features

* **🔐 Scoped Authorization** — Agents only get access to the specific tools they need, e.g. `github:repo:write`, instead of a full-access credential.
* **⏱️ Time-Boxed Tokens** — JWT access tokens expire automatically (default 15 minutes, max 60 minutes).
* **⚡ Instant Kill-Switch** — Revoking an agent invalidates its access on the very next action, even for tokens already issued — and token versioning ensures a reactivated agent can't resurrect old, pre-revocation tokens.
* **📋 Structured Event Audit Logging** — Every token minted, action executed, and revocation triggered is logged to a local SQLite database for inspection.
* **🔑 Dual-Key Admin Security** — Token issuance and revocation require a dedicated admin key, kept separate from the key used to sign JWTs, so agent identity alone is never enough to mint or kill access.
* **💻 Zero Vendor Lock-In** — Fully local and self-hosted via FastAPI; no external service dependency.

---

## Architecture

```text
┌─────────────────┐
│    AI Agent     │
└────────┬────────┘
         │
         │ Scoped Token
         ▼
┌─────────────────┐
│     Scopr       │
│                 │
│ • Identity      │
│ • Permissions   │
│ • Revocation    │
│ • Audit Logs    │
└────────┬────────┘
         │
         │ Authorized Action
         ▼
┌─────────────────┐
│   Agent Tool    │
│ / API / Service │
└─────────────────┘
```

---

## Quickstart

### 1. Clone and Install

```bash
git clone https://github.com/AleksTheGreat1/scopr.git
cd scopr
pip install -e .
```

### 2. Set Your Security Keys

Scopr requires two distinct keys: one for signing JWTs, and one for authorizing administrative actions (minting tokens, revoking agents). Set them in your environment, or in a `.env` file in the root directory:

```bash
export SCOPR_JWT_SECRET="your_super_secure_jwt_signing_key_here"
export SCOPR_ADMIN_KEY="your_admin_endpoint_password_here"
```

### 3. Initialize the Database

```bash
sqlite3 scopr/server/scopr.db < scopr/server/schema.sql
```

### 4. Start the Server

```bash
uvicorn scopr.server.main:app --reload
```

Interactive API docs will be available at:

```text
http://127.0.0.1:8000/docs
```

---

## Usage

### Python SDK & Decorators

Scopr is designed to make protecting an agent tool as simple as adding a decorator or a single call. The decorator acts as a genuine runtime authorization boundary — it verifies the agent's token and injects the verified authorization context into the protected call, rather than just checking a token exists.

```python
import os
from scopr.sdk.scopr_sdk import ScoprClient

# Initialize the client with your admin key
scopr = ScoprClient(admin_key=os.getenv("SCOPR_ADMIN_KEY"))

AGENT_ID = "agent_123"
REQUIRED_SCOPE = "github:repo:write"

# The SDK automatically handles token fetching, caching, and 401 retries
result = scopr.execute_action(
    agent_id=AGENT_ID,
    scope=REQUIRED_SCOPE,
    endpoint="/resource/github/commit",
    payload={"commit_message": "Fixed bug in core engine"}
)

print(result)
```

Or protect a tool function directly with the decorator:

```python
@scopr.protect(agent_id="agent_123", scope="github:repo:write")
def push_code_to_github(commit_message: str):
    print(f"Pushing commit -> {commit_message}")
    return {"status": "success"}

push_code_to_github("Fix critical security bug")
```

---

## Example Permission Scopes

```text
github:repo:read
github:repo:write
github:repo:delete

database:read
database:write

calendar:read
calendar:write

email:read
email:send
```

The goal is to give an agent **only the permissions it actually needs**, rather than exposing an entire account or service.

---

## Agent Revocation

Agents can be revoked immediately when access needs to be terminated, via the admin-gated API:

```bash
curl -X POST http://127.0.0.1:8000/agents/agent_123/revoke \
  -H "X-Admin-Key: your_admin_endpoint_password_here"
```

Once revoked, any protected operation — including with a token issued *before* revocation — is rejected on its next use. Token versioning means this holds even if the agent is later reactivated: previously issued tokens stay invalid permanently, and a fresh token must be minted.

> **Note:** For local testing, you can restore an agent's active status directly:
> ```bash
> sqlite3 scopr/server/scopr.db "UPDATE agents SET status = 'active' WHERE agent_id = 'agent_123';"
> ```

---

## Security & Testing

Scopr ships with a `pytest` suite covering token tampering, scope escalation, cross-agent access, token lifetime limits, missing/invalid JWT claims, token resurrection after reactivation, and instant revocation edge cases — using an isolated temporary database per run.

```bash
pytest test_security.py -v
```

---

## Security Limitations & Known Assumptions (v0.2.0)

While Scopr hardens agent execution with time-boxed, verified JWTs and instant revocation, the following architectural assumptions remain unaddressed in the current version:

1. **Shared Admin Key:** A single `SCOPR_ADMIN_KEY` is used globally to mint tokens and revoke agents. If this key is compromised, an attacker can mint tokens for *any* registered agent. Future versions will introduce per-agent client credentials (Client ID / Client Secret) for token minting, reserving the global Admin Key strictly for provisioning and revocation.
2. **Bearer-Token Replay:** JWTs are standard bearer tokens. If a token is intercepted mid-flight, it can be replayed against the protected resource until it expires (max 60 minutes) or the agent is revoked. Future updates will explore Proof-of-Possession (PoP) or mTLS-bound tokens for highly sensitive environments.

---

## Project Structure

```text
scopr/
├── scopr/
│   ├── server/
│   │   ├── main.py
│   │   └── schema.sql
│   │
│   └── sdk/
│       └── scopr_sdk.py
│
├── test_security.py
├── pyproject.toml
├── README.md
└── LICENSE
```

---

## Roadmap

* [x] Split admin key from JWT signing key
* [x] Token versioning (prevents resurrected tokens after reactivation)
* [ ] Per-agent credentials (move off a single shared admin key)
* [ ] Proof-of-Possession / mTLS-bound tokens
* [ ] OAuth provider integrations
* [ ] More granular, policy-based permissions
* [ ] Agent-to-agent authorization
* [ ] Cloud deployment support
* [ ] PostgreSQL support
* [ ] Rate limiting on token issuance and revocation endpoints
* [ ] Web-based administration dashboard
* [ ] Integration with popular AI agent frameworks (MCP, LangChain, CrewAI, etc.)

---

## Security Philosophy

Scopr follows a simple principle:

> **Agents should never need more access than the action they are performing requires.**

Instead of giving an autonomous system a permanent credential with broad permissions, Scopr aims to provide:

1. **Identity** — Know which agent is making the request.
2. **Authorization** — Determine exactly what that agent is allowed to do.
3. **Expiration** — Limit how long access remains valid.
4. **Revocation** — Provide an immediate way to terminate access, permanently, even across reactivation.
5. **Auditability** — Record what the agent attempted and executed.

---

## License

This project is licensed under the **MIT License**.