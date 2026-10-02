# Scopr 🎯

> **Scoped authorization and runtime permission guard for autonomous AI agents.**

When you give an AI agent access to your system tools — GitHub, a database, a server — handing it a permanent API key is a serious security risk. Scopr acts as an intermediary authorization layer: it issues time-boxed, scope-limited JWTs to agents and forces them to re-authenticate before executing sensitive actions, giving you an instant kill-switch if an agent goes rogue.

> **Status: Early development.** Core authorization, revocation, and audit logging work and are covered by tests, but Scopr has not yet had independent security review. Treat it as a prototype, not production-hardened infrastructure, until noted otherwise.

---

## Key Features

* **🔐 Scoped Authorization** — Agents only get access to the specific tools they need, e.g. `github:repo:write`, instead of a full-access credential.
* **⏱️ Time-Boxed Tokens** — JWT access tokens expire automatically (default 15 minutes).
* **⚡ Instant Kill-Switch** — Revoking an agent invalidates its access on the very next action, even for tokens already issued — not just future ones.
* **📋 Structured Event Audit Logging** — Every token minted, action executed, and revocation triggered is logged to a local SQLite database for inspection.
* **🔑 Admin-Gated Operations** — Token issuance and revocation both require an admin key, so agent identity alone isn't enough to mint or kill access.
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

### 2. Set Your Secret Keys

Create a `.env` file in the root directory (or export these directly):

```bash
echo "SCOPR_SECRET_KEY=your_super_secure_random_string" > .env
```

<!-- Once the admin key and JWT signing key are split in code, replace the
     line above with the two separate keys below:
echo "SCOPR_SECRET_KEY=your_jwt_signing_secret" > .env
echo "SCOPR_ADMIN_KEY=your_admin_key" >> .env
-->

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

Scopr is designed to make protecting an agent tool as simple as adding a decorator or a single call.

```python
import os
from scopr.sdk.scopr_sdk import ScoprClient

# Initialize the client with your admin key
scopr = ScoprClient(admin_key=os.getenv("SCOPR_SECRET_KEY"))

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
  -H "X-Admin-Key: your_super_secure_random_string"
```

Once revoked, any protected operation — including with a token issued *before* revocation — is rejected on its next use.

> **Note:** For local testing, you can restore an agent directly:
> ```bash
> sqlite3 scopr/server/scopr.db "UPDATE agents SET status = 'active' WHERE agent_id = 'agent_123';"
> ```

---

## Security & Testing

Scopr ships with a `pytest` suite covering token tampering, scope escalation, cross-agent access, and instant revocation edge cases, using an isolated temporary database per run.

```bash
pytest test_security.py -v
```

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

* [ ] Split admin key from JWT signing key
* [ ] Per-agent credentials (move off a single shared admin key)
* [ ] Token versioning / jti-based revocation
* [ ] OAuth provider integrations
* [ ] More granular, policy-based permissions
* [ ] Agent-to-agent authorization
* [ ] Cloud deployment support
* [ ] PostgreSQL support
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
4. **Revocation** — Provide an immediate way to terminate access.
5. **Auditability** — Record what the agent attempted and executed.

---

## License

This project is licensed under the **MIT License**.