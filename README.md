# Scopr 🔒🤖

> **OAuth for AI agents.** Scoped identity, instant revocation, and decorator-based tool protection for autonomous software.

When an AI agent acts on someone's behalf, whether booking a flight, modifying a codebase, or calling an enterprise API, it often needs to be given raw credentials such as a real password or a full-access API key.

That's a massive security risk with no standard, developer-friendly solution.

**Scopr** provides a lightweight identity and permissions layer for AI agents, allowing them to operate using **scoped, time-limited tokens instead of raw credentials**.

---

## Features

* **🔐 Scoped Access**
  Restrict agents to exact permissions, such as `github:repo:write`, instead of granting full account access.

* **🛡️ Decorator Protection**
  Secure local agent tools or functions instantly using `@scopr.protect(agent_id, scope)`.

* **⚡ Instant Revocation**
  Immediately cut off an agent's access using a kill switch, without changing underlying passwords or API keys.

* **📋 Structured Event Audit Logging**
  Maintain a time-stamped history of every action an agent attempts or executes.

* **💻 Zero-Infra / Local First**
  Built with FastAPI and SQLite, allowing developers to get started locally with minimal infrastructure.

---

## Architecture

At a high level, Scopr sits between an AI agent and the tools or resources it needs to access.

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

### 1. Clone the Repository

```bash
git clone https://github.com/AleksTheGreat1/scopr.git
cd scopr
```

### 2. Create a Virtual Environment

```bash
python3 -m venv scopr_env
source scopr_env/bin/activate
```

### 3. Install Dependencies

```bash
pip install fastapi uvicorn pyjwt requests python-dotenv
```

### 4. Configure Environment Variables

Create a `.env` file in the root directory to hold your cryptographic secret:

```bash
echo "SCOPR_SECRET_KEY=your_super_secure_random_string" > .env
```

### 5. Initialize the Database

```bash
sqlite3 scopr/server/scopr.db < scopr/server/schema.sql
```

### 6. Start the Server

```bash
uvicorn scopr.server.main:app --reload
```

The interactive API documentation will be available at:

```text
http://127.0.0.1:8000/docs
```

---

## Usage

### Python SDK & Decorators

Scopr is designed to make protecting an agent tool as simple as adding a decorator.

```python
from scopr.sdk.scopr_sdk import ScoprClient

# Initialize the client
scopr = ScoprClient("http://127.0.0.1:8000")


# Secure any agent tool with a single decorator
@scopr.protect(
    agent_id="agent_123",
    scope="github:repo:write"
)
def push_code_to_github(commit_message: str):
    print(f"Pushing commit -> {commit_message}")
    return {"status": "success"}


# Run the protected tool
push_code_to_github("Fix critical security bug")
```

The decorator allows Scopr to validate the agent's identity and requested scope before allowing the protected function to execute.

---

## Example Permission Scopes

Scopr uses granular scopes to control what an agent is allowed to do.

Examples:

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

Agents can be revoked immediately when access needs to be terminated via the API.

```bash
curl -X POST http://127.0.0.1:8000/agents/agent_123/revoke
```

Once revoked, any protected operations will instantly reject requests from that agent.

> **Note:** If you are testing locally and need to restore an agent, you can run:
> ```bash
> sqlite3 scopr/server/scopr.db "UPDATE agents SET status = 'active' WHERE agent_id = 'agent_123';"
> ```

---

## Project Structure

```text
scopr/
├── scopr/
│   ├── server/
│   │   ├── main.py
│   │   ├── schema.sql
│   │   └── scopr.db
│   │
│   └── sdk/
│       └── scopr_sdk.py
│
├── README.md
└── ...
```

---

## Roadmap

Potential future development areas include:

* [ ] Token expiration and automatic rotation
* [ ] OAuth provider integrations
* [ ] More granular permission policies
* [ ] Agent-to-agent authorization
* [ ] Cloud deployment support
* [ ] PostgreSQL support
* [ ] Web-based administration dashboard
* [ ] Expanded audit and monitoring capabilities
* [ ] Integration with popular AI agent frameworks
* [ ] Production-grade authentication and key management

---

## Security Philosophy

Scopr follows a simple principle:

> **Agents should never need more access than the action they are performing requires.**

Instead of giving an autonomous system a permanent credential with broad permissions, Scopr aims to provide:

1. **Identity**: Know which agent is making the request.
2. **Authorization**: Determine exactly what that agent is allowed to do.
3. **Expiration**: Limit how long access remains valid.
4. **Revocation**: Provide an immediate way to terminate access.
5. **Auditability**: Record what the agent attempted and executed.

---

## Development

Start the local development server with:

```bash
uvicorn scopr.server.main:app --reload
```

Then open:

```text
http://127.0.0.1:8000/docs
```

FastAPI's interactive documentation can be used to explore and test the available endpoints.

---

## License

This project is licensed under the **MIT License**.