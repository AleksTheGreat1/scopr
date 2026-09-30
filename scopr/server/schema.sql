-- The human who owns the AI agent
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL
);

-- The autonomous software acting on their behalf
CREATE TABLE agents (
    agent_id TEXT PRIMARY KEY,
    owner_id TEXT REFERENCES users(user_id),
    name TEXT NOT NULL,
    status TEXT DEFAULT 'active'
);

-- The specific, restricted actions the agent is allowed to take
CREATE TABLE agent_scopes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT REFERENCES agents(agent_id),
    scope TEXT NOT NULL
);
