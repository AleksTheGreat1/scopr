import requests

class ScoprClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url
        self._cached_tokens = {}

    def get_token(self, agent_id: str, scope: str) -> str:
        """Requests a scoped, time-limited token for the given agent."""
        response = requests.post(
            f"{self.base_url}/oauth/token",
            params={"agent_id": agent_id, "requested_scope": scope}
        )
        
        if response.status_code != 200:
            raise PermissionError(f"Scopr Auth Failed: {response.json().get('detail')}")
            
        data = response.json()
        token = data["access_token"]
        self._cached_tokens[scope] = token
        return token

    def execute_action(self, agent_id: str, scope: str, endpoint: str, payload: dict = None) -> dict:
        """Automatically acquires a token (or uses cached) and executes a protected resource action."""
        token = self._cached_tokens.get(scope)
        if not token:
            token = self.get_token(agent_id, scope)
            
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{self.base_url}{endpoint}"
        
        res = requests.post(url, headers=headers, json=payload or {})
        
        # If token expired or was unauthorized, try refreshing once
        if res.status_code in [401, 403]:
            token = self.get_token(agent_id, scope)
            headers = {"Authorization": f"Bearer {token}"}
            res = requests.post(url, headers=headers, json=payload or {})
            
        if res.status_code != 200:
            raise RuntimeError(f"Action blocked by Scopr policy: {res.json()}")
            
        return res.json()

    def protect(self, agent_id: str, scope: str):
        """A decorator that wraps any function/tool, ensuring valid Tether authorization before execution."""
        def decorator(func):
            def wrapper(*args, **kwargs):
                print(f"🛡️ Scopr Guard: Verifying agent [{agent_id}] for scope [{scope}]...")
                # FIX: Force a fresh server check on every execution to guarantee instant revocation works
                self.get_token(agent_id, scope)
                return func(*args, **kwargs)
            return wrapper
        return decorator

