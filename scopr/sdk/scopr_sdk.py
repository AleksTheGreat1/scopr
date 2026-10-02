import functools
import inspect
from typing import Any, Callable, Dict, Optional, Tuple
import requests


class ScoprClient:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        admin_key: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.admin_key = admin_key
        self.timeout = timeout
        self._cached_tokens: Dict[Tuple[str, str], str] = {}
        # Step 8: Reusable HTTP session for connection pooling
        self.session = requests.Session()

    def get_token(self, agent_id: str, scope: str, expires_in_minutes: int = 15) -> str:
        """Requests a scoped, time-limited token using the Admin Key."""
        headers = {"X-Admin-Key": self.admin_key} if self.admin_key else {}
        response = self.session.post(
            f"{self.base_url}/oauth/token",
            params={
                "agent_id": agent_id,
                "requested_scope": scope,
                "expires_in_minutes": expires_in_minutes,
            },
            headers=headers,
            timeout=self.timeout,
        )

        if response.status_code != 200:
            detail = response.json().get("detail", response.text)
            raise PermissionError(f"Scopr Auth Failed: {detail}")

        data = response.json()
        token = data["access_token"]
        self._cached_tokens[(agent_id, scope)] = token
        return token

    def verify_token(self, token: str) -> dict:
        """Verifies a token with the Scopr server."""
        headers = {"Authorization": f"Bearer {token}"}
        response = self.session.post(
            f"{self.base_url}/oauth/verify",
            headers=headers,
            timeout=self.timeout,
        )
        if response.status_code != 200:
            detail = response.json().get("detail", response.text)
            raise PermissionError(f"Scopr Verification Failed: {detail}")
        return response.json()

    def execute_action(
        self,
        agent_id: str,
        scope: str,
        endpoint: str,
        payload: Optional[dict] = None,
    ) -> dict:
        """Acquires a token and executes an action against a protected endpoint."""
        token = self._cached_tokens.get((agent_id, scope))
        if not token:
            token = self.get_token(agent_id, scope)

        headers = {"Authorization": f"Bearer {token}"}
        url = f"{self.base_url}{endpoint}"

        res = self.session.post(url, headers=headers, json=payload or {}, timeout=self.timeout)

        # Retry once on 401 in case token expired
        if res.status_code == 401:
            token = self.get_token(agent_id, scope)
            headers = {"Authorization": f"Bearer {token}"}
            res = self.session.post(url, headers=headers, json=payload or {}, timeout=self.timeout)

        if res.status_code != 200:
            raise RuntimeError(f"Action blocked by Scopr policy: {res.text}")

        return res.json()

    def protect(self, agent_id: str, scope: str):
        """Genuine runtime guard decorator (Step 5).
        
        Verifies authorization with Scopr and injects the verified context
        (scopr_token / scopr_auth) into the tool function if it accepts it.
        """
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            sig = inspect.signature(func)

            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                # 1. Fetch fresh active token from Scopr
                token = self.get_token(agent_id, scope)
                
                # 2. Verify token and claims against active policy
                verified = self.verify_token(token)

                # 3. Inject authorization proof into function parameters if accepted
                if "scopr_token" in sig.parameters:
                    kwargs["scopr_token"] = token
                if "scopr_auth" in sig.parameters:
                    kwargs["scopr_auth"] = verified

                return func(*args, **kwargs)

            return wrapper
        return decorator
    