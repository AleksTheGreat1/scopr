import os
from scopr.sdk.scopr_sdk import ScoprClient

# Initialize the Scopr client pointing to your local server
scopr = ScoprClient()

AGENT_ID = "agent_123"
REQUIRED_SCOPE = "github:repo:write"

print("🛡️ Initializing Scopr SDK wrapper for autonomous agent...")

try:
    # 1. Execute a protected tool call cleanly through the SDK
    print(f"🔄 Requesting scoped authorization for scope: [{REQUIRED_SCOPE}]...")
    result = scopr.execute_action(
        agent_id=AGENT_ID,
        scope=REQUIRED_SCOPE,
        endpoint="/resource/github/commit"
    )
    
    print("\n🎉 SDK Action Execution Successful!")
    print(result)

except Exception as e:
    print(f"\n❌ Scopr Authorization Error: {e}")
