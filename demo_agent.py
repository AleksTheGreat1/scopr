from tether.sdk.tether_sdk import TetherClient

# Initialize the Tether client pointing to your local server
tether = TetherClient()

AGENT_ID = "agent_123"
REQUIRED_SCOPE = "github:repo:write"

print("🛡️ Initializing Tether SDK wrapper for autonomous agent...")

try:
    # 1. Execute a protected tool call cleanly through the SDK
    print(f"🔄 Requesting scoped authorization for scope: [{REQUIRED_SCOPE}]...")
    result = tether.execute_action(
        agent_id=AGENT_ID,
        scope=REQUIRED_SCOPE,
        endpoint="/resource/github/commit"
    )
    
    print("\n🎉 SDK Action Execution Successful!")
    print(result)

except Exception as e:
    print(f"\n❌ Tether Authorization Error: {e}")
