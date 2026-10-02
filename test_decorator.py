from scopr.sdk.scopr_sdk import ScoprClient

# Initialize the Tether client
scopr = ScoprClient("http://127.0.0.1:8000")
AGENT_ID = "agent_123"
SCOPE = "github:repo:write"

# Define a standard tool function secured with the Scopr decorator
@scopr.protect(agent_id=AGENT_ID, scope=SCOPE)
def push_code_to_github(commit_message: str):
    print(f"🚀 Executing tool logic: Pushing commit -> '{commit_message}'")
    return {"status": "committed", "message": commit_message}

# Simulate the agent calling the tool
if __name__ == "__main__":
    print("🤖 Agent attempting to run protected tool...")
    try:
        result = push_code_to_github("Fix critical security bug in auth module")
        print(f"🎉 Tool Result: {result}")
    except Exception as e:
        print(f"❌ Execution Blocked: {e}")
