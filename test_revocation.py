import requests
from scopr.sdk.scopr_sdk import ScoprClient

# Initialize Tether client and server base URL
BASE_URL = "http://127.0.0.1:8000"
scopr = ScoprClient(BASE_URL)
AGENT_ID = "agent_123"
SCOPE = "github:repo:write"

# Define a protected tool
@scopr.protect(agent_id=AGENT_ID, scope=SCOPE)
def sensitive_deployment_tool(service_name: str):
    print(f"🚀 [DESTRUCTION/DEPLOY] Deploying {service_name} to production...")
    return {"status": "deployed", "service": service_name}

if __name__ == "__main__":
    print("--- PHASE 1: Normal Operation ---")
    try:
        res = sensitive_deployment_tool("auth-service-v2")
        print(f"Result: {res}\n")
    except Exception as e:
        print(f"Blocked: {e}\n")

    print("--- PHASE 2: Triggering Emergency Kill-Switch ---")
    print(f"🚨 Revoking agent [{AGENT_ID}] on the server...")
    
    # Hit the server's revocation endpoint directly
    revoke_res = requests.post(f"{BASE_URL}/agents/{AGENT_ID}/revoke")
    print(f"Server Response: {revoke_res.json()}\n")

    print("--- PHASE 3: Post-Revocation Attempt ---")
    print("🤖 Agent attempting to run protected tool post-revocation...")
    
    try:
        res = sensitive_deployment_tool("unauthorized-rogue-payload")
        print(f"Result: {res}")
    except Exception as e:
        print(f"❌ SUCCESS! Action correctly blocked by kill-switch: {e}")
