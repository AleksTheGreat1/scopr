import requests

BASE_URL = "http://127.0.0.1:8000"
AGENT_ID = "agent_123"
SCOPE = "github:repo:write"

print("🤖 AI Agent initiating authentication workflow...")

# Step 1: Request an access token from Scopr
token_res = requests.post(
    f"{BASE_URL}/oauth/token",
    params={"agent_id": AGENT_ID, "requested_scope": SCOPE}
)

if token_res.status_code != 200:
    print(f"❌ Authentication failed: {token_res.json()}")
    exit()

token_data = token_res.json()
access_token = token_data["access_token"]
print(f"✅ Token acquired successfully! (Expires in {token_data['expires_in']}s)")

# Step 2: Use the token to access a protected resource
print("\n🚀 Agent attempting to execute protected action (git commit)...")
headers = {"Authorization": f"Bearer {access_token}"}
resource_res = requests.post(f"{BASE_URL}/resource/github/commit", headers=headers)

if resource_res.status_code == 200:
    print("🎉 Action authorized and executed successfully!")
    print(resource_res.json())
else:
    print(f"❌ Action blocked: {resource_res.json()}")
