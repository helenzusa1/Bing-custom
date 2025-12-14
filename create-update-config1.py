# Python with MSAL (service principal)

import json
import requests
from msal import ConfidentialClientApplication

# ---- Replace with your real values ----
TENANT_ID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
CLIENT_ID = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
CLIENT_SECRET = "***************"
SUBSCRIPTION_ID = "subscriptionID"
RESOURCE_GROUP = "my-resourcegroup"
ACCOUNT_NAME = "Bing-custom2"
CONFIG_NAME = "Bing-custom2-config"
API_VERSION = "2025-05-01-preview"

# ARM scope for AAD tokens
SCOPE = ["https://management.azure.com/.default"]
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"

# Acquire token
app = ConfidentialClientApplication(
    CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET
)
token = app.acquire_token_for_client(scopes=SCOPE)
if "access_token" not in token:
    raise RuntimeError(f"Token acquisition failed: {token}")

access_token = token["access_token"]

# Construct the PUT URL to Custom Search Configuration (matches your curl)
base = "https://management.azure.com"
put_url = (
    f"{base}/subscriptions/{SUBSCRIPTION_ID}"
    f"/resourceGroups/{RESOURCE_GROUP}"
    f"/providers/Microsoft.Bing/accounts/{ACCOUNT_NAME}"
    f"/customSearchConfigurations/{CONFIG_NAME}"
    f"?api-version={API_VERSION}"
)

# Payload (identical to your curl body)
payload = {
    "properties": {
        "blockedDomains": [
            {"domain": "www.aa.com", "includeSubPages": True},
            {"domain": "www.yahoo.com", "includeSubPages": False}
        ],
        "allowedDomains": [
            {"domain": "www.amazon.com", "includeSubPages": True, "boostLevel": "Demoted"},
            {"domain": "www.weather.com", "includeSubPages": False, "boostLevel": "Default"}
        ]
    }
}

headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json"
}

# Send request
resp = requests.put(put_url, headers=headers, data=json.dumps(payload), timeout=60)
print("Status:", resp.status_code)
print("Response:", resp.text)
resp.raise_for_status()  # ensure failures throw
