# Python with Managed Identity (running in Azure)

import json
import os
import requests

SUBSCRIPTION_ID = "subscriptionID"
RESOURCE_GROUP  = "my-resourcegroup"
ACCOUNT_NAME    = "Bing-custom2"
CONFIG_NAME     = "Bing-custom2-config"
API_VERSION     = "2025-05-01-preview"

# Optional: user-assigned client ID (if you use UAMI)
USER_ASSIGNED_CLIENT_ID = os.getenv("MSI_CLIENT_ID")  # or set it directly as a string

# Get token from IMDS for ARM
params = {
    "resource": "https://management.azure.com/",
    "api-version": "2018-02-01"
}
headers = {"Metadata": "true"}
if USER_ASSIGNED_CLIENT_ID:
    params["client_id"] = USER_ASSIGNED_CLIENT_ID

token_resp = requests.get(
    "http://169.254.169.254/metadata/identity/oauth2/token",
    params=params,
    headers=headers,
    timeout=5
)
token_resp.raise_for_status()
access_token = token_resp.json()["access_token"]

# PUT URL
base = "https://management.azure.com"
put_url = (
    f"{base}/subscriptions/{SUBSCRIPTION_ID}"
    f"/resourceGroups/{RESOURCE_GROUP}"
    f"/providers/Microsoft.Bing/accounts/{ACCOUNT_NAME}"
    f"/customSearchConfigurations/{CONFIG_NAME}"
    f"?api-version={API_VERSION}"
)

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

resp = requests.put(put_url, headers=headers, data=json.dumps(payload), timeout=60)
print("Status:", resp.status_code)
print("Response:", resp.text)
resp.raise_for_status()
