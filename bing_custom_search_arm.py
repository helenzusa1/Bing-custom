
#!/usr/bin/env python3
"""
Authenticate via the chosen mode, then configure Bing Custom Search via ARM:
  1) If Microsoft.Bing/accounts/{account} exists -> skip; else PUT (create)
  2) If customSearchConfigurations/{config} exists -> update via PUT; else create via PUT

Configuration comes from a .env file and JSON list files (allowed/blocked).
Auth modes supported: serviceprincipal | managedidentity | azurecli | interactive

There are 5 ways to run:

1> python bing_custom_search_arm.py --mode interactive
2> python bing_custom_search_arm.py --mode azurecli
3> python bing_custom_search_arm.py --mode serviceprincipal
4> python bing_custom_search_arm.py --mode managedidentity #This mode only works in Azure-hosted resources
5> python bing_custom_search_arm.py   # This will default to serviceprincipal mode

"""

import os
import sys
import json
import time
import argparse
from typing import Optional, List, Dict

import requests
from dotenv import load_dotenv
from azure.identity import (
    InteractiveBrowserCredential,
    AzureCliCredential,
    ManagedIdentityCredential,
    ClientSecretCredential,
)

# ===== Constants =====
ARM_SCOPE = "https://management.azure.com/.default"  # ARM audience for token
ARM_BASE = "https://management.azure.com"
RETRYABLE_STATUSES = (429, 500, 502, 503, 504)

AUTH_MODES = {"interactive", "azurecli", "managedidentity", "serviceprincipal"}

# -------------- Utility: JSON loader --------------
def load_json_array(path: Optional[str], label: str) -> Optional[List[Dict]]:
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError(f"{label} JSON must be an array of objects.")
        return data
    except Exception as e:
        raise RuntimeError(f"Failed to load {label} from {path}: {e}")

# -------------- Auth helpers --------------
def build_credential(mode: str,
                     tenant_id: Optional[str],
                     client_id: Optional[str],
                     client_secret: Optional[str],
                     mi_client_id: Optional[str]):
    """
    Construct the credential for the requested mode.
    """
    if mode == "interactive":
        if not tenant_id:
            raise ValueError("interactive mode requires --tenant-id or TENANT_ID in .env")
        return InteractiveBrowserCredential(tenant_id=tenant_id)

    if mode == "azurecli":
        return AzureCliCredential()

    if mode == "managedidentity":
        return ManagedIdentityCredential(client_id=mi_client_id) if mi_client_id else ManagedIdentityCredential()

    if mode == "serviceprincipal":
        if not (tenant_id and client_id and client_secret):
            raise ValueError("serviceprincipal mode requires TENANT_ID, CLIENT_ID, CLIENT_SECRET")
        return ClientSecretCredential(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)

    raise ValueError(f"Unsupported auth mode: {mode}")


def get_arm_token(credential) -> str:
    """
    Acquire an ARM audience token (aud=https://management.azure.com).
    """
    token = credential.get_token(ARM_SCOPE)
    return token.token

# -------------- HTTP helpers --------------
def auth_headers(token: str):
    if not token:
        raise ValueError("Missing Bearer token.")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

def put_with_retry(url: str, headers: dict, payload: dict, max_retries: int = 6, base_delay: float = 1.0) -> requests.Response:
    """
    PUT with exponential backoff honoring Retry-After (if present).
    """
    attempt = 0
    while True:
        resp = requests.put(url, headers=headers, data=json.dumps(payload))
        if resp.status_code < 400:
            return resp

        if resp.status_code in RETRYABLE_STATUSES and attempt < max_retries:
            attempt += 1
            delay = base_delay * (2 ** (attempt - 1))
            ra = resp.headers.get("Retry-After")
            if ra:
                try:
                    delay = max(delay, float(ra))
                except ValueError:
                    pass
            time.sleep(delay)
            continue

        raise RuntimeError(f"PUT {url} failed with {resp.status_code}: {resp.text}")

def get_ok_or_404(url: str, headers: dict) -> Optional[dict]:
    r = requests.get(url, headers=headers)
    if r.status_code == 404:
        return None
    if r.status_code >= 400:
        raise RuntimeError(f"GET {url} failed with {r.status_code}: {r.text}")
    return r.json() if r.content else {}

# -------------- Optional pre-flight checks --------------
def ensure_provider_registered(token: str, subscription_id: str):
    url = f"{ARM_BASE}/subscriptions/{subscription_id}/providers/Microsoft.Bing?api-version=2021-04-01"
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    if r.status_code >= 400:
        raise RuntimeError(f"Provider check failed: {r.status_code}: {r.text}")
    state = (r.json() or {}).get("registrationState")
    if state != "Registered":
        raise RuntimeError(
            f"Provider 'Microsoft.Bing' not registered (state={state}). "
            f"Run: az provider register --namespace Microsoft.Bing --subscription {subscription_id}"
        )

def ensure_rg_exists(token: str, subscription_id: str, resource_group: str):
    url = f"{ARM_BASE}/subscriptions/{subscription_id}/resourcegroups/{resource_group}?api-version=2021-04-01"
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    if r.status_code == 404:
        raise RuntimeError(f"Resource group '{resource_group}' not found in subscription '{subscription_id}'.")
    if r.status_code >= 400:
        raise RuntimeError(f"RG check failed: {r.status_code}: {r.text}")

# -------------- Validation --------------
_ALLOWED_BOOSTS = {"Default", "Elevated", "Demoted"}

def validate_domains(domains: Optional[List[Dict]], label: str):
    if not domains:
        return
    for d in domains:
        domain = d.get("domain")
        if not domain or not isinstance(domain, str):
            raise ValueError(f"{label}: each entry requires a non-empty 'domain' string.")
        isp = d.get("includeSubPages")
        if isp is None:
            # ARM/Bing expect explicit boolean; make it explicit to avoid backend defaults confusion
            raise ValueError(f"{label}: domain '{domain}' must set 'includeSubPages': true|false.")
        boost = d.get("boostLevel")
        if boost is not None:
            if boost not in _ALLOWED_BOOSTS:
                raise ValueError(f"{label}: domain '{domain}' has invalid boostLevel '{boost}'. Allowed: {_ALLOWED_BOOSTS}.")
            if isp is False:
                raise ValueError(f"{label}: domain '{domain}' sets boostLevel but includeSubPages=false. "
                                 f"BoostLevel requires includeSubPages=true.")

# -------------- Bing operations --------------
def account_exists(token: str, subscription_id: str, resource_group: str, account_name: str, api_version: str) -> bool:
    url = (
        f"{ARM_BASE}/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Bing/accounts/{account_name}"
        f"?api-version={api_version}"
    )
    hdr = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=hdr)
    if r.status_code == 404:
        return False
    if r.status_code >= 400:
        raise RuntimeError(f"Account existence check failed: {r.status_code}: {r.text}")
    return True

def config_exists(token: str, subscription_id: str, resource_group: str, account_name: str, config_name: str, api_version: str) -> bool:
    url = (
        f"{ARM_BASE}/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Bing/accounts/{account_name}"
        f"/customSearchConfigurations/{config_name}"
        f"?api-version={api_version}"
    )
    hdr = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=hdr)
    if r.status_code == 404:
        return False
    if r.status_code >= 400:
        raise RuntimeError(f"Config existence check failed: {r.status_code}: {r.text}")
    return True

def create_or_update_bing_account(token: str,
                                  subscription_id: str,
                                  resource_group: str,
                                  account_name: str,
                                  api_version: str) -> dict:
    url = (
        f"{ARM_BASE}/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Bing/accounts/{account_name}"
        f"?api-version={api_version}"
    )
    headers = auth_headers(token)
    payload = {
        "type": "Microsoft.Bing/accounts",
        "location": "global",
        "sku": {"name": "G2"},
        "kind": "Bing.GroundingCustomSearch",
        "tags": {"name": account_name}
    }
    resp = put_with_retry(url, headers, payload)
    return resp.json() if resp.content else {}

def set_custom_search_configuration(token: str,
                                    subscription_id: str,
                                    resource_group: str,
                                    account_name: str,
                                    config_name: str,
                                    allowed_domains: Optional[List[Dict]],
                                    blocked_domains: Optional[List[Dict]],
                                    api_version: str) -> dict:
    url = (
        f"{ARM_BASE}/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Bing/accounts/{account_name}"
        f"/customSearchConfigurations/{config_name}"
        f"?api-version={api_version}"
    )
    headers = auth_headers(token)

    # Validate before PUT to avoid backend 400/500s
    validate_domains(allowed_domains, "allowedDomains")
    validate_domains(blocked_domains, "blockedDomains")

    payload = {"properties": {}}
    if blocked_domains is not None:
        payload["properties"]["blockedDomains"] = blocked_domains
    if allowed_domains is not None:
        payload["properties"]["allowedDomains"] = allowed_domains

    if not payload["properties"]:
        # Nothing to update; avoid sending an empty properties object which may be rejected
        return {}

    resp = put_with_retry(url, headers, payload)
    return resp.json() if resp.content else {}

# -------------- CLI / main --------------
def parse_args():
    p = argparse.ArgumentParser(description="Configure Bing Custom Search account and domain lists (env-driven).")
    p.add_argument(
        "--mode",
        choices=list(AUTH_MODES),
        default=os.getenv("AZURE_AUTH_MODE", os.getenv("AUTH_MODE", "serviceprincipal")),
        help="Auth mode. Defaults to serviceprincipal (or AZURE_AUTH_MODE/AUTH_MODE)."
    )
    # Allow CLI overrides (env/.env still loaded)
    p.add_argument("--tenant-id", default=os.getenv("TENANT_ID"))
    p.add_argument("--subscription-id", default=os.getenv("SUBSCRIPTION_ID"))
    p.add_argument("--client-id", default=os.getenv("CLIENT_ID"))
    p.add_argument("--client-secret", default=os.getenv("CLIENT_SECRET"))
    p.add_argument("--mi-client-id", default=os.getenv("MI_CLIENT_ID"))

    p.add_argument("--resource-group", default=os.getenv("RESOURCE_GROUP"))
    p.add_argument("--account-name",  default=os.getenv("ACCOUNT_NAME"))
    p.add_argument("--config-name",   default=os.getenv("CONFIG_NAME"))

    p.add_argument("--allowed-json",  default=os.getenv("ALLOWED_DOMAINS_FILE"))
    p.add_argument("--blocked-json",  default=os.getenv("BLOCKED_DOMAINS_FILE"))

    # API versions (env-overridable + CLI override)
    p.add_argument("--account-api-version", default=os.getenv("ACCOUNT_API_VERSION", "2020-06-10"))
    p.add_argument("--config-api-version",  default=os.getenv("CONFIG_API_VERSION",  "2025-05-01-preview"))

    # Optional: skip preflight checks
    p.add_argument("--skip-preflight", action="store_true", help="Skip provider/RG checks.")

    return p.parse_args()


def main():
    # Load .env first so os.getenv() works for defaults
    load_dotenv()

    args = parse_args()

    # Validate required values
    missing = []
    for k in ("SUBSCRIPTION_ID", "RESOURCE_GROUP", "ACCOUNT_NAME"):
        if not os.getenv(k) and not getattr(args, k.lower()):
            missing.append(k)
    if missing:
        print(f"[ERROR] Missing required settings: {', '.join(missing)} "
              f"(set in .env or pass via CLI).", file=sys.stderr)
        sys.exit(1)

    # Normalize names from args
    tenant_id       = args.tenant_id
    subscription_id = args.subscription_id
    client_id       = args.client_id
    client_secret   = args.client_secret
    mi_client_id    = args.mi_client_id
    resource_group  = args.resource_group
    account_name    = args.account_name
    config_name     = args.config_name or f"{account_name}-config"

    account_api_version = args.account_api_version
    config_api_version  = args.config_api_version

    # Mode-specific checks
    if args.mode in {"interactive", "serviceprincipal"} and not tenant_id:
        print(f"[ERROR] --tenant-id (or TENANT_ID) is required for mode '{args.mode}'.", file=sys.stderr)
        sys.exit(1)

    # 1) Authenticate & get Bearer token
    print(f"[INFO] Auth mode: {args.mode}")
    cred = build_credential(args.mode, tenant_id, client_id, client_secret, mi_client_id)
    token = get_arm_token(cred)
    print(f"[INFO] Acquired ARM token: {token[:32]}... (truncated)")

    # 2) Optional preflight checks
    if not args.skip_preflight:
        ensure_provider_registered(token, subscription_id)
        ensure_rg_exists(token, subscription_id, resource_group)

    # 3) Account: GET -> skip or PUT (create)
    print("[STEP] Checking if Bing account exists ...")
    if account_exists(token, subscription_id, resource_group, account_name, account_api_version):
        print(f"[INFO] Bing account '{account_name}' already exists — skipping account creation.")
    else:
        print(f"[INFO] Creating Bing account '{account_name}' ...")
        acct = create_or_update_bing_account(
            token=token,
            subscription_id=subscription_id,
            resource_group=resource_group,
            account_name=account_name,
            api_version=account_api_version
        )
        print(json.dumps(acct, indent=2) if acct else "[INFO] Account PUT returned no body.")

    # 4) Config: load domain lists; if provided, GET existence -> PUT (create/update)
    allowed = load_json_array(args.allowed_json, "allowed domains") if args.allowed_json else None
    blocked = load_json_array(args.blocked_json, "blocked domains") if args.blocked_json else None

    if allowed is None and blocked is None:
        print("\n[STEP] No allowed/blocked JSON provided — skipping configuration update.")
    else:
        print("\n[STEP] Checking if configuration exists ...")
        exists = config_exists(token, subscription_id, resource_group, account_name, config_name, config_api_version)
        if exists:
            print(f"[INFO] Config '{config_name}' exists — updating with provided lists.")
        else:
            print(f"[INFO] Config '{config_name}' not found — creating it.")

        cfg = set_custom_search_configuration(
            token=token,
            subscription_id=subscription_id,
            resource_group=resource_group,
            account_name=account_name,
            config_name=config_name,
            allowed_domains=allowed,
            blocked_domains=blocked,
            api_version=config_api_version
        )
        print(json.dumps(cfg, indent=2) if cfg else "[INFO] Config PUT returned no body.")

    print("\n[DONE] Bing account + configuration flow completed successfully.")


if __name__ == "__main__":
    main()

