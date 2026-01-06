
#!/usr/bin/env python3
"""
Reference article:
  https://learn.microsoft.com/en-us/azure/azure-monitor/platform/rest-api-walkthrough?tabs=SDK%2Cportal 
  
Azure SDK equivalent of:
  - az login --tenant "<tenant-id>"
  - az login --scope https://management.core.windows.net//.default   (SDK uses https://management.azure.com/.default)
  - az account get-access-token --resource https://management.azure.com
  - az account set --subscription "<subscription-id>"

Auth modes: interactive | devicecode | azurecli | managedidentity | serviceprincipal

Install:
  pip install azure-identity azure-mgmt-resource

Examples:
  python azure_login_arm.py --mode interactive --tenant-id <TENANT_ID> --subscription-id <SUB_ID> --prefetch
  python azure_login_arm.py --mode azurecli --subscription-id <SUB_ID> --print-token
  python azure_login_arm.py --mode serviceprincipal --tenant-id <TENANT_ID> --client-id <APP_ID> --client-secret <SECRET> --subscription-id <SUB_ID> --output-bearer

Env vars (optional):
  AZURE_AUTH_MODE, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID,
  AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_MI_CLIENT_ID
"""

import argparse
import os
import sys
from typing import Optional

from azure.identity import (
    InteractiveBrowserCredential,
    DeviceCodeCredential,
    AzureCliCredential,
    ManagedIdentityCredential,
    ClientSecretCredential,
    #ClientCertificateCredential,  # if you want cert auth; not used by default
)
from azure.mgmt.resource import ResourceManagementClient

ARM_SCOPE = "https://management.azure.com/.default"
AUTH_MODES = {"interactive", "devicecode", "azurecli", "managedidentity", "serviceprincipal"}


def build_credential(mode: str,
                     tenant_id: Optional[str],
                     client_id: Optional[str],
                     client_secret: Optional[str],
                     mi_client_id: Optional[str]):
    """Construct credential matching the requested mode (maps to `az login --tenant ...`)."""
    if mode == "interactive":
        if not tenant_id:
            raise ValueError("interactive mode requires --tenant-id or AZURE_TENANT_ID.")
        return InteractiveBrowserCredential(tenant_id=tenant_id)

    if mode == "devicecode":
        if not tenant_id:
            raise ValueError("devicecode mode requires --tenant-id or AZURE_TENANT_ID.")
        return DeviceCodeCredential(tenant_id=tenant_id)

    if mode == "azurecli":
        # Uses current az login context (tenant/sub selection follows CLI defaults)
        return AzureCliCredential()

    if mode == "managedidentity":
        # System-assigned MI: no client_id; User-assigned MI: provide client_id
        return ManagedIdentityCredential(client_id=mi_client_id) if mi_client_id else ManagedIdentityCredential()

    if mode == "serviceprincipal":
        if not (tenant_id and client_id and client_secret):
            raise ValueError("serviceprincipal mode requires --tenant-id, --client-id, and --client-secret.")
        return ClientSecretCredential(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)

    raise ValueError(f"Unsupported auth mode: {mode}")


def get_arm_token(credential) -> str:
    """
    Acquire an ARM audience token (equivalent to `az account get-access-token --resource https://management.azure.com`).
    If a valid token is cached (e.g., after prefetch), this is instant; otherwise it triggers acquisition.
    """
    token = credential.get_token(ARM_SCOPE)
    return token.token


def bind_subscription_client(credential, subscription_id: str) -> ResourceManagementClient:
    """Create a client scoped to the subscription (equivalent to `az account set --subscription ...`)."""
    return ResourceManagementClient(credential=credential, subscription_id=subscription_id)


def parse_args():
    parser = argparse.ArgumentParser(description="Azure SDK equivalents of az login/scope/get-access-token/account set")
    parser.add_argument("--mode", choices=list(AUTH_MODES), default=os.getenv("AZURE_AUTH_MODE", "interactive"),
                        help="Auth mode to use.")
    parser.add_argument("--tenant-id", default=os.getenv("AZURE_TENANT_ID"),
                        help="Tenant ID (required for interactive/devicecode/serviceprincipal).")
    parser.add_argument("--subscription-id", default=os.getenv("AZURE_SUBSCRIPTION_ID"),
                        help="Subscription ID to bind SDK clients.")
    parser.add_argument("--client-id", default=os.getenv("AZURE_CLIENT_ID"),
                        help="App (client) ID (service principal or user-assigned MI).")
    parser.add_argument("--client-secret", default=os.getenv("AZURE_CLIENT_SECRET"),
                        help="Client secret (serviceprincipal mode).")
    parser.add_argument("--mi-client-id", default=os.getenv("AZURE_MI_CLIENT_ID"),
                        help="User-assigned Managed Identity client ID (managedidentity mode).")

    # New flags for CLI parity / convenience
    parser.add_argument("--prefetch", action="store_true",
                        help="Prefetch the ARM token at startup (mimics `az login --scope ...`).")
    parser.add_argument("--print-token", action="store_true",
                        help="Print the current ARM access token (mimics `az account get-access-token ...`).")
    parser.add_argument("--output-bearer", action="store_true",
                        help="Print full 'Authorization: Bearer <token>' header line (for REST copy/paste).")
    parser.add_argument("--list-rgs", action="store_true",
                        help="List up to 10 resource groups to validate subscription context.")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.mode in {"interactive", "devicecode", "serviceprincipal"} and not args.tenant_id:
        print(f"[ERROR] --tenant-id (or AZURE_TENANT_ID) is required for mode '{args.mode}'.", file=sys.stderr)
        sys.exit(1)
    if not args.subscription_id:
        print("[ERROR] --subscription-id (or AZURE_SUBSCRIPTION_ID) is required.", file=sys.stderr)
        sys.exit(1)

    # 1) Build credential (equivalent to `az login --tenant ...`)
    credential = build_credential(
        mode=args.mode,
        tenant_id=args.tenant_id,
        client_id=args.client_id,
        client_secret=args.client_secret,
        mi_client_id=args.mi_client_id
    )
    print(f"[INFO] Auth mode: {args.mode}")

    # 2) Optional: prefetch ARM token (equivalent to `az login --scope ...`)
    if args.prefetch:
        prefetch_token = get_arm_token(credential)
        print(f"[INFO] Prefetched ARM token (aud=https://management.azure.com): {prefetch_token[:32]}... (truncated)")

    # 3) On-demand: get the token (equivalent to `az account get-access-token --resource https://management.azure.com`)
    if args.print_token or args.output_bearer:
        token = get_arm_token(credential)
        if args.output_bearer:
            print(f"Authorization: Bearer {token}")
        else:
            print(token)

    # 4) Bind client to subscription (equivalent to `az account set --subscription ...`)
    rm_client = bind_subscription_client(credential, args.subscription_id)
    print(f"[INFO] Bound ResourceManagementClient to subscription: {args.subscription_id}")

    # Optional proof: list RGs
    if args.list_rgs:
        print("[INFO] Listing up to 10 resource groups in this subscription:")
        try:
            for i, rg in enumerate(rm_client.resource_groups.list()):
                print(f"  - {rg.name}")
                if i >= 9:
                    break
        except Exception as e:
            print(f"[WARN] Could not list resource groups: {e}", file=sys.stderr)

    print("[DONE] Login/Scope/Get-Access-Token/Subscription binding completed.")


if __name__ == "__main__":
    main()

