
using System;
using System.CommandLine;                 // dotnet add package System.CommandLine
using System.CommandLine.Invocation;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Azure.ResourceManager;               // dotnet add package Azure.ResourceManager
using Azure.ResourceManager.Resources;     // dotnet add package Azure.ResourceManager.Resources

/*
  Enhanced Azure login (C#) with configurable resource audience and optional certificate-based auth.

  Modes: interactive, devicecode, managedidentity, serviceprincipal
  Outputs: token, "Authorization: Bearer <token>"
  ARM-only: bind to subscription and list RGs (if resource == https://management.azure.com/.default)

  Usage examples (see section below for full CLI):
    dotnet run -- --mode serviceprincipal --tenant-id <TENANT> --client-id <APP_ID> --client-secret <SECRET> \
      --subscription-id <SUB_ID> --resource https://graph.microsoft.com/.default --output-bearer

    dotnet run -- --mode serviceprincipal --tenant-id <TENANT> --client-id <APP_ID> --cert-path /path/to/cert.pfx \
      --cert-password <optional> --subscription-id <SUB_ID> --resource https://management.azure.com/.default --list-rgs
*/

class Program
{
    static readonly string DefaultScope = "https://management.azure.com/.default";

    static async Task<int> Main(string[] args)
    {
        var modeOption            = new Option<string>("--mode", () => "interactive", "Auth mode: interactive|devicecode|managedidentity|serviceprincipal");
        var tenantIdOption        = new Option<string>("--tenant-id", description: "Tenant ID (required for interactive/devicecode/serviceprincipal)");
        var subscriptionIdOption  = new Option<string>("--subscription-id", description: "Subscription ID (ARM operations)");
        var clientIdOption        = new Option<string>("--client-id", description: "App (client) ID");
        var clientSecretOption    = new Option<string>("--client-secret", description: "Client secret (serviceprincipal)");
        var miClientIdOption      = new Option<string>("--mi-client-id", description: "User-assigned Managed Identity client ID (managedidentity)");
        var certPathOption        = new Option<string>("--cert-path", description: "Path to certificate file for certificate auth (serviceprincipal)");
        var certPasswordOption    = new Option<string>("--cert-password", () => "", "Optional certificate password (serviceprincipal)");
        var resourceOption        = new Option<string>("--resource", () => DefaultScope, "Resource scope (audience), e.g., https://graph.microsoft.com/.default");
        var prefetchOption        = new Option<bool>("--prefetch", () => false, "Prefetch token at startup");
        var printTokenOption      = new Option<bool>("--print-token", () => false, "Print raw access token");
        var outputBearerOption    = new Option<bool>("--output-bearer", () => false, "Print 'Authorization: Bearer <token>'");
        var listRgsOption         = new Option<bool>("--list-rgs", () => false, "List up to 10 resource groups (ARM scope only)");

        var root = new RootCommand("Azure SDK equivalents with configurable resource audience (C#)");
        root.AddOption(modeOption);
        root.AddOption(tenantIdOption);
        root.AddOption(subscriptionIdOption);
        root.AddOption(clientIdOption);
        root.AddOption(clientSecretOption);
        root.AddOption(miClientIdOption);
        root.AddOption(certPathOption);
        root.AddOption(certPasswordOption);
        root.AddOption(resourceOption);
        root.AddOption(prefetchOption);
        root.AddOption(printTokenOption);
        root.AddOption(outputBearerOption);
        root.AddOption(listRgsOption);

        root.SetHandler(async (mode, tenantId, subscriptionId, clientId, clientSecret, miClientId, certPath, certPassword, resource, prefetch, printTok, outputBearer, listRgs) =>
        {
            try
            {
                if ((mode == "interactive" || mode == "devicecode" || mode == "serviceprincipal") &&
                    string.IsNullOrWhiteSpace(tenantId))
                {
                    Console.Error.WriteLine($"[ERROR] --tenant-id is required for mode '{mode}'.");
                    Environment.Exit(1);
                }

                // subscription-id required only for ARM client binding or --list-rgs
                if ((IsArmScope(resource) || listRgs) && string.IsNullOrWhiteSpace(subscriptionId))
                {
                    Console.Error.WriteLine("[ERROR] --subscription-id is required for ARM operations.");
                    Environment.Exit(1);
                }

                var credential = BuildCredential(
                    mode: mode,
                    tenantId: tenantId,
                    clientId: clientId,
                    clientSecret: clientSecret,
                    miClientId: miClientId,
                    certPath: certPath,
                    certPassword: certPassword);

                Console.WriteLine($"[INFO] Auth mode: {mode}");
                Console.WriteLine($"[INFO] Resource scope: {resource}");

                if (prefetch)
                {
                    var preToken = await GetTokenForResourceAsync(credential, resource);
                    Console.WriteLine($"[INFO] Prefetched token for {resource}: {Truncate(preToken, 32)}... (truncated)");
                }

                string token = null;
                if (printTok || outputBearer)
                {
                    token = await GetTokenForResourceAsync(credential, resource);
                    if (outputBearer)
                        Console.WriteLine($"Authorization: Bearer {token}");
                    else
                        Console.WriteLine(token);
                }

                // ARM-only client binding & RG listing
                if (IsArmScope(resource))
                {
                    var armClient = new ArmClient(credential, subscriptionId);
                    Console.WriteLine($"[INFO] Bound ArmClient to subscription: {subscriptionId}");

                    if (listRgs)
                    {
                        Console.WriteLine("[INFO] Listing up to 10 resource groups in this subscription:");
                        try
                        {
                            int count = 0;
                            var sub = armClient.GetSubscriptionResource(SubscriptionResource.CreateResourceIdentifier(subscriptionId));
                            await foreach (var rg in sub.GetResourceGroups().GetAllAsync())
                            {
                                Console.WriteLine($" - {rg.Data.Name}");
                                count++;
                                if (count >= 10) break;
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.Error.WriteLine($"[WARN] Could not list resource groups: {ex.Message}");
                        }
                    }
                }
                else if (listRgs)
                {
                    Console.Error.WriteLine("[WARN] --list-rgs is ignored because the selected resource scope is not ARM.");
                }

                Console.WriteLine("[DONE] Token acquisition and (optional) ARM operations completed.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ERROR] {ex.GetType().Name}: {ex.Message}");
                Environment.Exit(1);
            }

        }, modeOption, tenantIdOption, subscriptionIdOption, clientIdOption, clientSecretOption,
           miClientIdOption, certPathOption, certPasswordOption, resourceOption, prefetchOption,
           printTokenOption, outputBearerOption, listRgsOption);

        return await root.InvokeAsync(args);
    }

    static bool IsArmScope(string scope) =>
        scope?.Trim().Equals("https://management.azure.com/.default", StringComparison.OrdinalIgnoreCase) ?? false;

    static string Truncate(string s, int n) =>
        string.IsNullOrEmpty(s) ? s : (s.Length <= n ? s : s.Substring(0, n));

    static async Task<string> GetTokenForResourceAsync(TokenCredential cred, string resourceScope)
    {
        var tok = await cred.GetTokenAsync(new TokenRequestContext(new[] { resourceScope }), default);
        return tok.Token;
    }

    static TokenCredential BuildCredential(
        string mode,
        string tenantId,
        string clientId,
        string clientSecret,
        string miClientId,
        string certPath,
        string certPassword)
    {
        switch (mode)
        {
            case "interactive":
                return new InteractiveBrowserCredential(new InteractiveBrowserCredentialOptions { TenantId = tenantId });

            case "devicecode":
                return new DeviceCodeCredential(new DeviceCodeCredentialOptions
                {
                    TenantId = tenantId,
                    DeviceCodeCallback = code =>
                    {
                        Console.WriteLine(code.Message);
                        return Task.CompletedTask;
                    }
                });

            case "managedidentity":
                return string.IsNullOrWhiteSpace(miClientId)
                    ? new ManagedIdentityCredential()
                    : new ManagedIdentityCredential(miClientId);

            case "serviceprincipal":
                if (!string.IsNullOrWhiteSpace(certPath))
                {
                    // Certificate-based service principal
                    return new ClientCertificateCredential(tenantId, clientId, certPath, new ClientCertificateCredentialOptions
                    {
                        SendCertificateChain = true,
                        Password = string.IsNullOrWhiteSpace(certPassword) ? null : certPassword
                    });
                }
                else
                {
                    // Client secret service principal
                    if (string.IsNullOrWhiteSpace(clientSecret))
                        throw new ArgumentException("serviceprincipal mode requires --client-secret or --cert-path");
                    return new ClientSecretCredential(tenantId, clientId, clientSecret);
                }

            default:
                throw new ArgumentException($"Unsupported auth mode: {mode}");
        }
    }
}
