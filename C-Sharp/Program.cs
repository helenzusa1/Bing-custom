using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Identity;
using DotNetEnv;

class Program
{
    // ===== Constants =====
    private const string ArmScope = "https://management.azure.com/.default";
    private const string ArmBase  = "https://management.azure.com";
    private static readonly int[] RetryableStatuses = { 429, 500, 502, 503, 504 };

    private static readonly HashSet<string> AllowedBoosts = new(StringComparer.OrdinalIgnoreCase)
    { "Default", "Elevated", "Demoted" };

    // ✅ NEW: Global JSON options — omit nulls so "boostLevel": null is never sent
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };


    // add near the other helpers in Program.cs
    static List<T>? LoadJsonArray<T>(string? path, string label)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        try
        {
            var json = File.ReadAllText(path, Encoding.UTF8);
            var data = JsonSerializer.Deserialize<List<T>>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            if (data is null)
                throw new InvalidOperationException($"{label} JSON must be an array.");
            return data;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to load {label} from '{path}': {ex.Message}", ex);
        }
    }

    // ===== Config model =====
    record AppConfig(
        string? TENANT_ID,
        string? SUBSCRIPTION_ID,
        string? CLIENT_ID,
        string? CLIENT_SECRET,
        string? MI_CLIENT_ID,
        string? RESOURCE_GROUP,
        string? ACCOUNT_NAME,
        string? CONFIG_NAME,
        string? ALLOWED_DOMAINS_FILE,
        string? BLOCKED_DOMAINS_FILE,
        string? ACCOUNT_API_VERSION,
        string? CONFIG_API_VERSION,
        string? AUTH_MODE
    );

    // ===== Domain entry models =====
    class DomainEntry
    {
        [JsonPropertyName("domain")] public string? Domain { get; set; }
        [JsonPropertyName("includeSubPages")] public bool? IncludeSubPages { get; set; }
        [JsonPropertyName("boostLevel")] public string? BoostLevel { get; set; }
    }

    static async Task Main(string[] args)
    {
        // 1) Load .env then environment
        TryLoadDotEnv();
        var cfg = LoadConfig();


        // --- NEW: accept command-line override for --mode ---
        // Supports:   dotnet run .\Bing-custom.csproj -- --mode azurecli
        //           or dotnet run .\Bing-custom.csproj -- --mode=azurecli
        string? cliMode = null;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--mode" && i + 1 < args.Length)
            {
                cliMode = args[i + 1];
                i++; // skip the value
            }
            else if (args[i].StartsWith("--mode=", StringComparison.OrdinalIgnoreCase))
            {
                cliMode = args[i].Substring("--mode=".Length);
            }
        }

        // Default mode is serviceprincipal if unset
        
        var mode = cliMode 
                ?? cfg.AUTH_MODE 
                ?? "serviceprincipal";

        // Basic required settings
        Require(cfg.SUBSCRIPTION_ID, "SUBSCRIPTION_ID");
        Require(cfg.RESOURCE_GROUP,  "RESOURCE_GROUP");
        Require(cfg.ACCOUNT_NAME,    "ACCOUNT_NAME");

        // Mode-specific requirements
        if ((mode.Equals("serviceprincipal", StringComparison.OrdinalIgnoreCase) ||
             mode.Equals("interactive", StringComparison.OrdinalIgnoreCase)) &&
            string.IsNullOrWhiteSpace(cfg.TENANT_ID))
        {
            Fail($"TENANT_ID is required for mode '{mode}'.");
        }

        // 2) Build credential & get ARM token
        Console.WriteLine($"[INFO] Auth mode: {mode}");
        var cred  = BuildCredential(mode, cfg);
        var token = await GetArmTokenAsync(cred);
        Console.WriteLine($"[INFO] Acquired ARM token: {token[..Math.Min(token.Length, 32)]}... (truncated)");

        // 3) Optional preflight checks (provider + RG)
        await EnsureProviderRegisteredAsync(token, cfg.SUBSCRIPTION_ID!);
        await EnsureResourceGroupExistsAsync(token, cfg.SUBSCRIPTION_ID!, cfg.RESOURCE_GROUP!);

        // Arm API versions (from env, with defaults)
        var accountApiVersion = string.IsNullOrWhiteSpace(cfg.ACCOUNT_API_VERSION) ? "2020-06-10" : cfg.ACCOUNT_API_VERSION!;
        var configApiVersion  = string.IsNullOrWhiteSpace(cfg.CONFIG_API_VERSION)  ? "2025-05-01-preview" : cfg.CONFIG_API_VERSION!;

        // 4) Account: GET -> skip or PUT (create)
        Console.WriteLine("[STEP] Checking if Bing account exists ...");
        bool accountExists = await AccountExistsAsync(token, cfg.SUBSCRIPTION_ID!, cfg.RESOURCE_GROUP!, cfg.ACCOUNT_NAME!, accountApiVersion);
        if (accountExists)
        {
            Console.WriteLine($"[INFO] Bing account '{cfg.ACCOUNT_NAME}' already exists — skipping account creation.");
        }
        else
        {
            Console.WriteLine($"[INFO] Creating Bing account '{cfg.ACCOUNT_NAME}' ...");
            var acct = await CreateOrUpdateBingAccountAsync(token, cfg.SUBSCRIPTION_ID!, cfg.RESOURCE_GROUP!, cfg.ACCOUNT_NAME!, accountApiVersion);
            DumpJson(acct, "[INFO] Account PUT returned no body.");
        }

        // 5) Config: load lists; if provided, GET existence -> PUT (create/update)
        var allowed = LoadJsonArray<DomainEntry>(cfg.ALLOWED_DOMAINS_FILE, "allowed domains");
        var blocked = LoadJsonArray<DomainEntry>(cfg.BLOCKED_DOMAINS_FILE, "blocked domains");

        if ((allowed is null || allowed.Count == 0) && (blocked is null || blocked.Count == 0))
        {
            Console.WriteLine("\n[STEP] No allowed/blocked JSON provided — skipping configuration update.");
            return;
        }

        // Validation
        ValidateDomains(allowed, "allowedDomains");
        ValidateDomains(blocked, "blockedDomains");

        var configName = string.IsNullOrWhiteSpace(cfg.CONFIG_NAME) ? $"{cfg.ACCOUNT_NAME}-config" : cfg.CONFIG_NAME!;
        Console.WriteLine("\n[STEP] Checking if configuration exists ...");
        bool cfgExists = await ConfigExistsAsync(token, cfg.SUBSCRIPTION_ID!, cfg.RESOURCE_GROUP!, cfg.ACCOUNT_NAME!, configName, configApiVersion);
        Console.WriteLine(cfgExists
            ? $"[INFO] Config '{configName}' exists — updating with provided lists."
            : $"[INFO] Config '{configName}' not found — creating it.");

        var cfgResp = await SetCustomSearchConfigurationAsync(
            token,
            cfg.SUBSCRIPTION_ID!,
            cfg.RESOURCE_GROUP!,
            cfg.ACCOUNT_NAME!,
            configName,
            allowed,
            blocked,
            configApiVersion);

        DumpJson(cfgResp, "[INFO] Config PUT returned no body.");

        Console.WriteLine("\n[DONE] Bing account + configuration flow completed successfully.");
    }

    // -------------------- Helpers --------------------
    static void TryLoadDotEnv()
    {
        try { Env.Load(); } catch { /* ignore if .env missing */ }
    }

    static AppConfig LoadConfig()
    {
        // Read from environment
        return new AppConfig(
            Environment.GetEnvironmentVariable("TENANT_ID"),
            Environment.GetEnvironmentVariable("SUBSCRIPTION_ID"),
            Environment.GetEnvironmentVariable("CLIENT_ID"),
            Environment.GetEnvironmentVariable("CLIENT_SECRET"),
            Environment.GetEnvironmentVariable("MI_CLIENT_ID"),
            Environment.GetEnvironmentVariable("RESOURCE_GROUP"),
            Environment.GetEnvironmentVariable("ACCOUNT_NAME"),
            Environment.GetEnvironmentVariable("CONFIG_NAME"),
            Environment.GetEnvironmentVariable("ALLOWED_DOMAINS_FILE"),
            Environment.GetEnvironmentVariable("BLOCKED_DOMAINS_FILE"),
            Environment.GetEnvironmentVariable("ACCOUNT_API_VERSION"),
            Environment.GetEnvironmentVariable("CONFIG_API_VERSION"),
            Environment.GetEnvironmentVariable("AUTH_MODE")
        );
    }

    static void Require(string? value, string key)
    {
        if (string.IsNullOrWhiteSpace(value))
            Fail($"Missing required setting '{key}' (set in .env or environment).");
    }

    static void Fail(string message)
    {
        Console.Error.WriteLine($"[ERROR] {message}");
        Environment.Exit(1);
    }

    static TokenCredential BuildCredential(string mode, AppConfig cfg)
    {
        return mode.ToLowerInvariant() switch
        {
            "interactive"     => new InteractiveBrowserCredential(
                                    new InteractiveBrowserCredentialOptions{TenantId = cfg.TENANT_ID}
                                ),
            "azurecli"        => new AzureCliCredential(),
            "managedidentity" => string.IsNullOrWhiteSpace(cfg.MI_CLIENT_ID)
                                    ? new ManagedIdentityCredential()
                                    : new ManagedIdentityCredential(cfg.MI_CLIENT_ID),
            "serviceprincipal" => new ClientSecretCredential(cfg.TENANT_ID, cfg.CLIENT_ID, cfg.CLIENT_SECRET),
            _ => throw new ArgumentException($"Unsupported auth mode: {mode}")
        };
    }

    static async Task<string> GetArmTokenAsync(TokenCredential cred)
    {
        var ctx = new TokenRequestContext(new[] { ArmScope });
        var token = await cred.GetTokenAsync(ctx, CancellationToken.None);
        return token.Token;
    }

    static async Task EnsureProviderRegisteredAsync(string token, string subscriptionId)
    {
        var url = $"{ArmBase}/subscriptions/{subscriptionId}/providers/Microsoft.Bing?api-version=2021-04-01";
        var r = await HttpGetAsync(url, token, throwOnError: false);
        if (r.StatusCode != HttpStatusCode.OK)
            Fail($"Provider check failed: {(int)r.StatusCode}: {await r.Content.ReadAsStringAsync()}");

        var doc = JsonDoc(await r.Content.ReadAsStringAsync());
        var state = doc.RootElement.GetPropertyOrDefault("registrationState");
        if (!string.Equals(state, "Registered", StringComparison.OrdinalIgnoreCase))
            Fail($"Provider 'Microsoft.Bing' not registered (state={state}). " +
                 $"Run: az provider register --namespace Microsoft.Bing --subscription {subscriptionId}");
    }

    static async Task EnsureResourceGroupExistsAsync(string token, string subscriptionId, string resourceGroup)
    {
        var url = $"{ArmBase}/subscriptions/{subscriptionId}/resourcegroups/{resourceGroup}?api-version=2021-04-01";
        var r = await HttpGetAsync(url, token, throwOnError: false);
        if (r.StatusCode == HttpStatusCode.NotFound)
            Fail($"Resource group '{resourceGroup}' not found in subscription '{subscriptionId}'.");
        if ((int)r.StatusCode >= 400)
            Fail($"RG check failed: {(int)r.StatusCode}: {await r.Content.ReadAsStringAsync()}");
    }

    static async Task<bool> AccountExistsAsync(string token, string sub, string rg, string account, string apiVersion)
    {
        var url = $"{ArmBase}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Bing/accounts/{account}?api-version={apiVersion}";
        var r = await HttpGetAsync(url, token, throwOnError: false);
        return r.StatusCode == HttpStatusCode.OK;
    }

    static async Task<JsonDocument?> CreateOrUpdateBingAccountAsync(string token, string sub, string rg, string account, string apiVersion)
    {
        var url = $"{ArmBase}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Bing/accounts/{account}?api-version={apiVersion}";
        var payload = new
        {
            type = "Microsoft.Bing/accounts",
            location = "global",
            sku = new { name = "G2" },
            kind = "Bing.GroundingCustomSearch",
            tags = new { name = account }
        };
        var resp = await PutWithRetryAsync(url, token, payload);
        return await ReadJsonOrNull(resp);
    }

    static async Task<bool> ConfigExistsAsync(string token, string sub, string rg, string account, string config, string apiVersion)
    {
        var url = $"{ArmBase}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Bing/accounts/{account}/customSearchConfigurations/{config}?api-version={apiVersion}";
        var r = await HttpGetAsync(url, token, throwOnError: false);
        return r.StatusCode == HttpStatusCode.OK;
    }

    static async Task<JsonDocument?> SetCustomSearchConfigurationAsync(
        string token,
        string sub,
        string rg,
        string account,
        string config,
        List<DomainEntry>? allowed,
        List<DomainEntry>? blocked,
        string apiVersion)
    {
        // Build payload
        var props = new Dictionary<string, object>();
        if (blocked is not null) props["blockedDomains"] = blocked;
        if (allowed is not null) props["allowedDomains"] = allowed;
        if (props.Count == 0) return null; // nothing to update

        var payload = new Dictionary<string, object> { ["properties"] = props };

        var url = $"{ArmBase}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Bing/accounts/{account}/customSearchConfigurations/{config}?api-version={apiVersion}";
        var resp = await PutWithRetryAsync(url, token, payload);
        return await ReadJsonOrNull(resp);
    }

    static void ValidateDomains(List<DomainEntry>? domains, string label)
    {
        if (domains is null || domains.Count == 0) return;
        foreach (var d in domains)
        {
            if (string.IsNullOrWhiteSpace(d.Domain))
                Fail($"{label}: each entry requires a non-empty 'domain' string.");
            if (d.IncludeSubPages is null)
                Fail($"{label}: domain '{d.Domain}' must set 'includeSubPages': true|false.");
            if (!string.IsNullOrWhiteSpace(d.BoostLevel))
            {
                if (!AllowedBoosts.Contains(d.BoostLevel!))
                    Fail($"{label}: domain '{d.Domain}' has invalid boostLevel '{d.BoostLevel}'. Allowed: Default|Elevated|Demoted.");
                if (d.IncludeSubPages == false)
                    Fail($"{label}: domain '{d.Domain}' sets boostLevel but includeSubPages=false. BoostLevel requires includeSubPages=true.");
            }
        }
    }

    // ===== HTTP utilities =====
    static async Task<HttpResponseMessage> HttpGetAsync(string url, string token, bool throwOnError = true)
    {
        using var client = new HttpClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        var resp = await client.GetAsync(url);
        if (throwOnError && (int)resp.StatusCode >= 400)
            throw new HttpRequestException($"GET {url} failed: {(int)resp.StatusCode}: {await resp.Content.ReadAsStringAsync()}");
        return resp;
    }

    static async Task<HttpResponseMessage> PutWithRetryAsync(string url, string token, object payload, int maxRetries = 6, double baseDelaySec = 1.0)
    {
        using var client = new HttpClient();
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        // ✅ UPDATED: serialize with JsonOptions so nulls (e.g., boostLevel=null) are omitted
        var body = JsonSerializer.Serialize(payload, JsonOptions);
        var content = new StringContent(body, Encoding.UTF8, "application/json");

        int attempt = 0;
        while (true)
        {
            var resp = await client.PutAsync(url, content);
            if ((int)resp.StatusCode < 400) return resp;

            if (RetryableStatuses.Contains((int)resp.StatusCode) && attempt < maxRetries)
            {
                attempt++;
                double delay = baseDelaySec * Math.Pow(2, attempt - 1);
                if (resp.Headers.TryGetValues("Retry-After", out var vals))
                {
                    if (double.TryParse(vals.FirstOrDefault(), out var ra)) delay = Math.Max(delay, ra);
                }
                await Task.Delay(TimeSpan.FromSeconds(delay));
                continue;
            }

            var text = await resp.Content.ReadAsStringAsync();
            throw new HttpRequestException($"PUT {url} failed with {(int)resp.StatusCode}: {text}");
        }
    }

    static async Task<JsonDocument?> ReadJsonOrNull(HttpResponseMessage resp)
    {
        var s = await resp.Content.ReadAsStringAsync();
        if (string.IsNullOrWhiteSpace(s)) return null;
        return JsonDocument.Parse(s);
    }

    static JsonDocument JsonDoc(string s) => JsonDocument.Parse(s);

    static void DumpJson(JsonDocument? doc, string emptyMsg)
    {
        if (doc is null) { Console.WriteLine(emptyMsg); return; }
        var options = new JsonSerializerOptions { WriteIndented = true };
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });
        doc.RootElement.WriteTo(writer);
        writer.Flush();
        Console.WriteLine(Encoding.UTF8.GetString(stream.ToArray()));
    }
}

// ===== JsonElement helper =====
static class JsonExtensions
{
    public static string? GetPropertyOrDefault(this JsonElement el, string name)
    {
        if (el.TryGetProperty(name, out var v))
            return v.ValueKind switch
            {
                JsonValueKind.String => v.GetString(),
                JsonValueKind.Number => v.ToString(),
                JsonValueKind.True   => "true",
                JsonValueKind.False  => "false",
                _ => v.ToString()
            };
        return null;
    }

}

