using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

#pragma warning disable IDE0079
#pragma warning disable CA1416

namespace FortiCertSync;

internal sealed class FortiClient
{
    private readonly HttpClient _http;
    private readonly string _baseUrl;

    private FortiClient(HttpClient h, string baseUrl)
    { _http = h; _baseUrl = baseUrl; }

    // ---- URL helper (adds vdom only if provided) ----
    private string Url(string path, string? query = null, string? vdom = null)
    {
        var hasQ = !string.IsNullOrEmpty(query);
        var sb = new StringBuilder(_baseUrl.Length + path.Length + 32);
        sb.Append(_baseUrl).Append(path);
        if (hasQ) sb.Append('?').Append(query);
        if (!string.IsNullOrWhiteSpace(vdom))
            sb.Append(hasQ ? '&' : '?').Append("vdom=").Append(Uri.EscapeDataString(vdom));
        return sb.ToString();
    }

    public static async Task<FortiClient> CreateAsync(Ini.Section forti, string iniPath)
    {
        var baseUrl = forti.Get("baseUrl")?.TrimEnd('/') ?? throw new Exception("fortigate.baseUrl required");
        var tokenRaw = forti.Get("apiKey") ?? throw new Exception("fortigate.apiKey required");

        var token = tokenRaw.StartsWith("enc:", StringComparison.OrdinalIgnoreCase)
            ? Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(tokenRaw[4..]), null, DataProtectionScope.CurrentUser))
            : tokenRaw;

        var h = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        h.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var ping = await h.GetAsync($"{baseUrl}/api/v2/monitor/system/status");
        if (!ping.IsSuccessStatusCode) throw new Exception($"FortiGate auth failed: {(int)ping.StatusCode}");

        if (!tokenRaw.StartsWith("enc:", StringComparison.OrdinalIgnoreCase))
        {
            var enc = "enc:" + Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(token), null, DataProtectionScope.CurrentUser));
            Ini.UpdateKeyInPlace(iniPath, "fortigate", "apiKey", enc);
            Logger.Info("API key encrypted in INI (DPAPI CurrentUser).");
        }

        return new FortiClient(h, baseUrl);
    }

    internal record FortiCert(string Name, string Subject, DateTime ValidToUtc);

    public async Task<List<FortiCert>> ListLocalCertsAsync(string? vdom)
    {
        var json = await _http.GetStringAsync(Url("/api/v2/cmdb/vpn.certificate/local", null, vdom));
        using var doc = JsonDocument.Parse(json);

        var list = new List<FortiCert>();
        if (!doc.RootElement.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array)
            return list;

        foreach (var el in results.EnumerateArray())
        {
            var name = el.TryGetProperty("name", out var n) ? n.GetString() : null;
            if (string.IsNullOrWhiteSpace(name)) continue;

            var cert = await GetLocalCertMetaAsync(name!, vdom); // <- sequential detail fetch
            if (cert != null) list.Add(cert);
        }
        return list;
    }

    private async Task<FortiCert?> GetLocalCertMetaAsync(string name, string? vdom)
    {
        try
        {
            var url = Url($"/api/v2/cmdb/vpn.certificate/local/{Uri.EscapeDataString(name)}", null, vdom);
            var resp = await _http.GetAsync(url);
            if (!resp.IsSuccessStatusCode)
            {
                Logger.Warn($"Get cert meta skipped for '{name}': {(int)resp.StatusCode} {resp.ReasonPhrase}");
                return null;
            }

            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            if (!doc.RootElement.TryGetProperty("results", out var results))
            {
                Logger.Warn($"Get cert meta skipped for '{name}': missing 'results'");
                return null;
            }

            var obj = results.ValueKind switch
            {
                JsonValueKind.Object => results,
                JsonValueKind.Array when results.GetArrayLength() > 0 => results[0],
                _ => default
            };
            if (obj.ValueKind == JsonValueKind.Undefined)
            {
                Logger.Warn($"Get cert meta skipped for '{name}': unexpected 'results' shape");
                return null;
            }

            if (!obj.TryGetProperty("certificate", out var certProp) || certProp.ValueKind != JsonValueKind.String)
            {
                Logger.Warn($"Get cert meta skipped for '{name}': 'certificate' field missing");
                return null;
            }

            var pem = certProp.GetString();
            const string begin = "-----BEGIN CERTIFICATE-----";
            const string end = "-----END CERTIFICATE-----";
            var i = pem!.IndexOf(begin, StringComparison.Ordinal);
            var j = pem.IndexOf(end, StringComparison.Ordinal);
            if (i < 0 || j < 0 || j <= i)
            {
                if (!name.StartsWith("Fortinet_", StringComparison.OrdinalIgnoreCase))
                    Logger.Warn($"Get cert meta skipped for '{name}': invalid PEM");
                return null;
            }

            var b64 = pem[(i + begin.Length)..j].Replace("\r", "").Replace("\n", "").Trim();
            using var x509 = new System.Security.Cryptography.X509Certificates.X509Certificate2(Convert.FromBase64String(b64));
            var cn = x509.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.DnsName, false);
            if (string.IsNullOrWhiteSpace(cn))
                cn = x509.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false);

            var validToUtc = x509.NotAfter.ToUniversalTime();
            return new FortiCert(name, cn ?? x509.Subject, validToUtc);
        }
        catch (Exception ex)
        {
            Logger.Warn($"Get cert meta skipped for '{name}': {ex.Message}");
            return null;
        }
    }

    public async Task ImportPkcs12Async(string? vdom, string mkey, string pfxPass, byte[] pfxBytes, bool replace)
    {
        if (replace)
        {
            // PUT: update existing cert "slot" (FortiOS: /api/v2/cmdb/certificate/local/<name>)
            var url = Url($"/api/v2/cmdb/certificate/local/{Uri.EscapeDataString(mkey)}", null, vdom);

            using var ms = new MemoryStream();
            using (var jw = new Utf8JsonWriter(ms))
            {
                jw.WriteStartObject();
                jw.WriteString("type", "pkcs12");
                jw.WriteString("password", pfxPass);
                // Forti expects the PKCS#12 content base64-encoded in the body.
                // Field name varies in docs; "file_content" is accepted across recent trains.
                jw.WriteString("file_content", Convert.ToBase64String(pfxBytes));
                jw.WriteEndObject();
            }
            using var content = new ByteArrayContent(ms.ToArray());
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            var resp = await _http.PutAsync(url, content);
            if (!resp.IsSuccessStatusCode)
                throw new Exception($"Update cert '{mkey}' failed: {(int)resp.StatusCode} {await resp.Content.ReadAsStringAsync()}");
        }
        else
        {
            // POST: import new cert (monitor endpoint)
            var q = $"scope=global&type=pkcs12&replace=0&mkey={Uri.EscapeDataString(mkey)}&password={Uri.EscapeDataString(pfxPass)}";
            var url = Url("/api/v2/monitor/vpn-certificate/local/import", q, vdom);

            using var form = new MultipartFormDataContent { { new ByteArrayContent(pfxBytes), "file", $"{mkey}.pfx" } };
            var resp = await _http.PostAsync(url, form);
            if (!resp.IsSuccessStatusCode)
                throw new Exception($"Import cert '{mkey}' failed: {(int)resp.StatusCode} {await resp.Content.ReadAsStringAsync()}");
        }
    }

}
